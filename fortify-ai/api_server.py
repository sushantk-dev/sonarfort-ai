"""
FortifyAI — FastAPI Server
===========================
Exposes every execution combination of the FortifyAI pipeline as REST endpoints.
All /pipeline/* endpoints are fully async — they return a pipeline_id immediately
and execute the heavy work in a thread-pool executor so the event loop stays free.

Execution Modes:
  FULL PIPELINE  (async — returns pipeline_id immediately)
    POST /pipeline/live            — Full pipeline, live Fortify API
    POST /pipeline/offline         — Full pipeline, offline JSON report
    POST /pipeline/app-name        — Full pipeline, resolve app name → release
    POST /pipeline/app-id          — Full pipeline, resolve app_id → release
    POST /pipeline/dry-run         — Full pipeline, skips ADR/PR/writeback side-effects

  PIPELINE STATUS
    GET  /pipeline/status/{pipeline_id}               — overall pipeline status + all stage statuses
    GET  /pipeline/status/{pipeline_id}/{stage_name}  — status of a single stage
         stage_name: triage | version-resolver | context | api-diff |
                     ai-reasoning | adr-fix | build-validation | pr-agent | fortify-writeback
    POST /pipeline/cancel/{pipeline_id}   — cooperative cancellation at the next stage boundary
    POST /pipeline/resume/{pipeline_id}   — resume an interrupted/failed/cancelled run from its
                                             last checkpointed stage (full-pipeline runs only).
                                             Jobs merely interrupted by a pod restart usually
                                             resume on their own — see AUTO_RESUME_ENABLED below —
                                             but failed/cancelled jobs always need this call made
                                             manually.
    POST /pipeline/sweep                  — manually trigger the orphan-job sweep (also runs
                                             automatically in the background on every pod)

  AUTO-RESUME (env-configurable, on by default)
    Jobs left 'interrupted' by a previous pod's graceful SIGTERM shutdown
    (eviction, rolling deploy, scale-down — i.e. nothing actually went
    wrong with the run) are automatically resumed from their last
    checkpoint by a one-shot scan at every pod's startup, instead of
    waiting for a human to call POST /pipeline/resume/{pipeline_id}.
    Bounded by AUTO_RESUME_MAX_ATTEMPTS (default 3) per job. Disable with
    AUTO_RESUME_ENABLED=false.

    Deliberately does NOT cover 'failed' jobs (a raised exception, or the
    orphan sweep timing out a job whose pod died without a clean SIGTERM)
    or 'cancelled' jobs (a deliberate user action) — both always require
    a human to call POST /pipeline/resume/{pipeline_id} explicitly.

    Any per-request credentials captured for the resume (Fortify password,
    GitHub PAT, Sonar token) are stored symmetrically encrypted — see
    credential_vault.py — never in plaintext in the job store.

  INDIVIDUAL STAGES (can be called in isolation)
    POST /stages/triage            — Stage 1: filter/group raw vulnerabilities
    POST /stages/version-resolver  — Stage 2: resolve safe version candidates
    POST /stages/context           — Stage 3: locate dep in codebase
    POST /stages/api-diff          — Stage 4: run japicmp API diff
    POST /stages/ai-reasoning      — Stage 5: AI safety verdict
    POST /stages/adr-fix           — Stage 6:  invoke adr.py --commit --skip-build (commit only)
    POST /stages/build-validation  — Stage 6b: mvn clean install → push on success / rollback on failure
    POST /stages/ai-code-fix       — Stage 7: AI patch for broken call sites
    POST /stages/pr-agent          — Stage 8: create GitHub PR
    POST /stages/fortify-writeback — Stage 9: post outcome comment to SSC

  PARTIAL PIPELINES (stop at a given stage — async, returns pipeline_id)
    POST /pipeline/until/triage
    POST /pipeline/until/version-resolver
    POST /pipeline/until/context
    POST /pipeline/until/api-diff
    POST /pipeline/until/ai-reasoning
    POST /pipeline/until/adr-fix
    POST /pipeline/until/build-validation
    POST /pipeline/until/pr-agent

  UTILITY
    GET  /health                   — liveness probe
    GET  /api/config               — read current config (env vars; tokens masked)
    POST /api/config               — update process environment variables only
    GET  /config/validate          — validate current config (from environment)
    GET  /releases                 — list releases for an app name

Run:
    uvicorn api_server:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import asyncio
import os
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Callable, Dict, Literal, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# ── Internal imports ──────────────────────────────────────────────────────────
from config import FortifyAIConfig, load_config
from job_store import create_job_store, ALL_STAGE_NAMES
from maven_warmup import start_maven_warmup, log_warmup_status
from token_tracker import token_tracker
from runtime_config import apply_overrides, persist_overrides, is_persisted
from credential_vault import encrypt_resume_meta, decrypt_resume_meta
from state import AgentState, PipelineCancelledError

# Temporarily disabled: the background 'mvn dependency:go-offline' warm-up
# (maven_warmup.py) runs on its own thread with no synchronization against
# adr-fix's own 'mvn dependency:tree' or build-validation's 'mvn clean
# install' — it's fire-and-forget, and log_warmup_status() only reports
# whether it's still running rather than waiting for it. Two live mvn
# processes writing into the same .m2 repository at once can produce
# resolver-lock / *.lastUpdated "Access is denied" failures that look like
# a build deadlock. Flipping this back to True restores the warm-up once
# it's synchronized (a shared lock, or an actual join before adr-fix runs).
_MAVEN_WARMUP_ENABLED = False

# Pull any GCS-persisted runtime config overrides (Settings-page saves,
# refreshed Fortify tokens) into this pod's environment before anything
# else reads load_config().
apply_overrides(force=True)


# ── Pipeline job store ────────────────────────────────────────────────────────
# GCS-backed when GCS_BUCKET is set; falls back to in-process dict otherwise.
# Any uvicorn worker or GKE pod can look up any pipeline_id — eliminates the
# 404-on-poll race that occurs with multi-worker / multi-replica deployments.
_store = create_job_store()

# Shared executor — bounded thread pool for heavy pipeline work.
# Override MAX_PIPELINE_WORKERS env var to tune for your pod's CPU limit.
_MAX_WORKERS = int(os.environ.get("MAX_PIPELINE_WORKERS", 8))
_EXECUTOR = ThreadPoolExecutor(max_workers=_MAX_WORKERS, thread_name_prefix="pipeline-worker")

# ── Fault tolerance: active-pipeline registry ─────────────────────────────────
# Tracks pipeline_ids currently executing on THIS pod (not a global view —
# each pod only knows about its own in-flight work). Used by the shutdown
# handler below to mark jobs "interrupted" instead of leaving them stuck at
# "running" forever when the pod receives SIGTERM (k8s node drain, scale-down,
# rolling deploy, OOM-adjacent eviction, etc.).
_active_lock = Lock()
_ACTIVE_PIPELINES: Dict[str, float] = {}   # pipeline_id -> time.time() when it started


def _track_start(pipeline_id: str) -> None:
    with _active_lock:
        _ACTIVE_PIPELINES[pipeline_id] = time.time()


def _track_end(pipeline_id: str) -> None:
    with _active_lock:
        _ACTIVE_PIPELINES.pop(pipeline_id, None)


# Orphan-job sweep tuning — env-overridable.
_ORPHAN_SWEEP_INTERVAL_SECONDS = int(os.environ.get("ORPHAN_SWEEP_INTERVAL_SECONDS", 300))
_ORPHAN_SWEEP_TIMEOUT_SECONDS  = int(os.environ.get("ORPHAN_SWEEP_TIMEOUT_SECONDS", 1800))
_orphan_sweep_task: "asyncio.Task | None" = None

# Auto-resume tuning — env-overridable. When enabled, jobs left
# 'interrupted' by a previous pod's graceful-shutdown handler (SIGTERM —
# pod eviction, rolling deploy, scale-down) are resumed automatically from
# their last checkpoint at the next pod's startup, instead of sitting
# until a human notices and calls POST /pipeline/resume/{pipeline_id}.
# See `_try_auto_resume`, called from `startup_event`.
#
# Deliberately does NOT cover 'failed' jobs. A failure means a stage
# actually raised (bad/expired credentials, a deleted repo, a Fortify/
# GitHub API error, a bug) — that's a real problem that silently retrying
# won't fix and could make worse (e.g. hammering a rate-limited API, or
# opening duplicate side effects if the failure happened after a
# side-effecting stage but the checkpoint is stale). Failed jobs — whether
# from an exception or from the orphan sweep timing a stuck 'running' job
# out — always require a human to look and call
# POST /pipeline/resume/{pipeline_id} explicitly. Nor does it cover
# 'cancelled' — that was a deliberate user action.
_AUTO_RESUME_ENABLED = os.environ.get("AUTO_RESUME_ENABLED", "true").strip().lower() not in ("0", "false", "no")
_AUTO_RESUME_MAX_ATTEMPTS = int(os.environ.get("AUTO_RESUME_MAX_ATTEMPTS", 3))
_AUTO_RESUME_STATUSES = ("interrupted",)


def _run_orphan_sweep(timeout_seconds: float | None = None) -> list[str]:
    """
    Find jobs stuck at status='running' with no stage progress for longer
    than *timeout_seconds* (default ORPHAN_SWEEP_TIMEOUT_SECONDS) and flip
    them to 'failed'. This closes the "stuck forever" gap left when a pod
    dies (OOM kill, node eviction, hard crash) mid-job without ever reaching
    finish_job — no SIGTERM is delivered in that case, so the shutdown
    handler below never runs, and the job never becomes eligible for
    auto-resume (see AUTO_RESUME_STATUSES) — a human must call
    POST /pipeline/resume/{pipeline_id} for these.

    The checkpoint (if any) is preserved — finish_job only clears it on
    status='completed' — so a swept job still exposes a resumable
    checkpoint via that manual resume call.

    Returns the list of pipeline_ids that were swept.
    """
    timeout = timeout_seconds if timeout_seconds is not None else _ORPHAN_SWEEP_TIMEOUT_SECONDS
    swept: list[str] = []
    try:
        stale_jobs = _store.find_stale_running(timeout)
    except Exception as exc:
        print(f"[OrphanSweep] find_stale_running failed: {exc}")
        return swept
    for job in stale_jobs:
        pid = job.get("pipeline_id")
        if not pid:
            continue
        try:
            _store.finish_job(
                pid, "failed",
                error=(
                    f"No stage progress for over {int(timeout)}s — presumed "
                    "orphaned (pod crash, OOM kill, or node eviction). "
                    "Resume via POST /pipeline/resume/{pipeline_id} if a "
                    "checkpoint exists."
                ),
            )
            swept.append(pid)
            print(f"[OrphanSweep] Marked orphaned job as failed: {pid}")
        except Exception as exc:
            print(f"[OrphanSweep] Failed to finish_job for {pid}: {exc}")
    return swept


async def _orphan_sweep_loop() -> None:
    """Background task: periodically sweep orphaned 'running' jobs."""
    while True:
        try:
            await asyncio.sleep(_ORPHAN_SWEEP_INTERVAL_SECONDS)
            await asyncio.get_event_loop().run_in_executor(_EXECUTOR, _run_orphan_sweep)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            print(f"[OrphanSweep] loop iteration failed: {exc}")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_job(stages: list[str] | None = None) -> dict:
    """Create and persist a fresh job record via the shared store; return it."""
    return _store.new_job(stages)


def _update_stage(pipeline_id: str, stage: str, **kwargs) -> None:
    _store.update_stage(pipeline_id, stage, **kwargs)


def _finish_job(pipeline_id: str, status: str, result: dict | None = None,
                error: str | None = None, t0: float | None = None) -> None:
    # Attach LLM token consumption for this run to the persisted result so
    # GET /pipeline/status/{id} reports it after completion. end_run() also
    # unbinds the tracker from the worker thread.
    usage = token_tracker.end_run(pipeline_id)
    if isinstance(result, dict) and "token_usage" not in result:
        result["token_usage"] = usage
    _store.finish_job(pipeline_id, status, result=result, error=error, t0=t0)


class PipelineCancelled(Exception):
    """
    Raised internally when a job's cancel flag is observed between stages
    (see ``_check_cancelled``).

    Sibling exception: ``state.PipelineCancelledError`` — raised from inside
    agent code (agents.adr_fix, agents.ai_reasoning) when cancellation is
    observed *mid-stage* (mid-subprocess, mid per-group loop) rather than at
    a stage boundary. It lives in state.py instead of here so agent modules
    don't have to import api_server. Every ``except PipelineCancelled:``
    below also catches it — both mean the same thing: mark the job
    ``"cancelled"``.
    """


def _check_cancelled(pipeline_id: str | None) -> None:
    """
    Cooperative cancellation checkpoint. Called between pipeline stages (and
    inside long per-group loops) so a POST /pipeline/cancel/{id} actually
    stops the run from advancing to the next stage/side-effect, instead of
    just being ignored while the job runs to completion in the background.
    """
    if pipeline_id and _store.is_cancel_requested(pipeline_id):
        raise PipelineCancelled()


def _cancel_check_for(pipeline_id: str | None) -> "Callable[[], bool]":
    """
    Build a zero-arg cancel-check callback bound to *pipeline_id*, for
    passing into agents.adr_fix.run_adr_fix / agents.ai_reasoning.reason_all_groups
    so they can interrupt a long subprocess or per-group LLM loop instead of
    only being checked at the surrounding stage boundary. Always returns
    False when pipeline_id is None (e.g. ad-hoc/non-job invocations).
    """
    def _check() -> bool:
        return bool(pipeline_id and _store.is_cancel_requested(pipeline_id))
    return _check

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="FortifyAI API",
    description=(
        "REST API exposing every execution combination of the FortifyAI "
        "automated security dependency remediation pipeline."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:4200", "http://localhost:4201"],
    allow_origin_regex=r"http://localhost:\d+",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def _sync_runtime_config(request, call_next):
    """
    Keep this pod's environment in sync with the shared GCS runtime config
    (Settings-page saves and token refreshes made on ANY pod). Throttled
    internally to one GCS read per CONFIG_SYNC_SECONDS (default 15 s), so
    the per-request cost is a dict lookup.
    """
    apply_overrides()
    return await call_next(request)


# ═══════════════════════════════════════════════════════════════════════════════
# Request / Response models
# ═══════════════════════════════════════════════════════════════════════════════

class ConfigOverrides(BaseModel):
    """Optional per-request overrides for any FortifyAIConfig field."""
    fortify_base_url: Optional[str] = None
    fortify_api_token: Optional[str] = None
    fortify_username: Optional[str] = Field(
        default=None,
        description=(
            "Fortify OAuth username for this run only (overrides FORTIFY_USERNAME). "
            "The client is expected to send the fully-qualified value already "
            "prefixed with the 'equifax\\\\' domain, e.g. 'equifax\\\\jdoe'."
        ),
    )
    fortify_password: Optional[str] = Field(
        default=None,
        description="Fortify OAuth password for this run only (overrides FORTIFY_PASSWORD).",
    )
    github_token: Optional[str] = None
    github_repo: Optional[str] = None
    project_path: Optional[str] = None
    adr_path: Optional[str] = None
    japicmp_jar_path: Optional[str] = None
    gcp_project: Optional[str] = None
    gcp_location: Optional[str] = None
    max_retries: Optional[int] = Field(default=None, ge=1, le=10)
    max_upgrades: Optional[int] = Field(
        default=None,
        ge=0,
        description=(
            "Maximum number of dependencies to upgrade in this run. "
            "Deps are prioritised by severity (Critical → High → Medium → Low). "
            "0 or null means no limit."
        ),
    )
    jira_id_prefix: Optional[str] = None
    reviewers: Optional[str] = None
    adr_output_dir: Optional[str] = None


# ── Full pipeline ─────────────────────────────────────────────────────────────

class LivePipelineRequest(BaseModel):
    release_id: int = Field(..., description="Fortify SSC release ID to remediate")
    repo: Optional[str] = Field(
        default=None,
        description=(
            "GitHub repository in 'owner/repo' format. "
            "Overrides the GITHUB_REPO environment variable and triggers an automatic shallow clone so "
            "no local PROJECT_PATH is needed. e.g. \"acme/backend\""
        ),
    )
    max_upgrades: int = Field(
        default=0,
        ge=0,
        description="Max dependencies to upgrade (0 = unlimited, highest severity first)",
    )
    config: ConfigOverrides = Field(default_factory=ConfigOverrides)


class AppNamePipelineRequest(BaseModel):
    app_name: str = Field(..., description="Fortify application name — resolved to app_id then latest release_id")
    repo: Optional[str] = Field(
        default=None,
        description=(
            "GitHub repository in 'owner/repo' format. "
            "Mirrors the --repo CLI flag: overrides the GITHUB_REPO environment variable and triggers an "
            "automatic clone so no local PROJECT_PATH is needed. "
            "e.g. \"acme/backend\""
        ),
    )
    max_upgrades: int = Field(
        default=0,
        ge=0,
        description="Max dependencies to upgrade (0 = unlimited, highest severity first)",
    )
    config: ConfigOverrides = Field(default_factory=ConfigOverrides)


class AppIdPipelineRequest(BaseModel):
    app_id: int = Field(..., description="Fortify applicationId — skips name lookup, resolves directly to latest release_id")
    repo: Optional[str] = Field(
        default=None,
        description=(
            "GitHub repository in 'owner/repo' format. "
            "Overrides the GITHUB_REPO environment variable and triggers an automatic shallow clone so "
            "no local PROJECT_PATH is needed. e.g. \"acme/backend\""
        ),
    )
    max_upgrades: int = Field(
        default=0,
        ge=0,
        description="Max dependencies to upgrade (0 = unlimited, highest severity first)",
    )
    config: ConfigOverrides = Field(default_factory=ConfigOverrides)


class OfflinePipelineRequest(BaseModel):
    report_path: str = Field(..., description="Absolute path to Fortify JSON report on disk")
    release_id: int = Field(default=0, description="Release ID override (0 = read from file)")
    repo: Optional[str] = Field(
        default=None,
        description=(
            "GitHub repository in 'owner/repo' format. "
            "Overrides the GITHUB_REPO environment variable and triggers an automatic shallow clone so "
            "no local PROJECT_PATH is needed. e.g. \"acme/backend\""
        ),
    )
    max_upgrades: int = Field(
        default=0,
        ge=0,
        description="Max dependencies to upgrade (0 = unlimited, highest severity first)",
    )
    config: ConfigOverrides = Field(default_factory=ConfigOverrides)


class DryRunRequest(BaseModel):
    """Full analysis pipeline — ADR/PR/writeback are simulated, not executed."""
    release_id: int = Field(default=0)
    report_path: Optional[str] = Field(default=None, description="Use offline JSON if provided")
    app_name: Optional[str] = Field(default=None, description="Fortify application name (resolved to app_id → release_id)")
    app_id: Optional[int] = Field(default=None, description="Fortify applicationId (skips name lookup)")
    repo: Optional[str] = Field(
        default=None,
        description=(
            "GitHub repository in 'owner/repo' format. "
            "Overrides the GITHUB_REPO environment variable and triggers an automatic shallow clone so "
            "no local PROJECT_PATH is needed. e.g. \"acme/backend\""
        ),
    )
    max_upgrades: int = Field(
        default=0,
        ge=0,
        description="Max dependencies to upgrade (0 = unlimited, highest severity first)",
    )
    config: ConfigOverrides = Field(default_factory=ConfigOverrides)


# ── Auth ─────────────────────────────────────────────────────────────────────

class AuthTokenRequest(BaseModel):
    """
    Override credentials per-request. Leave all fields empty to use values
    from the process environment. Useful for testing a different account
    without editing config.
    """
    username: Optional[str] = Field(default=None, description="Fortify login username (overrides FORTIFY_USERNAME)")
    password: Optional[str] = Field(default=None, description="Fortify login password (overrides FORTIFY_PASSWORD)")
    scope: Optional[str]    = Field(default=None, description="OAuth scope (default: api-tenant)")
    write_to_env: bool       = Field(default=True, description="Persist the new token to the FORTIFY_API_TOKEN process environment variable")


# ── Individual stages ─────────────────────────────────────────────────────────

class TriageRequest(BaseModel):
    raw_vulnerabilities: list[dict] = Field(..., description="Raw Fortify /vulnerabilities response items")
    max_upgrades: int = Field(
        default=0,
        ge=0,
        description="Max dependencies to upgrade (0 = unlimited, highest severity first)",
    )


class VersionResolverRequest(BaseModel):
    groups: list[dict] = Field(..., description="Triaged dependency groups from /stages/triage")
    release_id: int = Field(..., description="Fortify release ID for version lookup")
    config: ConfigOverrides = Field(default_factory=ConfigOverrides)


class ContextRequest(BaseModel):
    groups: list[dict] = Field(..., description="Version-resolved groups")
    project_path: str = Field(..., description="Absolute path to Maven project root")


class ApiDiffRequest(BaseModel):
    groups: list[dict] = Field(..., description="Context-located groups")
    project_path: str = Field(..., description="Absolute path to Maven project root")
    japicmp_jar_path: str = Field(..., description="Absolute path to japicmp fat-jar")


class AiReasoningRequest(BaseModel):
    groups: list[dict] = Field(..., description="API-diff annotated groups")
    gcp_project: str = Field(..., description="GCP project ID for Vertex AI")
    gcp_location: str = Field(default="us-central1")


class AdrFixRequest(BaseModel):
    groups: list[dict] = Field(..., description="AI-reasoned groups")
    adr_path: str = Field(..., description="Absolute path to adr.py")
    project_path: str = Field(..., description="Absolute path to Maven project root")
    jira_prefix: str = Field(default="FORTIFY")
    release_id: int = Field(default=0, description="Fortify release ID — used in branch name (feature/fortify-fix-{releaseId}-{randId})")


class BuildValidationRequest(BaseModel):
    adr_results: list[dict] = Field(..., description="Results from /stages/adr-fix (commit-only — build not yet run)")
    project_path: str = Field(..., description="Absolute path to Maven project root")
    github_token: str = Field(default="", description="GitHub token with actions:write + contents:write; defaults to cfg.github_token if empty")
    github_repo: str = Field(default="", description="owner/repo; defaults to cfg.github_repo if empty")
    workflow_file: str = Field(default="runMavenSharedWorkflow.yml", description="Workflow file under .github/workflows/ to dispatch — must declare 'on: workflow_dispatch'")
    workflow_inputs: Optional[dict] = Field(default=None, description="Passed through to the workflow_dispatch call as-is — only include keys the workflow declares under on.workflow_dispatch.inputs")


class AiCodeFixRequest(BaseModel):
    groups: list[dict] = Field(..., description="Groups that failed build — need AI patching")
    project_path: str = Field(..., description="Absolute path to Maven project root")
    gcp_project: str = Field(default="")
    gcp_location: str = Field(default="us-central1")


class PrAgentRequest(BaseModel):
    groups: list[dict] = Field(..., description="Reasoned groups")
    adr_results: list[dict] = Field(..., description="Results from /stages/build-validation (build-validated — only pushed branches should be passed here; passing raw /stages/adr-fix output would open PRs for unbuilt commits)")
    release_id: int = Field(..., description="Fortify release ID (used in PR body)")
    github_token: str = Field(..., description="GitHub personal access token")
    github_repo: str = Field(..., description="GitHub repo in owner/repo format")
    reviewers: list[str] = Field(default_factory=list)


class FortifyWritebackRequest(BaseModel):
    groups: list[dict] = Field(..., description="Reasoned groups")
    adr_results: list[dict] = Field(..., description="Results from /stages/build-validation (or /stages/adr-fix merged with it)")
    pr_results: list[dict] = Field(default_factory=list)
    output_dir: str = Field(default="")  # empty = read ADR_OUTPUT_DIR from the environment at runtime


# ── Partial pipeline ──────────────────────────────────────────────────────────

class PartialPipelineRequest(BaseModel):
    release_id: int = Field(default=0, description="Fortify release ID (pick one source)")
    report_path: Optional[str] = Field(default=None, description="Offline JSON report path (skips SSC API)")
    app_name: Optional[str] = Field(default=None, description="Fortify application name (resolved to app_id → release_id)")
    app_id: Optional[int] = Field(default=None, description="Fortify applicationId (skips name lookup, resolves to latest release_id)")
    repo: Optional[str] = Field(
        default=None,
        description=(
            "GitHub repository in 'owner/repo' format. "
            "Overrides the GITHUB_REPO environment variable and triggers an automatic shallow clone so "
            "no local PROJECT_PATH is needed. e.g. \"acme/backend\""
        ),
    )
    max_upgrades: int = Field(
        default=0,
        ge=0,
        description="Max dependencies to upgrade (0 = unlimited, highest severity first)",
    )
    config: ConfigOverrides = Field(default_factory=ConfigOverrides)


# ── Shared response envelope ──────────────────────────────────────────────────

def ok(data: Any, elapsed: float | None = None) -> dict:
    resp: dict = {"ok": True, "data": data}
    if elapsed is not None:
        resp["elapsed_seconds"] = round(elapsed, 3)
    return resp


def err(detail: str, exc: Exception | None = None) -> JSONResponse:
    body: dict = {"ok": False, "error": detail}
    if exc is not None:
        body["traceback"] = traceback.format_exc()
    return JSONResponse(status_code=500, content=body)


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _apply_overrides(cfg: FortifyAIConfig, overrides: ConfigOverrides) -> FortifyAIConfig:
    """Return a new config with non-None override fields applied."""
    data = cfg.model_dump()
    for field, value in overrides.model_dump().items():
        if value is not None:
            data[field] = value
    return FortifyAIConfig(**data)


def _escalation_reason(group: dict) -> str:
    """
    Resolve the human-readable reason a dependency group was escalated.

    Two different pipeline stages can send a group to escalation, and each
    records its reason under a different key on the group dict:
      - version_resolver.py sets ``group["escalate_reason"]`` when no safe
        upgrade candidate could be resolved at all (escalated before AI
        reasoning ever runs).
      - ai_reasoning.py sets ``group["ai_reasoning"]["reason"]`` — NOT a
        top-level ``group["escalation_reason"]`` key, despite that being
        what earlier code here looked for. That mismatch meant this always
        missed and silently fell back to a generic "Escalated by AI
        reasoning" placeholder, even though the actual, specific reason
        (e.g. "No safe version candidates available", or whatever the LLM
        flagged as unsafe) was sitting right there in the group.

    Checked in pipeline order: an earlier-stage escalation (version
    resolver) takes precedence over a later one (AI reasoning), since a
    group that never reached AI reasoning won't have an ai_reasoning
    result to explain anyway.
    """
    return (
        group.get("escalate_reason")
        or (group.get("ai_reasoning") or {}).get("reason")
        or "Escalated — no reason recorded"
    )


def _should_persist_token(overrides: ConfigOverrides) -> bool:
    """
    Decide whether a freshly-fetched Fortify OAuth token may be written to
    the shared process environment / GCS runtime config (see
    fortify_auth.write_token_to_env).

    That writeback is a *global* fallback used by any future request that
    doesn't supply its own credentials. If THIS request supplied a
    per-run fortify_username/fortify_password override, the token it
    produces belongs to that one user/run and must never become the
    default other users' un-credentialed runs silently pick up.

    Only the server's own env-configured default credentials (no override
    present) are allowed to refresh the shared fallback token.
    """
    return not (overrides.fortify_username or overrides.fortify_password)


def _resolve_vulnerabilities(
    cfg: FortifyAIConfig,
    release_id: int,
    report_path: str | None,
    app_name: str | None,
    app_id: int | None = None,
    persist_token: bool = True,
):
    """
    Returns (client, raw_vulns, resolved_release_id, resolved_app_id).

    Resolution priority:
      1. report_path  — offline mode, no SSC calls
      2. release_id   — direct, fastest
      3. app_id       — skips name lookup, calls GET /releases?limit=1
      4. app_name     — name → app_id → release_id (two API calls)

    ``persist_token`` controls whether a freshly-fetched OAuth token gets
    written to the shared process env / GCS config — see
    ``_should_persist_token``. Pass False whenever ``cfg`` carries
    per-request Fortify credentials that don't belong to the server's
    own default account.
    """
    from fortify_client import FortifyClient
    from offline_loader import load_report, NullFortifyClient

    if report_path:
        raw_vulns, file_release_id = load_report(report_path)
        effective_release_id = file_release_id if file_release_id else release_id
        client = NullFortifyClient(raw_vulns)
        return client, raw_vulns, effective_release_id, None

    client = FortifyClient.from_config(cfg, persist_token=persist_token)
    resolved_app_id: int | None = app_id

    if app_name and not app_id:
        # name → app_id (GET /api/v3/applications?filters=applicationName:<name>)
        app = client.get_application_by_name(app_name)
        resolved_app_id = app["applicationId"]

    if resolved_app_id and not release_id:
        # app_id → latest release_id (GET /api/v3/applications/{id}/releases?limit=1)
        release = client.get_latest_release(resolved_app_id)
        release_id = release["releaseId"]

    if release_id == 0:
        raise ValueError("Provide one of: release_id, app_id, app_name, or report_path")

    raw_vulns = client.get_vulnerabilities(release_id)
    return client, raw_vulns, release_id, resolved_app_id


def _clone_repo_if_needed(cfg: FortifyAIConfig, repo: str | None) -> tuple[FortifyAIConfig, str | None]:
    """
    Mirror the CLI --repo auto-clone behaviour for the API server.

    If *repo* is provided:
      1. Overrides cfg.github_repo with *repo*.
      2. Clones the repo into a temp directory (shallow, depth=1).
      3. Overrides cfg.project_path with the cloned directory — so ADR,
         context, api-diff, and every other stage that reads project_path
         will operate on the fresh clone instead of a stale local path.

    Returns (updated_cfg, clone_dir_or_None).
    The caller is responsible for cleaning up clone_dir when the pipeline finishes.
    """
    import tempfile
    import subprocess as _sp

    if not repo:
        return cfg, None

    # 1 — override github_repo
    object.__setattr__(cfg, "github_repo", repo)

    # 2 — clone
    repo_url = f"https://{cfg.github_token}@github.com/{cfg.github_repo}.git"
    clone_dir = tempfile.mkdtemp(prefix="fortifyai_clone_")
    try:
        result = _sp.run(
            ["git", "-c", "http.sslVerify=false", "clone", "--depth", "1", repo_url, clone_dir],
            capture_output=True, text=True, timeout=300,
        )
        if result.returncode != 0:
            import shutil
            shutil.rmtree(clone_dir, ignore_errors=True)
            raise RuntimeError(
                f"git clone failed for {repo}:\n{result.stderr[:500]}"
            )
    except _sp.TimeoutExpired:
        import shutil
        shutil.rmtree(clone_dir, ignore_errors=True)
        raise RuntimeError(f"git clone timed out after 300s for {repo}")
    except FileNotFoundError:
        import shutil
        shutil.rmtree(clone_dir, ignore_errors=True)
        raise RuntimeError("git not found on PATH — cannot auto-clone repo")

    # 3 — point project_path at the fresh clone so every downstream stage uses it
    object.__setattr__(cfg, "project_path", clone_dir)

    return cfg, clone_dir


def _run_full_pipeline(
    cfg: FortifyAIConfig,
    client,
    raw_vulns: list[dict],
    release_id: int,
    dry_run: bool = False,
    pipeline_id: str | None = None,
    max_upgrades: int = 0,
    resume_checkpoint: dict | None = None,
) -> dict:
    """
    Execute the full pipeline and return a summary dict.

    When *pipeline_id* is supplied, each stage updates the shared job store
    so callers can poll /pipeline/status/{pipeline_id} for live progress,
    AND the full JSON-serializable output of every completed stage is
    persisted via job_store.save_checkpoint (not just the lightweight
    output_summary shown in status polls).

    When *resume_checkpoint* is supplied (job_store.get_checkpoint for a
    prior interrupted/failed run of the SAME pipeline_id — see
    POST /pipeline/resume/{pipeline_id}), stages already present in the
    checkpoint are skipped entirely and their persisted output is reused
    instead of recomputed. This is what makes resuming safe for
    side-effecting stages: adr-fix (git commit only), build-validation
    (mvn build + push-or-rollback), and pr-agent (opens a GitHub PR) are NOT
    re-run once checkpointed — only stages after the checkpoint's
    resume_stage actually execute. pr-agent additionally guards against
    duplicate PRs via branch-name lookup (see pr_agent._find_existing_pr) in
    case a checkpoint boundary is ever re-crossed.
    """
    if pipeline_id:
        token_tracker.start_run(pipeline_id)   # bind LLM token accounting to this run

    from pathlib import Path
    from agents.triage import group_by_dependency, apply_max_upgrades
    from agents.version_resolver import resolve_all_groups
    from agents.context import locate_all_groups, detect_required_jdk
    from agents.api_diff import run_api_diff_all_groups
    from agents.ai_reasoning import reason_all_groups
    from agents.adr_fix import run_adr_fix
    from agents.build_validation import validate_one
    from agents.pr_agent import create_prs_for_all_groups
    from agents.fortify_writeback import run_all_reports
    from state import AdrResult

    def _stage_start(name: str) -> float:
        t = time.time()
        if pipeline_id:
            # update_stage() is a shallow merge (dict.update), so without
            # explicitly clearing these, a stage that's restarting — on
            # resume, or a future retry — keeps whatever error/output_summary
            # its LAST attempt left behind. That stale text (e.g. "Cancelled
            # by user") would otherwise still render as this step's detail
            # even though the stage is genuinely running again right now.
            _update_stage(pipeline_id, name, status="running", started_at=_now(),
                          finished_at=None, elapsed_seconds=None,
                          error=None, output_summary=None)
        return t

    def _stage_done(name: str, t: float, summary: dict | None = None) -> None:
        if pipeline_id:
            _update_stage(pipeline_id, name,
                          status="completed",
                          finished_at=_now(),
                          elapsed_seconds=round(time.time() - t, 3),
                          output_summary=summary)

    def _stage_fail(name: str, t: float, error: str) -> None:
        if pipeline_id:
            _update_stage(pipeline_id, name,
                          status="failed",
                          finished_at=_now(),
                          elapsed_seconds=round(time.time() - t, 3),
                          error=error)

    def _stage_skip(name: str) -> None:
        if pipeline_id:
            _update_stage(pipeline_id, name, status="skipped")

    # ── Resume bookkeeping ────────────────────────────────────────────────────
    # `acc` accumulates every completed stage's full output (not the
    # lightweight output_summary). `resume_stage` is the name of the next
    # stage that had NOT yet started when the checkpoint was written — every
    # stage before it in ALL_STAGE_NAMES is skipped and served from `acc`.
    acc: dict = dict(resume_checkpoint) if resume_checkpoint else {}
    resume_stage: str | None = acc.pop("resume_stage", None)

    def _already_done(stage: str) -> bool:
        return bool(resume_stage) and ALL_STAGE_NAMES.index(stage) < ALL_STAGE_NAMES.index(resume_stage)

    def _checkpoint(next_stage: str, **fields) -> None:
        acc.update(fields)
        if pipeline_id:
            _store.save_checkpoint(pipeline_id, resume_stage=next_stage, **acc)

    if resume_stage and pipeline_id:
        print(f"[Pipeline] Resuming {pipeline_id} from stage '{resume_stage}' "
              f"(stages before it served from checkpoint, not recomputed)")

    project_path = Path(cfg.project_path) if cfg.project_path else Path(".")
    japicmp_path = cfg.japicmp_jar_path or "/nonexistent/japicmp.jar"

    # ── Background Maven cache warm-up ─────────────────────────────────────────
    # project_path is final at this point (the caller already ran
    # _clone_repo_if_needed, if applicable, before invoking this function).
    # Kick off 'mvn dependency:go-offline' here, in the background, so the
    # .m2 cache has the whole triage / version-resolution / context / api-diff
    # / ai-reasoning window to warm up before adr-fix's Phase 1b (mvn
    # dependency:tree) needs it. See maven_warmup.py for details. Shared with
    # fortifyai.py's CLI entry point so the two don't drift with separate
    # copies of this logic.
    #
    # Skipped on a resume where build-validation is already checkpointed —
    # that stage (and the mvn build it runs) won't run again for this call,
    # so warming the cache would be wasted work.
    maven_warmup_thread = None
    if _MAVEN_WARMUP_ENABLED and not _already_done("build-validation"):
        maven_warmup_thread = start_maven_warmup(str(project_path))

    # Stage 1 — triage
    if _already_done("triage"):
        groups = acc["groups"]
        triage_skipped = acc.get("triage_skipped", 0)
    else:
        _check_cancelled(pipeline_id)
        t = _stage_start("triage")
        groups, triage_skipped = group_by_dependency(raw_vulns)
        groups = apply_max_upgrades(groups, max_upgrades or cfg.max_upgrades)
        if not groups:
            _stage_done("triage", t, {
                "total_groups": 0, "groups_count": 0,
                "total_skipped": triage_skipped,
            })
            for s in ["version-resolver", "context", "api-diff",
                      "ai-reasoning", "adr-fix", "build-validation", "pr-agent", "fortify-writeback"]:
                _stage_skip(s)
            return {"status": "skipped", "reason": "No actionable findings"}
        _stage_done("triage", t, {
            "total_groups": len(groups), "groups_count": len(groups),
            "total_skipped": triage_skipped,
        })
        _checkpoint("version-resolver", groups=groups, triage_skipped=triage_skipped)

    # Stage 2 — version resolver
    if _already_done("version-resolver"):
        resolved = acc["resolved"]
    else:
        _check_cancelled(pipeline_id)
        t = _stage_start("version-resolver")
        resolved = resolve_all_groups(client, release_id, groups)
        _stage_done("version-resolver", t, {"groups_count": len(resolved)})
        _checkpoint("context", resolved=resolved)

    # Stage 3 — context
    if _already_done("context"):
        context = acc["context"]
        # required_jdk was computed in a prior attempt and checkpointed
        # alongside "context" — pull it back out rather than losing it on
        # resume (it's still needed by ai-reasoning/adr-fix below).
        required_jdk = acc.get("required_jdk")
    else:
        _check_cancelled(pipeline_id)
        t = _stage_start("context")
        context = locate_all_groups(project_path, resolved)

        # detect_required_jdk() itself logs every step of what it finds
        # (INFO on a match, WARNING on mvn/effective-pom failures). This
        # block only adds the final per-run outcome — and, critically, logs
        # the None case explicitly rather than saying nothing, since silent
        # failure here was indistinguishable from this call never having
        # run at all.
        required_jdk = detect_required_jdk(project_path)
        if required_jdk:
            print(f"[Context] Project requires JDK {required_jdk}")
        else:
            print(
                "[Context] required_jdk is None for this run — downstream "
                "agents (AI Reasoning, JDK registry selection) will treat "
                "this project's JDK as unknown"
            )

        _stage_done("context", t, {
            "groups_count": len(context), "required_jdk": required_jdk,
        })
        _checkpoint("api-diff", context=context, required_jdk=required_jdk)

    # Stage 4 — api diff
    if _already_done("api-diff"):
        diffed = acc["diffed"]
    else:
        _check_cancelled(pipeline_id)
        t = _stage_start("api-diff")
        try:
            diffed = run_api_diff_all_groups(context, project_path, japicmp_path)
        except Exception as exc:
            # JAR missing / japicmp missing / japicmp execution failure — must
            # stop the pipeline. Mark the stage failed (not left stuck at
            # "running") and re-raise so the caller marks the whole job failed.
            _stage_fail("api-diff", t, str(exc))
            raise
        _stage_done("api-diff", t, {"groups_count": len(diffed)})
        _checkpoint("ai-reasoning", diffed=diffed)

    # Cancel-check callback threaded into ai-reasoning / adr-fix below so a
    # cancel request is honored mid-stage (mid per-group LLM loop, mid Maven
    # build subprocess) instead of only at the stage boundaries _check_cancelled
    # checks — see PipelineCancelledError in state.py for why.
    cancel_check = _cancel_check_for(pipeline_id)

    # Stage 5 — ai reasoning
    if _already_done("ai-reasoning"):
        reasoned = acc["reasoned"]
    else:
        _check_cancelled(pipeline_id)
        t = _stage_start("ai-reasoning")
        try:
            reasoned = reason_all_groups(
                diffed, cfg.gcp_project, cfg.gcp_location,
                cancel_check=cancel_check, required_jdk=required_jdk,
            )
        except PipelineCancelledError:
            _stage_fail("ai-reasoning", t, "Cancelled by user")
            raise
        except Exception as exc:
            # A fatal AI reasoning error (permission denied, auth, quota, etc.)
            # must stop the pipeline — mark the stage failed (not left stuck at
            # "running") and re-raise so the caller marks the whole job failed.
            _stage_fail("ai-reasoning", t, str(exc))
            raise
        _stage_done("ai-reasoning", t, {
            "safe": sum(1 for g in reasoned if g.get("next_node") != "escalate"),
            "escalated": sum(1 for g in reasoned if g.get("next_node") == "escalate"),
        })
        _checkpoint("adr-fix", reasoned=reasoned)

    # Stage 6 — adr fix (side-effecting: commits ONLY — no build, no push.
    # Never re-run once checkpointed.)
    if _already_done("adr-fix"):
        adr_results = acc["adr_results"]
    else:
        _check_cancelled(pipeline_id)
        t = _stage_start("adr-fix")
        adr_results: list[dict] = []
        try:
            for group in reasoned:
                _check_cancelled(pipeline_id)  # stop before committing the next group
                artifact_id = group["parsed"]["artifact_id"]
                if group.get("next_node") == "escalate":
                    adr_results.append({
                        "artifact_id": artifact_id,
                        "result": AdrResult(
                            success=False, branch_name=None, base_branch=None,
                            commit_hash=None, build_time_seconds=None, pdf_path=None,
                            error_reason=_escalation_reason(group),
                        ),
                    })
                    continue
                if dry_run or not cfg.adr_path:
                    adr_results.append({
                        "artifact_id": artifact_id,
                        "result": AdrResult(
                            success=False, branch_name=None, base_branch=None,
                            commit_hash=None, build_time_seconds=None, pdf_path=None,
                            error_reason="dry_run=True — ADR not invoked" if dry_run else "ADR_PATH not configured",
                        ),
                    })
                else:
                    result = run_adr_fix(
                        group, adr_path=cfg.adr_path,
                        project_path=str(project_path),
                        jira_prefix=cfg.jira_id_prefix,
                        release_id=release_id,
                        cancel_check=cancel_check,
                        required_jdk=required_jdk,
                    )
                    adr_results.append({"artifact_id": artifact_id, "result": result})
        except PipelineCancelledError:
            # Raised either between groups (_check_cancelled) or from inside
            # run_adr_fix if cancellation landed mid-commit — either way the
            # subprocess has already been terminated by this point.
            _stage_fail("adr-fix", t, "Cancelled by user")
            raise
        _adr_ok = sum(1 for r in adr_results if r.get("result", {}).get("success"))
        _stage_done("adr-fix", t, {"committed": _adr_ok, "total": len(adr_results)})
        _checkpoint("build-validation", adr_results=adr_results)

    # Stage 6b — build validation (side-effecting: runs mvn, then pushes on
    # success or rolls the branch back on failure. Never re-run once checkpointed.)
    log_warmup_status(maven_warmup_thread)
    if _already_done("build-validation"):
        adr_results = acc["adr_results"]  # overwritten below with the merged/build-validated version
    else:
        _check_cancelled(pipeline_id)
        t = _stage_start("build-validation")
        merged_results: list[dict] = []
        try:
            for entry in adr_results:
                _check_cancelled(pipeline_id)  # stop before pushing the next branch
                artifact_id = entry["artifact_id"]
                adr_result = entry["result"]
                if not adr_result.get("success"):
                    # Nothing was committed for this group — nothing to build.
                    merged_results.append({"artifact_id": artifact_id, "result": {
                        **adr_result, "build_time_seconds": None,
                    }})
                    continue
                bv_result = validate_one(
                    artifact_id, adr_result, str(project_path),
                    github_token=cfg.github_token, github_repo=cfg.github_repo,
                    workflow_file=cfg.build_workflow_file, cancel_check=cancel_check,
                )
                merged_results.append({"artifact_id": artifact_id, "result": {
                    **adr_result,
                    "success": bv_result["success"],
                    "branch_name": bv_result["branch_name"],
                    "build_time_seconds": bv_result["build_time_seconds"],
                    "error_reason": bv_result["error_reason"] or adr_result.get("error_reason"),
                }})
        except PipelineCancelledError:
            # Mid-build or mid-push termination — see validate_one's docstring;
            # treat state as unknown, not a clean rollback.
            _stage_fail("build-validation", t, "Cancelled by user")
            raise
        adr_results = merged_results
        _bv_ok = sum(1 for r in adr_results if r.get("result", {}).get("success"))
        _stage_done("build-validation", t, {"pushed": _bv_ok, "total": len(adr_results)})
        _checkpoint("pr-agent", adr_results=adr_results)

    # Stage 7 — pr agent (side-effecting: opens PRs — idempotent via branch-name lookup)
    if _already_done("pr-agent"):
        pr_results = acc.get("pr_results", [])
    else:
        _check_cancelled(pipeline_id)  # stop before opening PRs
        pr_results = []
        if not dry_run and cfg.github_token and cfg.github_repo:
            t = _stage_start("pr-agent")
            pr_results = create_prs_for_all_groups(
                groups=reasoned, adr_results=adr_results,
                release_id=release_id,
                github_token=cfg.github_token,
                github_repo=cfg.github_repo,
                reviewers=cfg.get_reviewers(),
            )
            _stage_done("pr-agent", t, {"prs_created": len(pr_results)})
        else:
            _stage_skip("pr-agent")
        _checkpoint("fortify-writeback", pr_results=pr_results)

    # Stage 8 — writeback + summary (idempotent — deterministic filenames keyed by pipeline_id)
    _check_cancelled(pipeline_id)
    if not dry_run:
        t = _stage_start("fortify-writeback")
        summary = run_all_reports(
            groups=reasoned, adr_results=adr_results,
            pr_results=pr_results, output_dir=cfg.adr_output_dir,
            pipeline_id=pipeline_id,
        )
        _stage_done("fortify-writeback", t, summary)
    else:
        _stage_skip("fortify-writeback")
        summary = {"dry_run": True, "groups": len(reasoned)}

    return {
        "release_id":   release_id,
        "groups_count": len(reasoned),
        "groups":       reasoned,
        "adr_results":  adr_results,
        "pr_results":   pr_results,
        "total_fixed":       summary.get("total_fixed",     0),
        "total_escalated":   summary.get("total_escalated", 0),
        "total_failed":      summary.get("total_failed",    0),
        "summary":      summary,
        "dry_run":      dry_run,
    }

@app.on_event("startup")
async def startup_event():
    """Fetch a fresh Fortify Bearer token at boot and set it in the process environment."""
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(_EXECUTOR, auth_token)
        if isinstance(result, dict) and result.get("ok"):
            print("[Startup] Fortify token fetched and set in process environment")
        else:
            print(f"[Startup] Fortify token fetch skipped or failed: {result}")
    except Exception as exc:
        # Non-fatal — server still starts; token can be fetched via POST /auth/token
        print(f"[Startup] Fortify token fetch error (non-fatal): {exc}")

    # Start the background orphan-job sweep (see _run_orphan_sweep / plan
    # item "orphan-job sweep"). Runs on every pod; each sweep is a cheap
    # metadata-only scan so redundant concurrent sweeps across pods are
    # harmless — worst case, two pods finish_job the same already-stale
    # job, and the second write is a no-op overwrite of the same status.
    global _orphan_sweep_task
    _orphan_sweep_task = asyncio.create_task(_orphan_sweep_loop())
    print(
        f"[Startup] Orphan-job sweep running every {_ORPHAN_SWEEP_INTERVAL_SECONDS}s "
        f"(timeout={_ORPHAN_SWEEP_TIMEOUT_SECONDS}s)"
    )

    # One-shot scan for jobs stranded 'interrupted'/'failed' by a pod that
    # went away before it could resume them itself — picks the work back
    # up on this pod instead of waiting for a human or the next sweep
    # interval. See _auto_resume_startup_scan / AUTO_RESUME_ENABLED.
    if _AUTO_RESUME_ENABLED:
        try:
            resumed = await loop.run_in_executor(_EXECUTOR, _auto_resume_startup_scan)
            if resumed:
                print(f"[Startup] Auto-resumed {len(resumed)} job(s) left over from a "
                      f"previous pod: {resumed}")
        except Exception as exc:
            print(f"[Startup] Auto-resume scan error (non-fatal): {exc}")
    else:
        print("[Startup] Auto-resume disabled (AUTO_RESUME_ENABLED=false)")


@app.on_event("shutdown")
async def shutdown_event():
    """
    Runs when the ASGI server begins graceful shutdown — uvicorn invokes the
    lifespan 'shutdown' event on receiving SIGTERM (the signal k8s sends on
    pod termination: node drain, scale-down, rolling deploy, preemptible/spot
    reclaim). This is the highest-leverage fault-tolerance fix: without it, a
    pipeline caught mid-run when the pod dies is left stuck at status
    'running' forever, with no indication anything went wrong until the
    orphan sweep's timeout eventually catches it.

    Two things happen for every pipeline_id still active on this pod:
      1. request_cancel — gives any in-flight run a chance to stop cleanly
         at the next stage boundary (_check_cancelled) if the remaining
         terminationGracePeriodSeconds allows it.
      2. finish_job(..., status='interrupted') — marks the job honestly
         rather than leaving it at 'running'. The checkpoint written after
         the last completed stage (see _run_full_pipeline) is NOT cleared,
         so POST /pipeline/resume/{pipeline_id} can continue the job on
         whichever pod picks it up next instead of restarting from triage.

    Note: this only fires for a graceful SIGTERM within the pod's
    terminationGracePeriodSeconds. A hard kill (SIGKILL / OOM kill) skips
    application shutdown entirely — that failure mode is covered by the
    orphan-job sweep instead (see _run_orphan_sweep).
    """
    with _active_lock:
        pids = list(_ACTIVE_PIPELINES.keys())

    if pids:
        print(f"[Shutdown] SIGTERM received — {len(pids)} pipeline(s) still active on this pod: {pids}")

    for pid in pids:
        try:
            _store.request_cancel(pid)
        except Exception as exc:
            print(f"[Shutdown] request_cancel failed for {pid}: {exc}")
        try:
            _store.finish_job(
                pid, "interrupted",
                error=(
                    "Pod received SIGTERM and shut down before this pipeline "
                    "finished. Resume via POST /pipeline/resume/{pipeline_id} "
                    "to continue from the last completed stage."
                ),
            )
        except Exception as exc:
            print(f"[Shutdown] finish_job(interrupted) failed for {pid}: {exc}")

    if _orphan_sweep_task is not None:
        _orphan_sweep_task.cancel()

# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/health", tags=["Utility"])
def health():
    """Liveness probe — always returns 200 OK."""
    return {"ok": True, "service": "FortifyAI API"}


class ConfigUpdateRequest(BaseModel):
    """Fields that the UI Settings page can read/write. All optional."""
    gcp_project:                 Optional[str]   = None
    vertex_model:                Optional[str]   = None
    max_issues:                  Optional[int]   = None
    max_tokens:                  Optional[int]   = None
    confidence_high_threshold:   Optional[float] = None
    confidence_medium_threshold: Optional[float] = None
    planner_temp:                Optional[float] = None
    generator_temp:              Optional[float] = None
    max_critic_retries:          Optional[int]   = None
    chroma_persist_dir:          Optional[str]   = None
    embedding_model:             Optional[str]   = None
    rag_top_k:                   Optional[int]   = None
    sonar_host_url:              Optional[str]   = None
    fortify_host_url:            Optional[str]   = None
    adr_output_dir:              Optional[str]   = None
    # Fortify OAuth credentials (used to fetch/refresh the Bearer token)
    fortify_username:             Optional[str]   = None
    fortify_password:             Optional[str]   = None
    fortify_scope:                Optional[str]   = None
    # Tokens — write-only; reading returns "***" if set, "" if empty
    github_token:                Optional[str]   = None
    sonar_token:                 Optional[str]   = None
    fortify_token:               Optional[str]   = None


def _mask(val: str) -> str:
    """Return '***' when a secret is set, empty string when it isn't."""
    return "***" if val else ""


@app.get("/api/config", tags=["Utility"])
def get_config():
    """
    Return current config values (read from the process environment) for
    the UI Settings page. Secret tokens are masked as '***' (never returned
    in plain text). adr_output_dir is always included so the UI knows where
    escalation files are written without needing to hardcode the path.
    """
    try:
        cfg = load_config()
    except Exception as exc:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(exc)})
    return {
        "gcp_project":                 cfg.gcp_project,
        "vertex_model":                getattr(cfg, "vertex_model", ""),
        "max_issues":                  getattr(cfg, "max_issues", 1),
        "max_tokens":                  getattr(cfg, "max_tokens", 8192),
        "confidence_high_threshold":   getattr(cfg, "confidence_high_threshold", 0.80),
        "confidence_medium_threshold": getattr(cfg, "confidence_medium_threshold", 0.50),
        "planner_temperature":         getattr(cfg, "planner_temp", 0.1),
        "generator_temperature":       getattr(cfg, "generator_temp", 0.3),
        "max_critic_retries":          cfg.max_retries,
        "chroma_persist_dir":          getattr(cfg, "chroma_persist_dir", ""),
        "embedding_model":             getattr(cfg, "embedding_model", ""),
        "rag_top_k":                   getattr(cfg, "rag_top_k", 3),
        "sonar_host_url":              getattr(cfg, "sonar_host_url", ""),
        "fortify_host_url":            cfg.fortify_base_url,
        "adr_output_dir":              cfg.adr_output_dir,
        # Fortify OAuth credentials — username/scope are not secret, password is masked
        "fortify_username":            cfg.fortify_username,
        "fortify_password":            _mask(cfg.fortify_password),
        "fortify_scope":               cfg.fortify_scope,
        # Tokens — masked
        "github_token":                _mask(cfg.github_token),
        "sonar_token":                 _mask(getattr(cfg, "sonar_token", "")),
        "fortify_token":               _mask(cfg.fortify_api_token),
    }


@app.post("/api/config", tags=["Utility"])
def save_config(req: ConfigUpdateRequest):
    """
    Apply Settings-page fields as runtime config overrides.

    Each field is written to the shared GCS runtime config blob
    (gs://{GCS_BUCKET}/fortifyai/config/runtime.json) AND to this process's
    environment. Every other pod picks the change up within
    CONFIG_SYNC_SECONDS (default 15 s) via the sync middleware, and the
    values survive pod restarts.

    When GCS_BUCKET is unset (local dev), behaviour degrades to the
    original process-environment-only semantics.

    Only non-None fields are applied; fields omitted from the request are
    left untouched. Tokens are only applied when a non-empty string is
    supplied (empty string or None = leave unchanged).
    """
    import os as _os

    # Map from request field → environment variable name
    field_map: dict[str, str] = {
        "gcp_project":                 "GCP_PROJECT",
        "vertex_model":                "VERTEX_MODEL",
        "max_issues":                  "MAX_ISSUES",
        "max_tokens":                  "MAX_TOKENS",
        "confidence_high_threshold":   "CONFIDENCE_HIGH_THRESHOLD",
        "confidence_medium_threshold": "CONFIDENCE_MEDIUM_THRESHOLD",
        "planner_temp":                "PLANNER_TEMP",
        "generator_temp":              "GENERATOR_TEMP",
        "max_critic_retries":          "MAX_CRITIC_RETRIES",
        "chroma_persist_dir":          "CHROMA_PERSIST_DIR",
        "embedding_model":             "EMBEDDING_MODEL",
        "rag_top_k":                   "RAG_TOP_K",
        "sonar_host_url":              "SONAR_HOST_URL",
        "fortify_host_url":            "FORTIFY_BASE_URL",
        "adr_output_dir":              "ADR_OUTPUT_DIR",
        "fortify_username":            "FORTIFY_USERNAME",
        "fortify_password":            "FORTIFY_PASSWORD",
        "fortify_scope":               "FORTIFY_SCOPE",
        "github_token":                "GITHUB_TOKEN",
        "sonar_token":                 "SONAR_TOKEN",
        "fortify_token":               "FORTIFY_API_TOKEN",
    }

    updates: dict[str, str] = {}
    for field, env_key in field_map.items():
        val = getattr(req, field, None)
        if val is None:
            continue
        # For secret fields: skip if empty string (keep existing value)
        if field in ("github_token", "sonar_token", "fortify_token", "fortify_password") and not str(val):
            continue
        updates[env_key] = str(val)

    if not updates:
        return {"message": "No fields to update"}

    persisted = persist_overrides(updates)

    return {
        "message": (
            f"Applied {len(updates)} field(s) "
            + ("and persisted to shared GCS config" if persisted
               else "to the process environment only (GCS not configured)")
        ),
        "updated": list(updates.keys()),
        "persisted": persisted,
    }


@app.get("/config/validate", tags=["Utility"])
def config_validate():
    """
    Load and validate the current config from the process environment.
    Returns which required fields are present/missing.
    """
    try:
        cfg = load_config()
    except Exception as exc:
        return JSONResponse(status_code=422, content={"ok": False, "error": str(exc)})

    checks = {
        "fortify_base_url": bool(cfg.fortify_base_url),
        "fortify_api_token": bool(cfg.fortify_api_token),
        "github_token": bool(cfg.github_token),
        "github_repo": bool(cfg.github_repo),
        "project_path": bool(cfg.project_path),
        "adr_path": bool(cfg.adr_path),
        "japicmp_jar_path": bool(cfg.japicmp_jar_path),
        "gcp_project": bool(cfg.gcp_project),
    }
    missing = [k for k, v in checks.items() if not v]
    return ok({"fields": checks, "missing": missing, "ready": len(missing) == 0})


@app.post("/auth/token", tags=["Utility"])
def auth_token(req: Optional[AuthTokenRequest] = None):
    """
    Fetch a fresh Fortify Bearer token via OAuth2 password grant and
    optionally set it as `FORTIFY_API_TOKEN` in the process environment.

    Send as **JSON body** (`Content-Type: application/json`):

        {
          "username":     null,
          "password":     null,
          "scope":        null,
          "write_to_env": true
        }

    All fields are optional — null values fall back to environment-variable
    values (FORTIFY_USERNAME, FORTIFY_PASSWORD, FORTIFY_SCOPE).

    Flow:
      POST {FORTIFY_BASE_URL}/oauth/token   (form-encoded internally)
        grant_type=password  scope=api-tenant
        username=<FORTIFY_USERNAME>  password=<FORTIFY_PASSWORD>
        security_code=  do_totp=false
      → access_token set as FORTIFY_API_TOKEN in the process environment
        (if write_to_env=true)

    Note: this only updates the current process's environment — it does
    NOT persist across a server restart.

    Returns:
      access_token, token_type, expires_in, scope
    """
    import time as _time
    t0 = _time.time()
    try:
        from fortify_auth import fetch_token, write_token_to_env
        # req is fully optional — all fields fall back to environment values when absent
        _req = req or AuthTokenRequest()
        cfg  = load_config()

        token_data = fetch_token(
            cfg,
            username=_req.username,
            password=_req.password,
            scope=_req.scope,
        )
        if _req.write_to_env and token_data.get("access_token"):
            # write_token_to_env sets the local process env AND persists the
            # token to the shared GCS runtime config (see fortify_auth.py),
            # so every pod sees the refreshed token within CONFIG_SYNC_SECONDS.
            write_token_to_env(token_data["access_token"])
        return ok({
            "access_token":   token_data.get("access_token"),
            "token_type":     token_data.get("token_type", "Bearer"),
            "expires_in":     token_data.get("expires_in"),
            "scope":          token_data.get("scope"),
            "written_to_env": _req.write_to_env,
        }, _time.time() - t0)
    except Exception as exc:
        return err(str(exc), exc)


@app.get("/releases", tags=["Utility"])
def list_releases(
    app_name: Optional[str] = Query(default=None, description="Fortify application name"),
    app_id: Optional[int] = Query(default=None, description="Fortify applicationId (skips name lookup)"),
):
    """
    List all releases for an application.

    Provide **either** `app_name` or `app_id` as a query parameter.
    Using `app_id` skips the name-lookup API call and is preferred when the ID is known.

    Examples:
      GET /releases?app_name=1038_US_D360-Citi-Triggers-on-Cloud_USIS
      GET /releases?app_id=147266
    """
    try:
        if not app_name and not app_id:
            raise ValueError("Provide either app_name or app_id as a query parameter")
        cfg = load_config()
        from fortify_client import FortifyClient
        client = FortifyClient.from_config(cfg)
        if app_id is None:
            # name → app_id first
            app = client.get_application_by_name(app_name)
            app_id = app["applicationId"]
        releases = client.get_releases(app_id)
        return ok({"app_id": app_id, "app_name": app_name, "releases": releases})
    except Exception as exc:
        return err(str(exc), exc)


@app.get("/resolve/app-name", tags=["Utility"])
def resolve_app_name(
    app_name: str = Query(..., description="Fortify application name to resolve"),
):
    """
    Resolve an application name to its `applicationId` and latest `releaseId`.

    Calls:
      1. GET /api/v3/applications?filters=applicationName:<name>  → applicationId
      2. GET /api/v3/applications/{applicationId}/releases?limit=1 → releaseId

    Returns both IDs so callers can cache the `app_id` and use
    `/pipeline/app-id` on subsequent requests (one fewer API call).
    """
    try:
        cfg = load_config()
        from fortify_client import FortifyClient
        client = FortifyClient.from_config(cfg)
        app = client.get_application_by_name(app_name)
        app_id: int = app["applicationId"]
        release = client.get_latest_release(app_id)
        return ok({
            "app_name": app_name,
            "app_id": app_id,
            "latest_release_id": release["releaseId"],
            "latest_release_name": release.get("releaseName"),
            "latest_release_date": release.get("releaseCreatedDate"),
        })
    except Exception as exc:
        return err(str(exc), exc)


# ═══════════════════════════════════════════════════════════════════════════════
# FULL PIPELINE ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/pipeline/live", tags=["Full Pipeline"])
async def pipeline_live(req: LivePipelineRequest):
    """
    Run the **complete** FortifyAI pipeline against a live Fortify SSC release.

    Returns a *pipeline_id* immediately. Poll **GET /pipeline/status/{pipeline_id}**
    to track progress stage-by-stage.

    Stages: triage → version-resolver → context → api-diff →
            ai-reasoning → adr-fix → build-validation → pr-agent → fortify-writeback
    """
    job = _new_job()
    pid = job["pipeline_id"]

    async def _run():
        t0 = time.time()
        loop = asyncio.get_event_loop()
        clone_dir: str | None = None
        _store.update_job(pid, status="running")
        _track_start(pid)
        try:
            cfg = _apply_overrides(load_config(), req.config)
            cfg, clone_dir = await loop.run_in_executor(
                _EXECUTOR,
                lambda: _clone_repo_if_needed(cfg, req.repo),
            )
            client, raw_vulns, release_id, app_id = await loop.run_in_executor(
                _EXECUTOR,
                lambda: _resolve_vulnerabilities(
                    cfg, req.release_id, None, None,
                    persist_token=_should_persist_token(req.config),
                ),
            )
            # Capture everything a resume needs to reconstruct cfg + refetch
            # vulnerabilities, using the RESOLVED release_id (not the raw
            # request) so a later resume targets the exact same release.
            # Credentials inside config_overrides (Fortify password, GitHub
            # PAT, Sonar token, ...) are symmetrically encrypted before
            # this ever reaches the job store — see credential_vault.py.
            _store.update_job(pid, resume_meta=encrypt_resume_meta({
                "release_id": release_id,
                "report_path": None,
                "app_name": None,
                "app_id": None,
                "repo": req.repo,
                "dry_run": False,
                "max_upgrades": req.max_upgrades,
                "config_overrides": req.config.model_dump(),
            }))
            result = await loop.run_in_executor(
                _EXECUTOR,
                lambda: _run_full_pipeline(cfg, client, raw_vulns, release_id,
                                           max_upgrades=req.max_upgrades,
                                           pipeline_id=pid),
            )
            if req.repo:
                result["repo"] = req.repo
            _finish_job(pid, "completed", result=result, t0=t0)
        except (PipelineCancelled, PipelineCancelledError):
            _finish_job(pid, "cancelled", error="Cancelled by user", t0=t0)
        except Exception as exc:
            _finish_job(pid, "failed", error=str(exc), t0=t0)
        finally:
            _track_end(pid)
            if clone_dir:
                import shutil
                shutil.rmtree(clone_dir, ignore_errors=True)

    asyncio.create_task(_run())
    return ok({"pipeline_id": pid, "status": "queued"})


@app.post("/pipeline/offline", tags=["Full Pipeline"])
async def pipeline_offline(req: OfflinePipelineRequest):
    """
    Run the **complete** pipeline from a saved Fortify JSON report (no SSC credentials needed).

    Returns a *pipeline_id* immediately. Poll **GET /pipeline/status/{pipeline_id}**
    to track progress stage-by-stage.

    Stages: triage → version-resolver → context → api-diff →
            ai-reasoning → adr-fix → build-validation → pr-agent → fortify-writeback
    """
    job = _new_job()
    pid = job["pipeline_id"]

    async def _run():
        t0 = time.time()
        loop = asyncio.get_event_loop()
        clone_dir: str | None = None
        _store.update_job(pid, status="running")
        _track_start(pid)
        try:
            cfg = _apply_overrides(load_config(), req.config)
            cfg, clone_dir = await loop.run_in_executor(
                _EXECUTOR,
                lambda: _clone_repo_if_needed(cfg, req.repo),
            )
            client, raw_vulns, release_id, app_id = await loop.run_in_executor(
                _EXECUTOR,
                lambda: _resolve_vulnerabilities(
                    cfg, req.release_id, req.report_path, None,
                    persist_token=_should_persist_token(req.config),
                ),
            )
            _store.update_job(pid, resume_meta=encrypt_resume_meta({
                "release_id": release_id,
                "report_path": req.report_path,
                "app_name": None,
                "app_id": None,
                "repo": req.repo,
                "dry_run": False,
                "max_upgrades": req.max_upgrades,
                "config_overrides": req.config.model_dump(),
            }))
            result = await loop.run_in_executor(
                _EXECUTOR,
                lambda: _run_full_pipeline(cfg, client, raw_vulns, release_id,
                                           max_upgrades=req.max_upgrades,
                                           pipeline_id=pid),
            )
            if req.repo:
                result["repo"] = req.repo
            _finish_job(pid, "completed", result=result, t0=t0)
        except (PipelineCancelled, PipelineCancelledError):
            _finish_job(pid, "cancelled", error="Cancelled by user", t0=t0)
        except Exception as exc:
            _finish_job(pid, "failed", error=str(exc), t0=t0)
        finally:
            _track_end(pid)
            if clone_dir:
                import shutil
                shutil.rmtree(clone_dir, ignore_errors=True)

    asyncio.create_task(_run())
    return ok({"pipeline_id": pid, "status": "queued"})


@app.post("/pipeline/app-name", tags=["Full Pipeline"])
async def pipeline_app_name(req: AppNamePipelineRequest):
    """
    Run the **complete** pipeline by resolving an application name → `app_id` → latest `release_id`.

    Returns a *pipeline_id* immediately. Poll **GET /pipeline/status/{pipeline_id}**
    to track progress stage-by-stage.

    Resolution steps:
      1. GET /api/v3/applications?filters=applicationName:<name>  → `applicationId`
      2. GET /api/v3/applications/{applicationId}/releases?limit=1 → `releaseId`
      3. Full pipeline runs against that `releaseId`

    Pass **`repo`** (`"owner/repo"`) to override `GITHUB_REPO` at runtime and trigger
    an automatic clone — mirrors the `--repo` CLI flag so no local `PROJECT_PATH` is needed.

    Equivalent CLI:
        python fortifyai.py --app-name <app_name> --repo <owner/repo>

    Stages: (name→app_id→release_id) → triage → version-resolver → context → api-diff →
            ai-reasoning → adr-fix → build-validation → pr-agent → fortify-writeback
    """
    job = _new_job()
    pid = job["pipeline_id"]

    async def _run():
        t0 = time.time()
        loop = asyncio.get_event_loop()
        clone_dir: str | None = None
        _store.update_job(pid, status="running")
        _track_start(pid)
        try:
            cfg = _apply_overrides(load_config(), req.config)

            # Mirror CLI --repo: clone the repo and update project_path so ADR
            # (and every other stage) operates on the fresh clone, not a stale local path.
            cfg, clone_dir = await loop.run_in_executor(
                _EXECUTOR,
                lambda: _clone_repo_if_needed(cfg, req.repo),
            )

            client, raw_vulns, release_id, app_id = await loop.run_in_executor(
                _EXECUTOR,
                lambda: _resolve_vulnerabilities(
                    cfg, 0, None, req.app_name,
                    persist_token=_should_persist_token(req.config),
                ),
            )
            # Store the RESOLVED release_id (not app_name) so a resume hits
            # the exact same release even if a newer one has since appeared.
            _store.update_job(pid, resume_meta=encrypt_resume_meta({
                "release_id": release_id,
                "report_path": None,
                "app_name": None,
                "app_id": None,
                "repo": req.repo,
                "dry_run": False,
                "max_upgrades": req.max_upgrades,
                "config_overrides": req.config.model_dump(),
            }))
            result = await loop.run_in_executor(
                _EXECUTOR,
                lambda: _run_full_pipeline(cfg, client, raw_vulns, release_id,
                                           max_upgrades=req.max_upgrades,
                                           pipeline_id=pid),
            )
            result["app_id"] = app_id
            result["repo"] = req.repo  # echo back so callers know which repo was used
            _finish_job(pid, "completed", result=result, t0=t0)
        except (PipelineCancelled, PipelineCancelledError):
            _finish_job(pid, "cancelled", error="Cancelled by user", t0=t0)
        except Exception as exc:
            _finish_job(pid, "failed", error=str(exc), t0=t0)
        finally:
            _track_end(pid)
            # Always remove the temp clone — mirrors CLI cleanup behaviour
            if clone_dir:
                import shutil
                shutil.rmtree(clone_dir, ignore_errors=True)

    asyncio.create_task(_run())
    return ok({"pipeline_id": pid, "status": "queued"})


@app.post("/pipeline/app-id", tags=["Full Pipeline"])
async def pipeline_app_id(req: AppIdPipelineRequest):
    """
    Run the **complete** pipeline using a known Fortify `applicationId`.

    Returns a *pipeline_id* immediately. Poll **GET /pipeline/status/{pipeline_id}**
    to track progress stage-by-stage.

    Skips the name-lookup step — one fewer API call vs `/pipeline/app-name`.
    Resolves `app_id → latest release_id` then runs the full pipeline.

    Stages: (release lookup) → triage → version-resolver → context → api-diff →
            ai-reasoning → adr-fix → build-validation → pr-agent → fortify-writeback
    """
    job = _new_job()
    pid = job["pipeline_id"]

    async def _run():
        t0 = time.time()
        loop = asyncio.get_event_loop()
        clone_dir: str | None = None
        _store.update_job(pid, status="running")
        _track_start(pid)
        try:
            cfg = _apply_overrides(load_config(), req.config)
            cfg, clone_dir = await loop.run_in_executor(
                _EXECUTOR,
                lambda: _clone_repo_if_needed(cfg, req.repo),
            )
            client, raw_vulns, release_id, app_id = await loop.run_in_executor(
                _EXECUTOR,
                lambda: _resolve_vulnerabilities(
                    cfg, 0, None, None, req.app_id,
                    persist_token=_should_persist_token(req.config),
                ),
            )
            _store.update_job(pid, resume_meta=encrypt_resume_meta({
                "release_id": release_id,
                "report_path": None,
                "app_name": None,
                "app_id": None,
                "repo": req.repo,
                "dry_run": False,
                "max_upgrades": req.max_upgrades,
                "config_overrides": req.config.model_dump(),
            }))
            result = await loop.run_in_executor(
                _EXECUTOR,
                lambda: _run_full_pipeline(cfg, client, raw_vulns, release_id,
                                           max_upgrades=req.max_upgrades,
                                           pipeline_id=pid),
            )
            result["app_id"] = app_id
            if req.repo:
                result["repo"] = req.repo
            _finish_job(pid, "completed", result=result, t0=t0)
        except (PipelineCancelled, PipelineCancelledError):
            _finish_job(pid, "cancelled", error="Cancelled by user", t0=t0)
        except Exception as exc:
            _finish_job(pid, "failed", error=str(exc), t0=t0)
        finally:
            _track_end(pid)
            if clone_dir:
                import shutil
                shutil.rmtree(clone_dir, ignore_errors=True)

    asyncio.create_task(_run())
    return ok({"pipeline_id": pid, "status": "queued"})


@app.post("/pipeline/dry-run", tags=["Full Pipeline"])
async def pipeline_dry_run(req: DryRunRequest):
    """
    Run the full analysis pipeline **without** side effects.

    Returns a *pipeline_id* immediately. Poll **GET /pipeline/status/{pipeline_id}**
    to track progress stage-by-stage.

    ADR fix (git commit), build validation (mvn build + push), PR creation,
    and Fortify writeback are **skipped**. Everything up to and including
    AI reasoning runs normally. Useful for previewing what the pipeline
    would do.
    """
    job = _new_job()
    pid = job["pipeline_id"]

    async def _run():
        t0 = time.time()
        loop = asyncio.get_event_loop()
        clone_dir: str | None = None
        _store.update_job(pid, status="running")
        _track_start(pid)
        try:
            cfg = _apply_overrides(load_config(), req.config)
            cfg, clone_dir = await loop.run_in_executor(
                _EXECUTOR,
                lambda: _clone_repo_if_needed(cfg, req.repo),
            )
            client, raw_vulns, release_id, app_id = await loop.run_in_executor(
                _EXECUTOR,
                lambda: _resolve_vulnerabilities(
                    cfg, req.release_id, req.report_path, req.app_name,
                    getattr(req, "app_id", None),
                    persist_token=_should_persist_token(req.config),
                ),
            )
            _store.update_job(pid, resume_meta=encrypt_resume_meta({
                "release_id": release_id,
                "report_path": req.report_path,
                "app_name": None,
                "app_id": None,
                "repo": req.repo,
                "dry_run": True,
                "max_upgrades": req.max_upgrades,
                "config_overrides": req.config.model_dump(),
            }))
            result = await loop.run_in_executor(
                _EXECUTOR,
                lambda: _run_full_pipeline(cfg, client, raw_vulns, release_id,
                                           dry_run=True, max_upgrades=req.max_upgrades,
                                           pipeline_id=pid),
            )
            if req.repo:
                result["repo"] = req.repo
            _finish_job(pid, "completed", result=result, t0=t0)
        except (PipelineCancelled, PipelineCancelledError):
            _finish_job(pid, "cancelled", error="Cancelled by user", t0=t0)
        except Exception as exc:
            _finish_job(pid, "failed", error=str(exc), t0=t0)
        finally:
            _track_end(pid)
            if clone_dir:
                import shutil
                shutil.rmtree(clone_dir, ignore_errors=True)

    asyncio.create_task(_run())
    return ok({"pipeline_id": pid, "status": "queued"})


# ═══════════════════════════════════════════════════════════════════════════════
# PIPELINE STATUS ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

def _sanitize_job_for_response(job: dict) -> dict:
    """
    Strip fields from a job doc that should never leave the server, before
    it's returned from a GET endpoint.

    Currently this is just ``resume_meta.config_overrides_secret`` — the
    Fernet-encrypted blob holding any per-request credentials saved for a
    resume (see credential_vault.py). It's not plaintext, so returning it
    wouldn't leak a credential directly, but it's ciphertext with no
    legitimate client-side use (only `_resume_precheck` ever decrypts it,
    server-side, at resume time) and there's no reason to hand a bucket of
    encrypted secrets to every status-poller. The non-secret parts of
    `resume_meta`/`config_overrides` (paths, repo, gcp project, etc.) are
    left as-is — that's useful for callers building a resume/retry UI.
    """
    resume_meta = job.get("resume_meta")
    if not resume_meta or "config_overrides_secret" not in resume_meta:
        return job
    sanitized = dict(job)
    sanitized["resume_meta"] = {k: v for k, v in resume_meta.items() if k != "config_overrides_secret"}
    sanitized["resume_meta"]["has_saved_credentials"] = True
    return sanitized


@app.get("/pipeline/runs", tags=["Pipeline Status"])
def list_pipeline_runs(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    """
    List Fortify pipeline jobs across **all users** — not just the caller's
    own browser session.

    Jobs are persisted server-side (GCS-backed `JobStore`, shared across
    every pod), so this reflects the *global* state of every run currently
    queued/running/completed/failed/cancelled, regardless of who started it
    or which machine/browser they used. This is what powers the shared
    Activity dashboard instead of each user only seeing pipelines they
    personally kicked off from their own browser's local storage.

    Returns newest-first, paginated via `limit` / `offset`. Each entry is
    the same lightweight job doc shape as `GET /pipeline/status/{id}`
    (overall status + per-stage breakdown) but excludes the heavy `result`
    payload and `checkpoint` — fetch `GET /pipeline/status/{pipeline_id}`
    for the full detail on any individual run.
    """
    jobs = [_sanitize_job_for_response(j) for j in _store.list_jobs(limit=limit, offset=offset)]
    return ok({"jobs": jobs, "count": len(jobs)})


@app.get("/pipeline/status/{pipeline_id}", tags=["Pipeline Status"])
def pipeline_status(pipeline_id: str):
    """
    Return the overall status of a pipeline job **and** the per-stage breakdown.

    **Overall status values**
    | Value         | Meaning                                                        |
    |---------------|-----------------------------------------------------------------|
    | `queued`      | Accepted but thread not yet started                            |
    | `running`     | At least one stage is executing                                |
    | `completed`   | All stages finished successfully                                |
    | `failed`      | Pipeline aborted due to an unhandled error                      |
    | `cancelled`   | Stopped via POST /pipeline/cancel/{pipeline_id}                 |
    | `interrupted` | Pod received SIGTERM mid-run (see shutdown_event)               |

    `failed` / `cancelled` / `interrupted` jobs that have at least one
    completed stage carry a `resume_stage` field and can be continued via
    **POST /pipeline/resume/{pipeline_id}** instead of restarting from
    triage — see that endpoint's docstring for requirements.

    **Per-stage status values:** `pending` · `running` · `completed` · `skipped` · `failed`

    Each stage entry includes:
    - `started_at` / `finished_at` — ISO-8601 UTC timestamps
    - `elapsed_seconds` — wall-clock time for that stage
    - `output_summary` — lightweight excerpt (counts, verdicts), not full payload
    - `error` — set only when status is `failed`
    """
    job = _store.get_job(pipeline_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"pipeline_id '{pipeline_id}' not found")
    return ok(_sanitize_job_for_response(job))


@app.get("/pipeline/status/{pipeline_id}/{stage_name}", tags=["Pipeline Status"])
def pipeline_stage_status(pipeline_id: str, stage_name: str):
    """
    Return the status of a **single stage** within a pipeline run.

    Valid `stage_name` values:
    `triage` · `version-resolver` · `context` · `api-diff` ·
    `ai-reasoning` · `adr-fix` · `build-validation` · `pr-agent` · `fortify-writeback`

    Returns the same stage object as the full `/pipeline/status/{pipeline_id}` response
    but scoped to the requested stage only.
    """
    job = _store.get_job(pipeline_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"pipeline_id '{pipeline_id}' not found")
    stage = job["stages"].get(stage_name)
    if stage is None:
        valid = ", ".join(job["stages"].keys())
        raise HTTPException(
            status_code=404,
            detail=f"Stage '{stage_name}' not found in pipeline '{pipeline_id}'. "
                   f"Valid stages: {valid}",
        )
    return ok({"pipeline_id": pipeline_id, "stage": stage_name, **stage})


@app.post("/pipeline/cancel/{pipeline_id}", tags=["Pipeline Status"])
def cancel_pipeline(pipeline_id: str):
    """
    Request cancellation of a running pipeline job.

    This sets a flag that the pipeline runner checks **between stages**
    (see `_check_cancelled` calls in `_run_full_pipeline` / `_run_until`).
    Work already executing inside the current stage's thread-pool call is
    NOT interrupted — cancellation takes effect at the next stage boundary
    (and, for the `adr-fix` / `build-validation` stages, between each
    dependency in the loop),
    which is what stops further side-effects like PR creation or Fortify
    writeback from firing after the user cancels.

    Returns 404 if the pipeline_id is unknown. If the job has already
    reached a terminal state (`completed` / `failed` / `cancelled`), this
    is a no-op that reports the existing status.
    """
    job = _store.get_job(pipeline_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"pipeline_id '{pipeline_id}' not found")

    if job.get("status") in ("completed", "failed", "cancelled"):
        return ok({
            "pipeline_id": pipeline_id,
            "message": f"Job already in terminal state '{job['status']}' — nothing to cancel",
            "status": job["status"],
        })

    _store.request_cancel(pipeline_id)
    return ok({
        "pipeline_id": pipeline_id,
        "message": "Cancellation requested — the run will stop at the next stage boundary",
        "status": "cancelling",
    })


# ═══════════════════════════════════════════════════════════════════════════════
# TOKEN USAGE ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/tokens/usage", tags=["Tokens"])
def tokens_usage_all():
    """
    Return LLM token consumption totals **since this process started**.

    Response shape:
    ```
    {
      "global": { calls, input_tokens, output_tokens, total_tokens,
                  models: {model: total}, stages: {stage: {...}} },
      "runs":   { "<pipeline_id>": { calls, input_tokens,
                                     output_tokens, total_tokens } }
    }
    ```

    Notes:
    - Counters are **in-memory and per-pod**. For a durable per-run record,
      read `result.token_usage` from `GET /pipeline/status/{pipeline_id}`
      after the run completes (persisted via the job store).
    - CLI runs (`fortifyai.py`) and stage-level `/stages/*` calls are counted
      in the global bucket even without a pipeline_id.
    """
    return ok(token_tracker.all_runs())


@app.get("/tokens/usage/{pipeline_id}", tags=["Tokens"])
def tokens_usage_run(pipeline_id: str):
    """
    Return **live** per-stage LLM token consumption for one pipeline run.

    Useful for polling while a run is in progress — unlike
    `/pipeline/status/{id}`, which only includes `token_usage` in the final
    result after completion. Returns zeros (not 404) for unknown or
    not-yet-started pipeline ids, and for runs executed on another pod.
    """
    return ok(token_tracker.summary(pipeline_id))


@app.delete("/pipeline/runs/{pipeline_id}", tags=["Pipeline Status"])
def delete_pipeline_run(pipeline_id: str):
    """
    Permanently remove a pipeline run (doc + result + checkpoint) from the
    job store.

    Idempotent by design: deleting a run that's already gone returns `200`
    with `deleted: false` rather than `404`. This matters in practice —
    the UI can legitimately fire more than one DELETE for the same run
    (multiple open tabs each clearing their own view of a shared Activity
    list, a click handler re-firing, etc.), and the *second* call arriving
    after the first one already succeeded is not an error condition; the
    end state the caller wanted ("this run is gone") is already true.

    If the run is still queued/running, cancellation is requested first
    (best-effort, same as `POST /pipeline/cancel/{id}`) before the record
    is removed — the in-flight background task will simply no-op the next
    time it tries to write status for a doc that's no longer there.
    """
    job = _store.get_job(pipeline_id)
    if job is not None and job.get("status") in ("queued", "running"):
        _store.request_cancel(pipeline_id)

    deleted = _store.delete_job(pipeline_id)
    return ok({
        "pipeline_id": pipeline_id,
        "deleted": deleted,
        "message": (
            f"Run '{pipeline_id}' deleted"
            if deleted else
            f"Run '{pipeline_id}' was already gone — nothing to delete"
        ),
    })


# Resume is only supported for interruptions at or before this stage.
# ai-reasoning is the last stage with no side effects — every stage after it
# (adr-fix: git commit, build-validation: mvn build + push/rollback,
# pr-agent: opens a PR) writes to the outside world. adr-fix in particular has no idempotence guard for a *partial*
# rerun the way pr-agent does (_find_existing_pr, keyed by branch name):
# adr-fix mints a brand-new random branch name on every call and resume
# re-clones the default branch (not whatever feature branch a prior
# attempt may have already pushed), so re-entering it after an interruption
# can silently redo already-fixed dependency groups on a duplicate branch.
# Disabling resume once adr-fix is next sidesteps that entirely — anything
# that got that far starts over as a fresh run instead.
# resume_stage is the NEXT stage a resume would start at (see
# job_store._blank_job), so rejecting once it's past ai-reasoning in
# ALL_STAGE_NAMES order means: ai-reasoning itself was interrupted or never
# started → still resumable; ai-reasoning already completed and
# checkpointed (next stage is adr-fix or later) → not resumable.
_RESUME_MAX_STAGE = "ai-reasoning"


def _resume_precheck(pipeline_id: str) -> tuple[dict, dict, dict] | tuple[None, None, None]:
    """
    Shared validation for manual (HTTP) and automatic resume. Returns
    ``(job, resume_meta, checkpoint)`` — with ``resume_meta`` already
    decrypted (see credential_vault.decrypt_resume_meta) — or raises
    HTTPException. Does NOT check job status; callers decide what
    statuses are eligible (manual resume disallows 'running'/'completed';
    auto-resume is choosier still — see `_auto_resumable`).
    """
    job = _store.get_job(pipeline_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"pipeline_id '{pipeline_id}' not found")

    resume_meta = job.get("resume_meta")
    if not resume_meta:
        raise HTTPException(
            status_code=400,
            detail=(
                "This job has no resume metadata — it was created before "
                "resume support existed, or via an individual stage / "
                "partial-pipeline endpoint that doesn't capture it. "
                "Start a new pipeline run instead."
            ),
        )
    resume_meta = decrypt_resume_meta(resume_meta)

    checkpoint = _store.get_checkpoint(pipeline_id)
    if not checkpoint:
        raise HTTPException(
            status_code=400,
            detail="No checkpoint found for this job — no stage completed "
                   "yet, so there is nothing to resume from. Start a new "
                   "pipeline run instead.",
        )

    resume_stage = checkpoint.get("resume_stage")
    if resume_stage and resume_stage in ALL_STAGE_NAMES and (
        ALL_STAGE_NAMES.index(resume_stage) > ALL_STAGE_NAMES.index(_RESUME_MAX_STAGE)
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Resume is only supported up to the AI Reasoning stage — "
                f"this job already completed it and progressed to "
                f"'{resume_stage}'. Start a new pipeline run instead."
            ),
        )

    return job, resume_meta, checkpoint


def _start_resume(pipeline_id: str, resume_meta: dict, checkpoint: dict, *, auto: bool = False) -> None:
    """
    Kick off the resume's background run and flip the job to 'running'.
    Shared by the manual `POST /pipeline/resume/{pipeline_id}` endpoint
    and automatic resume (orphan sweep / startup scan — see
    `_try_auto_resume`). Fires the run as an asyncio task and returns
    immediately; caller is responsible for any pre-conditions (status
    checks, attempt limits).
    """
    pid = pipeline_id
    t0 = time.time()
    _store.update_job(
        pid, status="running", cancel_requested=False, error=None,
        resumed_by=("auto" if auto else "manual"),
    )

    async def _run():
        loop = asyncio.get_event_loop()
        clone_dir: str | None = None
        _track_start(pid)
        try:
            # config_overrides was decrypted by _resume_precheck — any
            # per-request Fortify/GitHub/Sonar credentials saved at job
            # creation (see credential_vault.encrypt_resume_meta) are back
            # in plaintext here, in-memory only, for the duration of this run.
            resume_overrides = ConfigOverrides(**resume_meta.get("config_overrides") or {})
            cfg = _apply_overrides(load_config(), resume_overrides)
            cfg, clone_dir = await loop.run_in_executor(
                _EXECUTOR,
                lambda: _clone_repo_if_needed(cfg, resume_meta.get("repo")),
            )
            # Re-fetch vulnerabilities/client for API completeness even though
            # the triage stage that consumes them will be skipped (it's
            # already in the checkpoint) — keeps this code path identical to
            # a fresh run rather than special-casing which stages need what.
            client, raw_vulns, release_id, _app_id = await loop.run_in_executor(
                _EXECUTOR,
                lambda: _resolve_vulnerabilities(
                    cfg, resume_meta.get("release_id", 0),
                    resume_meta.get("report_path"), resume_meta.get("app_name"),
                    resume_meta.get("app_id"),
                    persist_token=_should_persist_token(resume_overrides),
                ),
            )
            result = await loop.run_in_executor(
                _EXECUTOR,
                lambda: _run_full_pipeline(
                    cfg, client, raw_vulns, release_id,
                    dry_run=resume_meta.get("dry_run", False),
                    max_upgrades=resume_meta.get("max_upgrades", 0),
                    pipeline_id=pid,
                    resume_checkpoint=checkpoint,
                ),
            )
            if resume_meta.get("repo"):
                result["repo"] = resume_meta["repo"]
            _finish_job(pid, "completed", result=result, t0=t0)
        except (PipelineCancelled, PipelineCancelledError):
            _finish_job(pid, "cancelled", error="Cancelled by user", t0=t0)
        except Exception as exc:
            _finish_job(pid, "failed", error=str(exc), t0=t0)
        finally:
            _track_end(pid)
            if clone_dir:
                import shutil
                shutil.rmtree(clone_dir, ignore_errors=True)

    asyncio.create_task(_run())


def _auto_resume_eligible(job: dict) -> bool:
    """Cheap, no-I/O check on a job doc — do the fields alone allow auto-resume?"""
    if not _AUTO_RESUME_ENABLED:
        return False
    if job.get("status") not in _AUTO_RESUME_STATUSES:
        return False
    if not job.get("resume_meta"):
        return False
    if int(job.get("auto_resume_attempts") or 0) >= _AUTO_RESUME_MAX_ATTEMPTS:
        return False
    return True


def _try_auto_resume(pipeline_id: str) -> bool:
    """
    Attempt to automatically resume *pipeline_id* from its last checkpoint
    instead of leaving it stuck until a human notices and calls
    POST /pipeline/resume/{pipeline_id}.

    Only ever called for jobs still at status 'interrupted' — see
    AUTO_RESUME_STATUSES — i.e. ones left mid-run by a *previous* pod's
    graceful-shutdown handler (SIGTERM: eviction, rolling deploy,
    scale-down), where nothing actually went wrong with the run itself.
    Called from `startup_event`'s one-shot scan at every pod boot.

    Deliberately NOT called for 'failed' jobs (whether from a raised
    exception or the orphan sweep timing out a stuck 'running' job) —
    those need a human to look before retrying. See the AUTO_RESUME_
    STATUSES comment above for why.

    Bounded by AUTO_RESUME_MAX_ATTEMPTS so a job that keeps getting
    interrupted (e.g. every pod that picks it up gets evicted again before
    finishing) doesn't retry forever; once exhausted it stays 'interrupted'
    and only a manual POST /pipeline/resume/{pipeline_id} will retry it.

    Returns True if a resume was actually kicked off.
    """
    job = _store.get_job(pipeline_id)
    if job is None or not _auto_resume_eligible(job):
        return False
    try:
        _job, resume_meta, checkpoint = _resume_precheck(pipeline_id)
    except HTTPException as exc:
        print(f"[AutoResume] {pipeline_id} not resumable: {exc.detail}")
        return False
    except Exception as exc:
        print(f"[AutoResume] precheck failed for {pipeline_id}: {exc}")
        return False

    attempts = int(job.get("auto_resume_attempts") or 0) + 1
    _store.update_job(pipeline_id, auto_resume_attempts=attempts)
    print(f"[AutoResume] Resuming {pipeline_id} from stage "
          f"'{checkpoint.get('resume_stage')}' "
          f"(attempt {attempts}/{_AUTO_RESUME_MAX_ATTEMPTS})")
    _start_resume(pipeline_id, resume_meta, checkpoint, auto=True)
    return True


def _auto_resume_startup_scan(limit: int = 200) -> list[str]:
    """
    One-time scan run at pod boot for jobs left 'interrupted' by a
    *previous* pod's graceful SIGTERM shutdown (see `shutdown_event`) —
    work that was cut off mid-run through no fault of the run itself, not
    a job that actually failed. Bounded by AUTO_RESUME_MAX_ATTEMPTS the
    same as any other auto-resume — see `_try_auto_resume`.

    Only scans the most recent *limit* jobs (list_jobs is newest-first);
    older stuck jobs remain reachable via a manual
    POST /pipeline/resume/{pipeline_id}. Returns the pipeline_ids resumed.
    """
    resumed: list[str] = []
    if not _AUTO_RESUME_ENABLED:
        return resumed
    try:
        jobs = _store.list_jobs(limit=limit, offset=0)
    except Exception as exc:
        print(f"[AutoResume] Startup scan: list_jobs failed: {exc}")
        return resumed
    for job in jobs:
        pid = job.get("pipeline_id")
        if not pid or not _auto_resume_eligible(job):
            continue
        if _try_auto_resume(pid):
            resumed.append(pid)
    return resumed


@app.post("/pipeline/resume/{pipeline_id}", tags=["Pipeline Status"])
async def resume_pipeline(pipeline_id: str):
    """
    Resume an interrupted, failed, or cancelled pipeline run from its last
    checkpointed stage instead of restarting from triage.

    Requires:
      - the job to exist and NOT currently be 'running' or 'completed'
      - `resume_meta` captured at job creation (only full-pipeline runs —
        /pipeline/live, /offline, /app-name, /app-id, /dry-run — capture
        this; individual /stages/* calls and partial /pipeline/until/*
        runs do not)
      - a checkpoint (at least one stage must have completed)
      - the checkpoint's next stage (`resume_stage`) to be at or before
        ai-reasoning ("AI Reasoning") — see `_RESUME_MAX_STAGE`. If
        ai-reasoning already completed (resume_stage is 'adr-fix',
        'build-validation', 'pr-agent', or 'fortify-writeback'), this
        returns 400: resume isn't offered once the pipeline has reached a
        side-effecting stage (adr-fix commits; build-validation builds +
        pushes/rolls back; pr-agent opens a PR). Whichever stage the
        job was actually interrupted at — including ai-reasoning itself, if
        cancellation landed mid-stage — is re-run in full, not skipped;
        only stages that fully completed before the interruption are
        served from the checkpoint.

    Any per-request credentials saved with the original run (Fortify
    password, GitHub PAT, Sonar token — stored encrypted, see
    credential_vault.py) are transparently decrypted and reused here.

    Side-effecting stages already checkpointed (adr-fix, build-validation,
    pr-agent) are reused as-is and NOT re-run — see `_run_full_pipeline`'s
    `resume_checkpoint` handling and `pr_agent._find_existing_pr` for the
    duplicate-PR guard.

    Note: jobs left 'interrupted' by a pod restart usually resume on their
    own — see AUTO_RESUME_ENABLED — so this call is mainly needed for
    'failed' jobs (auto-resume deliberately skips these; see the
    AUTO_RESUME_STATUSES comment near the top of this file for why),
    'cancelled' jobs, or an interrupted job whose auto-resume attempts
    were exhausted or that arrived while AUTO_RESUME_ENABLED was off.

    Returns a *pipeline_id* (the SAME one — resume continues the existing
    job record rather than minting a new one) immediately; poll
    **GET /pipeline/status/{pipeline_id}** as usual.
    """
    job, resume_meta, checkpoint = _resume_precheck(pipeline_id)

    if job.get("status") in ("running", "completed"):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot resume a job with status '{job['status']}'",
        )

    _start_resume(pipeline_id, resume_meta, checkpoint, auto=False)
    return ok({
        "pipeline_id": pipeline_id,
        "status": "queued",
        "resuming_from_stage": checkpoint.get("resume_stage"),
    })


@app.post("/pipeline/sweep", tags=["Pipeline Status"])
def trigger_orphan_sweep(timeout_seconds: Optional[float] = Query(default=None)):
    """
    Manually trigger the orphan-job sweep (also runs automatically every
    ORPHAN_SWEEP_INTERVAL_SECONDS on every pod — see startup_event).

    Flips any job stuck at status='running' with no stage progress for
    longer than `timeout_seconds` (default ORPHAN_SWEEP_TIMEOUT_SECONDS) to
    'failed'. Safe to call from an external scheduler (e.g. a k8s CronJob)
    as a belt-and-braces backstop alongside the built-in background loop.
    Checkpoints are preserved, so swept jobs remain resumable.
    """
    swept = _run_orphan_sweep(timeout_seconds)
    return ok({"swept_pipeline_ids": swept, "count": len(swept)})


# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/stages/triage", tags=["Individual Stages"])
def stage_triage(req: TriageRequest):
    """
    **Stage 1 — Triage**

    Filter and group raw Fortify vulnerability items by dependency.
    Suppressed, closed, and non-OSS findings are dropped.

    Input:  raw_vulnerabilities[]  (direct from Fortify /vulnerabilities API)
    Output: grouped dependency objects ready for version resolution
    """
    t0 = time.time()
    try:
        from agents.triage import group_by_dependency, apply_max_upgrades
        groups, skipped = group_by_dependency(req.raw_vulnerabilities)
        groups = apply_max_upgrades(groups, req.max_upgrades)
        return ok({
            "groups": groups, "count": len(groups),
            "total_groups": len(groups), "total_skipped": skipped,
        }, time.time() - t0)
    except Exception as exc:
        return err(str(exc), exc)


@app.post("/stages/version-resolver", tags=["Individual Stages"])
def stage_version_resolver(req: VersionResolverRequest):
    """
    **Stage 2 — Version Resolver**

    For each dependency group, resolve the next-safe and greatest-safe
    upgrade candidates from Fortify recommendations + Maven Central.

    Input:  groups[]       (from /stages/triage)
    Output: groups enriched with version_candidates
    """
    t0 = time.time()
    try:
        cfg = _apply_overrides(load_config(), req.config)
        from fortify_client import FortifyClient
        from agents.version_resolver import resolve_all_groups
        client = FortifyClient.from_config(cfg, persist_token=_should_persist_token(req.config))
        resolved = resolve_all_groups(client, req.release_id, req.groups)
        return ok({"groups": resolved}, time.time() - t0)
    except Exception as exc:
        return err(str(exc), exc)


@app.post("/stages/context", tags=["Individual Stages"])
def stage_context(req: ContextRequest):
    """
    **Stage 3 — Context Gathering**

    Locate each dependency in the codebase: find pom.xml declarations
    (direct or transitive) and all Java files that call the library.

    Input:  groups[]       (from /stages/version-resolver)
            project_path   (absolute path to Maven project root)
    Output: groups enriched with pom_location and calling_files
    """
    t0 = time.time()
    try:
        from agents.context import locate_all_groups
        groups = locate_all_groups(Path(req.project_path), req.groups)
        return ok({"groups": groups}, time.time() - t0)
    except Exception as exc:
        return err(str(exc), exc)


@app.post("/stages/api-diff", tags=["Individual Stages"])
def stage_api_diff(req: ApiDiffRequest):
    """
    **Stage 4 — API Diff**

    Download old + new JARs from Maven Central, run japicmp, and map
    breaking changes to calling file line numbers using Java AST analysis.

    Input:  groups[]           (from /stages/context)
            project_path       (absolute path to Maven project root)
            japicmp_jar_path   (absolute path to japicmp fat-jar)
    Output: groups enriched with api_diff (breaking change analysis)
    """
    t0 = time.time()
    try:
        from agents.api_diff import run_api_diff_all_groups
        groups = run_api_diff_all_groups(
            req.groups, Path(req.project_path), req.japicmp_jar_path
        )
        return ok({"groups": groups}, time.time() - t0)
    except Exception as exc:
        return err(str(exc), exc)


@app.post("/stages/ai-reasoning", tags=["Individual Stages"])
def stage_ai_reasoning(req: AiReasoningRequest):
    """
    **Stage 5 — AI Reasoning**

    Send calling code, API diff, and changelog to Claude/Gemini via Vertex AI.
    Returns a safety verdict (safe/unsafe), confidence level, and
    at-risk code lines. Routes each group to adr-fix or escalate.

    Input:  groups[]       (from /stages/api-diff)
            gcp_project    (GCP project ID)
            gcp_location   (Vertex AI region, default us-central1)
    Output: groups enriched with ai_reasoning verdict
    """
    t0 = time.time()
    try:
        from agents.ai_reasoning import reason_all_groups
        groups = reason_all_groups(req.groups, req.gcp_project, req.gcp_location)
        return ok({"groups": groups}, time.time() - t0)
    except Exception as exc:
        return err(str(exc), exc)


@app.post("/stages/adr-fix", tags=["Individual Stages"])
def stage_adr_fix(req: AdrFixRequest):
    """
    **Stage 6 — ADR Fix (commit only)**

    Invoke `adr.py --commit JIRA_ID --skip-build` for each actionable group.
    Applies the pom.xml version edit and creates a local git commit on a
    fresh feature branch — does NOT run the Maven build and does NOT push.
    Parses exit code, branch name, base branch, commit hash, and PDF path
    from stdout. Feed the output to **POST /stages/build-validation** next —
    that stage owns the actual build, and pushes (or rolls back) the branch.

    Input:  groups[]       (from /stages/ai-reasoning)
            adr_path       (absolute path to adr.py)
            project_path   (absolute path to Maven project root)
            jira_prefix    (e.g. "FORTIFY")
    Output: adr_results[] with success/failure per dependency (success here
            means "committed", not "build passed")
    """
    t0 = time.time()
    try:
        from agents.adr_fix import run_adr_fix
        from state import AdrResult

        results = []
        for group in req.groups:
            artifact_id = group["parsed"]["artifact_id"]
            if group.get("next_node") == "escalate":
                results.append({
                    "artifact_id": artifact_id,
                    "result": AdrResult(
                        success=False, branch_name=None, base_branch=None,
                        commit_hash=None, build_time_seconds=None, pdf_path=None,
                        error_reason=_escalation_reason(group),
                    ),
                })
                continue
            result = run_adr_fix(
                group, adr_path=req.adr_path,
                project_path=req.project_path,
                jira_prefix=req.jira_prefix,
                release_id=req.release_id,
            )
            results.append({"artifact_id": artifact_id, "result": result})

        return ok({"adr_results": results}, time.time() - t0)
    except Exception as exc:
        return err(str(exc), exc)


@app.post("/stages/build-validation", tags=["Individual Stages"])
def stage_build_validation(req: BuildValidationRequest):
    """
    **Stage 6b — Build Validation**

    Runs immediately after /stages/adr-fix. For each committed group: checks
    out its branch, pushes it, dispatches a GitHub Actions build
    (workflow_file, must declare `on: workflow_dispatch`) and waits for it,
    then leaves the branch pushed on success or rolls it back (checkout
    base_branch + delete branch, locally and on origin) on failure.
    Groups where the adr-fix result was already unsuccessful (escalated,
    dry-run, commit failure, no-op) are passed through unchanged — nothing
    to build.

    Input:  adr_results[]     (from /stages/adr-fix)
            project_path      (absolute path to Maven project root)
            github_token/repo (optional — falls back to cfg.github_token/github_repo)
            workflow_file     (optional — defaults to cfg.build_workflow_file)
    Output: adr_results[] — SAME shape as /stages/adr-fix, with success/branch_name/
            build_time_seconds/error_reason updated to reflect the build+push
            outcome. Pass this (not the raw /stages/adr-fix output) to
            /stages/pr-agent.
    """
    t0 = time.time()
    try:
        from agents.build_validation import validate_one

        cfg = load_config()

        results = []
        for entry in req.adr_results:
            artifact_id = entry["artifact_id"]
            adr_result = entry["result"]

            if not adr_result.get("success"):
                # Nothing was committed for this group — pass the failure through.
                results.append({"artifact_id": artifact_id, "result": {
                    **adr_result,
                    "build_time_seconds": None,
                }})
                continue

            bv_result = validate_one(
                artifact_id, adr_result, req.project_path,
                github_token=req.github_token or cfg.github_token,
                github_repo=req.github_repo or cfg.github_repo,
                workflow_file=req.workflow_file or cfg.build_workflow_file,
                workflow_inputs=req.workflow_inputs,
            )
            # Merge into the AdrResult shape so downstream /stages/pr-agent and
            # /stages/fortify-writeback (which expect adr_results[]) need no changes.
            results.append({"artifact_id": artifact_id, "result": {
                **adr_result,
                "success": bv_result["success"],
                "branch_name": bv_result["branch_name"],
                "build_time_seconds": bv_result["build_time_seconds"],
                "error_reason": bv_result["error_reason"] or adr_result.get("error_reason"),
            }})

        return ok({"adr_results": results}, time.time() - t0)
    except Exception as exc:
        return err(str(exc), exc)


@app.post("/stages/ai-code-fix", tags=["Individual Stages"])
def stage_ai_code_fix(req: AiCodeFixRequest):
    """
    **Stage 7 — AI Code Fix**

    When the build fails after an upgrade, send the Maven error and at-risk
    calling code to the LLM for an auto-generated patch. Applied before
    re-running ADR fix (retry loop).

    Input:  groups[]       (groups flagged as needing pre-fix)
            project_path   (absolute path to Maven project root)
            gcp_project
            gcp_location
    Output: groups with ai_code_fix_applied=True and patched source files
    """
    t0 = time.time()
    try:
        from agents.ai_code_fix import ai_code_fix_node
        from state import AgentState

        results = []
        for group in req.groups:
            state = AgentState(
                release_id=0, vuln_id=None, cve_list=[],
                dependency=group.get("parsed"),
                severity=None, owasp_2021=None, sonatype_explanation=None,
                primary_location=None, is_suppressed=False, auditor_status=None,
                closed_status=False, version_candidates=group.get("version_candidates"),
                current_candidate=group.get("current_candidate"),
                candidate_index=group.get("candidate_index", 0),
                pom_location=group.get("pom_location"),
                calling_files=group.get("calling_files", []),
                calling_code_snippet=group.get("calling_code_snippet"),
                api_diff=group.get("api_diff"),
                ai_reasoning=group.get("ai_reasoning"),
                adr_result=None, retry_count=0,
                last_build_error=group.get("last_build_error"),
                ai_code_fix_applied=False,
                pr_result=None, status="running",
                skip_reason=None, escalation_reason=None, audit_trail=[],
                _project_path=req.project_path,
                _gcp_project=req.gcp_project,
                _gcp_location=req.gcp_location,
            )
            updated_state = ai_code_fix_node(
                state, req.project_path, req.gcp_project, req.gcp_location
            )
            results.append({
                "artifact_id": group.get("parsed", {}).get("artifact_id"),
                "ai_code_fix_applied": updated_state.get("ai_code_fix_applied"),
                "status": updated_state.get("status"),
            })

        return ok({"results": results}, time.time() - t0)
    except Exception as exc:
        return err(str(exc), exc)


@app.post("/stages/pr-agent", tags=["Individual Stages"])
def stage_pr_agent(req: PrAgentRequest):
    """
    **Stage 8 — PR Agent**

    Create GitHub pull requests for all successfully fixed dependencies.
    Sets title, body, labels, reviewers, and attaches the ADR PDF report.

    Input:  groups[]       (from /stages/ai-reasoning)
            adr_results[]  (from /stages/build-validation — NOT raw /stages/adr-fix
                            output, which doesn't yet reflect whether the build passed)
            release_id
            github_token
            github_repo
            reviewers[]
    Output: pr_results[] with pr_url and pr_number per dependency
    """
    t0 = time.time()
    try:
        from agents.pr_agent import create_prs_for_all_groups
        pr_results = create_prs_for_all_groups(
            groups=req.groups,
            adr_results=req.adr_results,
            release_id=req.release_id,
            github_token=req.github_token,
            github_repo=req.github_repo,
            reviewers=req.reviewers,
        )
        return ok({"pr_results": pr_results}, time.time() - t0)
    except Exception as exc:
        return err(str(exc), exc)


@app.post("/stages/fortify-writeback", tags=["Individual Stages"])
def stage_fortify_writeback(req: FortifyWritebackRequest):
    """
    **Stage 9 — Fortify Writeback**

    Post the fix outcome (branch, PR URL, version bumped) as a comment
    back to each Fortify finding. Also generates escalation reports for
    findings that could not be auto-remediated.

    Input:  groups[]       (from /stages/ai-reasoning)
            adr_results[]  (from /stages/build-validation, or /stages/adr-fix merged with it)
            pr_results[]   (from /stages/pr-agent)
            output_dir     (directory for PDF reports and logs)
    Output: summary with total_fixed / total_escalated / total_failed
    """
    t0 = time.time()
    try:
        from agents.fortify_writeback import run_all_reports
        summary = run_all_reports(
            groups=req.groups,
            adr_results=req.adr_results,
            pr_results=req.pr_results,
            output_dir=req.output_dir,
        )
        return ok({"summary": summary}, time.time() - t0)
    except Exception as exc:
        return err(str(exc), exc)


# ═══════════════════════════════════════════════════════════════════════════════
# PARTIAL PIPELINE ENDPOINTS  (stop at a given stage)
# ═══════════════════════════════════════════════════════════════════════════════

StageLabel = Literal[
    "triage", "version-resolver", "context",
    "api-diff", "ai-reasoning", "adr-fix", "build-validation", "pr-agent",
]

STAGE_ORDER: list[StageLabel] = [
    "triage", "version-resolver", "context",
    "api-diff", "ai-reasoning", "adr-fix", "build-validation", "pr-agent",
]


def _run_until(
    cfg: FortifyAIConfig,
    client,
    raw_vulns: list[dict],
    release_id: int,
    stop_after: StageLabel,
    pipeline_id: str | None = None,
    max_upgrades: int = 0,
) -> dict:
    """Run the pipeline and stop (inclusive) at `stop_after`, updating the job store per stage."""
    if pipeline_id:
        token_tracker.start_run(pipeline_id)   # bind LLM token accounting to this run

    from pathlib import Path
    from agents.triage import group_by_dependency, apply_max_upgrades
    from agents.version_resolver import resolve_all_groups
    from agents.context import locate_all_groups
    from agents.api_diff import run_api_diff_all_groups
    from agents.ai_reasoning import reason_all_groups
    from agents.adr_fix import run_adr_fix
    from agents.build_validation import validate_one
    from agents.pr_agent import create_prs_for_all_groups
    from state import AdrResult

    def _s_start(name: str) -> float:
        t = time.time()
        if pipeline_id:
            _update_stage(pipeline_id, name, status="running", started_at=_now(),
                          finished_at=None, elapsed_seconds=None,
                          error=None, output_summary=None)
        return t

    def _s_done(name: str, t: float, summary: dict | None = None) -> None:
        if pipeline_id:
            _update_stage(pipeline_id, name,
                          status="completed",
                          finished_at=_now(),
                          elapsed_seconds=round(time.time() - t, 3),
                          output_summary=summary)

    def _s_skip(name: str) -> None:
        if pipeline_id:
            _update_stage(pipeline_id, name, status="skipped")

    def _s_fail(name: str, t: float, error: str) -> None:
        if pipeline_id:
            _update_stage(pipeline_id, name,
                          status="failed",
                          finished_at=_now(),
                          elapsed_seconds=round(time.time() - t, 3),
                          error=error)

    idx = STAGE_ORDER.index(stop_after)
    project_path = Path(cfg.project_path) if cfg.project_path else Path(".")

    result: dict = {"release_id": release_id, "stopped_after": stop_after}

    # Stage 0 — triage
    _check_cancelled(pipeline_id)
    t = _s_start("triage")
    groups, triage_skipped = group_by_dependency(raw_vulns)
    groups = apply_max_upgrades(groups, max_upgrades or cfg.max_upgrades)
    result["groups"] = groups
    result["groups_count"] = len(groups)
    _s_done("triage", t, {
        "total_groups": len(groups), "groups_count": len(groups),
        "total_skipped": triage_skipped,
    })
    if idx == 0 or not groups:
        for s in STAGE_ORDER[1:]:
            _s_skip(s)
        return result

    # Stage 1 — version resolver
    _check_cancelled(pipeline_id)
    t = _s_start("version-resolver")
    resolved = resolve_all_groups(client, release_id, groups)
    result["groups"] = resolved
    _s_done("version-resolver", t, {"groups_count": len(resolved)})
    if idx == 1:
        for s in STAGE_ORDER[2:]:
            _s_skip(s)
        return result

    # Stage 2 — context
    _check_cancelled(pipeline_id)
    t = _s_start("context")
    context_groups = locate_all_groups(project_path, resolved)
    result["groups"] = context_groups
    _s_done("context", t, {"groups_count": len(context_groups)})
    if idx == 2:
        for s in STAGE_ORDER[3:]:
            _s_skip(s)
        return result

    # Stage 3 — api diff
    _check_cancelled(pipeline_id)
    t = _s_start("api-diff")
    try:
        diff_groups = run_api_diff_all_groups(
            context_groups, project_path,
            cfg.japicmp_jar_path or "/nonexistent/japicmp.jar",
        )
    except Exception as exc:
        _s_fail("api-diff", t, str(exc))
        raise
    result["groups"] = diff_groups
    _s_done("api-diff", t, {"groups_count": len(diff_groups)})
    if idx == 3:
        for s in STAGE_ORDER[4:]:
            _s_skip(s)
        return result

    # Stage 4 — ai reasoning
    cancel_check = _cancel_check_for(pipeline_id)

    _check_cancelled(pipeline_id)
    t = _s_start("ai-reasoning")
    try:
        reasoned = reason_all_groups(
            diff_groups, cfg.gcp_project, cfg.gcp_location, cancel_check=cancel_check,
        )
    except PipelineCancelledError:
        _s_fail("ai-reasoning", t, "Cancelled by user")
        raise
    except Exception as exc:
        _s_fail("ai-reasoning", t, str(exc))
        raise
    result["groups"] = reasoned
    _s_done("ai-reasoning", t, {
        "safe": sum(1 for g in reasoned if g.get("next_node") != "escalate"),
        "escalated": sum(1 for g in reasoned if g.get("next_node") == "escalate"),
    })
    if idx == 4:
        for s in STAGE_ORDER[5:]:
            _s_skip(s)
        return result

    # Stage 5 — adr fix (commit only — no build, no push; see build-validation below)
    _check_cancelled(pipeline_id)
    t = _s_start("adr-fix")
    adr_results: list[dict] = []
    try:
        for group in reasoned:
            _check_cancelled(pipeline_id)  # stop before committing the next group
            artifact_id = group["parsed"]["artifact_id"]
            if group.get("next_node") == "escalate" or not cfg.adr_path:
                adr_results.append({
                    "artifact_id": artifact_id,
                    "result": AdrResult(
                        success=False, branch_name=None, base_branch=None,
                        commit_hash=None, build_time_seconds=None, pdf_path=None,
                        error_reason="Escalated or ADR_PATH not set",
                    ),
                })
            else:
                adr_results.append({
                    "artifact_id": artifact_id,
                    "result": run_adr_fix(
                        group, adr_path=cfg.adr_path,
                        project_path=str(project_path),
                        jira_prefix=cfg.jira_id_prefix,
                        release_id=release_id,
                        cancel_check=cancel_check,
                    ),
                })
    except PipelineCancelledError:
        _s_fail("adr-fix", t, "Cancelled by user")
        raise
    _adr_ok = sum(1 for r in adr_results if r.get("result", {}).get("success"))
    result["adr_results"] = adr_results
    _s_done("adr-fix", t, {"committed": _adr_ok, "total": len(adr_results)})
    if idx == 5:
        for s in STAGE_ORDER[6:]:
            _s_skip(s)
        return result

    # Stage 5b — build validation (runs mvn, then pushes on success or rolls
    # the branch back on failure)
    _check_cancelled(pipeline_id)
    t = _s_start("build-validation")
    merged_results: list[dict] = []
    try:
        for entry in adr_results:
            _check_cancelled(pipeline_id)  # stop before pushing the next branch
            artifact_id = entry["artifact_id"]
            adr_result = entry["result"]
            if not adr_result.get("success"):
                merged_results.append({"artifact_id": artifact_id, "result": {
                    **adr_result, "build_time_seconds": None,
                }})
                continue
            bv_result = validate_one(
                artifact_id, adr_result, str(project_path),
                github_token=cfg.github_token, github_repo=cfg.github_repo,
                workflow_file=cfg.build_workflow_file, cancel_check=cancel_check,
            )
            merged_results.append({"artifact_id": artifact_id, "result": {
                **adr_result,
                "success": bv_result["success"],
                "branch_name": bv_result["branch_name"],
                "build_time_seconds": bv_result["build_time_seconds"],
                "error_reason": bv_result["error_reason"] or adr_result.get("error_reason"),
            }})
    except PipelineCancelledError:
        _s_fail("build-validation", t, "Cancelled by user")
        raise
    adr_results = merged_results
    _bv_ok = sum(1 for r in adr_results if r.get("result", {}).get("success"))
    result["adr_results"] = adr_results
    _s_done("build-validation", t, {"pushed": _bv_ok, "total": len(adr_results)})
    if idx == 6:
        _s_skip("pr-agent")
        return result

    # Stage 6 — pr agent
    _check_cancelled(pipeline_id)  # stop before opening PRs
    t = _s_start("pr-agent")
    pr_results = []
    if cfg.github_token and cfg.github_repo:
        pr_results = create_prs_for_all_groups(
            groups=reasoned, adr_results=adr_results,
            release_id=release_id,
            github_token=cfg.github_token,
            github_repo=cfg.github_repo,
            reviewers=cfg.get_reviewers(),
        )
    result["pr_results"] = pr_results
    _s_done("pr-agent", t, {"prs_created": len(pr_results)})
    return result


def _make_partial_endpoint(stop_after: StageLabel):
    """Factory that returns an async FastAPI route handler for each partial pipeline."""
    stop_idx = STAGE_ORDER.index(stop_after)
    active_stages = STAGE_ORDER[: stop_idx + 1]

    async def handler(req: PartialPipelineRequest):
        job = _new_job(stages=active_stages)
        pid = job["pipeline_id"]

        async def _run():
            t0 = time.time()
            loop = asyncio.get_event_loop()
            clone_dir: str | None = None
            _store.update_job(pid, status="running")
            try:
                cfg = _apply_overrides(load_config(), req.config)
                cfg, clone_dir = await loop.run_in_executor(
                    _EXECUTOR,
                    lambda: _clone_repo_if_needed(cfg, req.repo),
                )
                client, raw_vulns, release_id, app_id = await loop.run_in_executor(
                    _EXECUTOR,
                    lambda: _resolve_vulnerabilities(
                        cfg, req.release_id, req.report_path, req.app_name,
                        getattr(req, "app_id", None),
                        persist_token=_should_persist_token(req.config),
                    ),
                )
                result = await loop.run_in_executor(
                    _EXECUTOR,
                    lambda: _run_until(cfg, client, raw_vulns, release_id,
                                       stop_after, pipeline_id=pid,
                                       max_upgrades=req.max_upgrades),
                )
                if req.repo:
                    result["repo"] = req.repo
                _finish_job(pid, "completed", result=result, t0=t0)
            except (PipelineCancelled, PipelineCancelledError):
                _finish_job(pid, "cancelled", error="Cancelled by user", t0=t0)
            except Exception as exc:
                _finish_job(pid, "failed", error=str(exc), t0=t0)
            finally:
                if clone_dir:
                    import shutil
                    shutil.rmtree(clone_dir, ignore_errors=True)

        asyncio.create_task(_run())
        return ok({"pipeline_id": pid, "status": "queued"})

    handler.__name__ = f"pipeline_until_{stop_after.replace('-', '_')}"
    return handler


for _stage in STAGE_ORDER:
    _descriptions = {
        "triage":           "Run only **Stage 1 — Triage**. Returns filtered & grouped dependency objects.",
        "version-resolver": "Run up to **Stage 2 — Version Resolver**. Returns groups enriched with safe version candidates.",
        "context":          "Run up to **Stage 3 — Context**. Returns groups with pom locations and calling files.",
        "api-diff":         "Run up to **Stage 4 — API Diff**. Returns groups with breaking-change analysis.",
        "ai-reasoning":     "Run up to **Stage 5 — AI Reasoning**. Returns groups with safety verdicts. No side-effects.",
        "adr-fix":          "Run up to **Stage 6 — ADR Fix**. Commits version bumps to git (no build, no push — see build-validation).",
        "build-validation": "Run up to **Stage 6b — Build Validation**. Runs the Maven build; pushes on success, rolls back on failure.",
        "pr-agent":         "Run up to **Stage 7 — PR Agent**. Creates GitHub PRs. No Fortify writeback.",
    }
    app.add_api_route(
        path=f"/pipeline/until/{_stage}",
        endpoint=_make_partial_endpoint(_stage),
        methods=["POST"],
        tags=["Partial Pipelines"],
        summary=f"Pipeline → stop after {_stage}",
        description=_descriptions[_stage],
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api_server:app", host="0.0.0.0", port=8000, reload=True)

# ═══════════════════════════════════════════════════════════════════════════════
# Escalation file endpoints
# Fortify writeback writes escalation .txt files to adr_output_dir.
# These endpoints serve them so the UI can list, view, and delete them.
# ═══════════════════════════════════════════════════════════════════════════════

# ── Escalation storage helpers (GCS-first, local fallback for dev) ───────────

def _esc_backend():
    """
    Return ("gcs", bucket, bucket_name, prefix, client) when GCS_BUCKET is
    set and reachable, else ("local",). Env vars are read fresh on every
    call so runtime-config overrides apply immediately.
    """
    bucket_name = os.environ.get("GCS_BUCKET", "").strip()
    if bucket_name:
        try:
            from google.cloud import storage
            client = storage.Client()
            prefix = os.environ.get("GCS_ESCALATION_PREFIX", "escalations/").rstrip("/") + "/"
            return ("gcs", client.bucket(bucket_name), bucket_name, prefix, client)
        except Exception as exc:
            print(f"[Escalations] GCS unavailable ({exc}) — using local dir")
    return ("local",)


def _parse_escalation_text(content: str) -> dict:
    """Parse key fields from the flat escalation report text format."""
    artifact_id = ""
    cves: list[str] = []
    reason = ""
    tried: list[str] = []
    severity = "HIGH"
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("Artifact:"):
            artifact_id = line.split(":", 1)[-1].strip()
        elif line.startswith("CVEs:"):
            cves = [v.strip() for v in line.split(":", 1)[-1].split(",") if v.strip()]
        elif line.startswith("Reason:"):
            reason = line.split(":", 1)[-1].strip()
        elif line.startswith("Tried:"):
            tried = [v.strip() for v in line.split(":", 1)[-1].split(",") if v.strip()]
        elif line.startswith("Severity:"):
            severity = line.split(":", 1)[-1].strip()
    return {"artifact_id": artifact_id, "cves": cves, "reason": reason,
            "tried": tried, "severity": severity}


@app.get("/escalations", tags=["Escalations"])
def list_fortify_escalations(output_dir: Optional[str] = Query(default=None)) -> dict:
    """List all Fortify escalation reports.

    GCS mode (GCS_BUCKET set): lists text blobs under GCS_ESCALATION_PREFIX
    in the shared bucket — every pod sees the same escalations regardless
    of which pod wrote them.
    Local mode (no GCS_BUCKET): lists escalation_*.txt in ADR_OUTPUT_DIR
    (override via ?output_dir=), for single-pod development only.
    """
    backend = _esc_backend()

    if backend[0] == "gcs":
        _, bucket, bucket_name, prefix, client = backend
        items = []
        for blob in client.list_blobs(bucket_name, prefix=prefix):
            if not blob.name.endswith(".txt"):
                continue
            filename = blob.name[len(prefix):]
            if "/" in filename or not filename.startswith("escalation_"):
                continue
            try:
                content = blob.download_as_bytes().decode("utf-8", errors="replace")
            except Exception:
                continue
            parsed = _parse_escalation_text(content)
            items.append({
                "filename":    filename,
                "artifact_id": parsed["artifact_id"] or filename.rsplit(".", 1)[0],
                "cves":        parsed["cves"],
                "reason":      parsed["reason"],
                "tried":       parsed["tried"],
                "severity":    parsed["severity"],
                "size_bytes":  blob.size or len(content),
                "modified_at": blob.updated.timestamp() if blob.updated else 0.0,
                "uri":         f"gs://{bucket_name}/{blob.name}",
            })
        items.sort(key=lambda i: i["modified_at"], reverse=True)
        return {"escalations": items, "total": len(items)}

    # ── Local mode (single-pod dev) ───────────────────────────────────────
    from pathlib import Path
    resolved_dir = output_dir or load_config().adr_output_dir
    esc_dir = Path(resolved_dir)
    if not esc_dir.exists():
        return {"escalations": [], "total": 0}

    items = []
    for txt_file in sorted(
        list(esc_dir.glob("escalation_*.txt")),
        key=lambda f: f.stat().st_mtime,
        reverse=True
    ):
        stat = txt_file.stat()
        content = txt_file.read_text(encoding="utf-8", errors="replace")
        parsed = _parse_escalation_text(content)
        items.append({
            "filename":    txt_file.name,
            "artifact_id": parsed["artifact_id"] or txt_file.stem,
            "cves":        parsed["cves"],
            "reason":      parsed["reason"],
            "tried":       parsed["tried"],
            "severity":    parsed["severity"],
            "size_bytes":  stat.st_size,
            "modified_at": stat.st_mtime,
        })

    return {"escalations": items, "total": len(items)}


@app.get("/escalations/{filename}", tags=["Escalations"])
def get_fortify_escalation(
    filename: str,
    output_dir: Optional[str] = Query(default=None)
) -> dict:
    """Return the full text content of one Fortify escalation report
    (GCS blob when GCS_BUCKET is set, local file otherwise)."""
    if "/" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    backend = _esc_backend()

    if backend[0] == "gcs":
        _, bucket, bucket_name, prefix, _client = backend
        from google.api_core import exceptions as gexc
        blob = bucket.blob(prefix + filename)
        try:
            content = blob.download_as_bytes().decode("utf-8", errors="replace")
        except gexc.NotFound:
            raise HTTPException(
                status_code=404,
                detail=f"Escalation {filename!r} not found in gs://{bucket_name}/{prefix}",
            )
        return {
            "filename":    filename,
            "content":     content,
            "modified_at": blob.updated.timestamp() if blob.updated else 0.0,
        }

    from pathlib import Path
    resolved_dir = output_dir or load_config().adr_output_dir
    esc_path = Path(resolved_dir) / filename
    if not esc_path.exists():
        raise HTTPException(status_code=404, detail=f"Escalation {filename!r} not found in {resolved_dir!r}")

    stat = esc_path.stat()
    return {
        "filename":    filename,
        "content":     esc_path.read_text(encoding="utf-8", errors="replace"),
        "modified_at": stat.st_mtime,
    }


@app.delete("/escalations/{filename}", tags=["Escalations"])
def delete_fortify_escalation(
    filename: str,
    output_dir: Optional[str] = Query(default=None)
) -> dict:
    """Delete a Fortify escalation report
    (GCS blob when GCS_BUCKET is set, local file otherwise)."""
    if "/" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    backend = _esc_backend()

    if backend[0] == "gcs":
        _, bucket, bucket_name, prefix, _client = backend
        from google.api_core import exceptions as gexc
        blob = bucket.blob(prefix + filename)
        try:
            blob.delete()
        except gexc.NotFound:
            raise HTTPException(
                status_code=404,
                detail=f"Escalation {filename!r} not found in gs://{bucket_name}/{prefix}",
            )
        return {"message": f"Deleted {filename}", "ok": True}

    from pathlib import Path
    resolved_dir = output_dir or load_config().adr_output_dir
    esc_path = Path(resolved_dir) / filename
    if not esc_path.exists():
        raise HTTPException(status_code=404, detail=f"Escalation {filename!r} not found in {resolved_dir!r}")

    esc_path.unlink()
    return {"message": f"Deleted {filename}", "ok": True}