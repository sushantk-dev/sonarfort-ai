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
                     ai-reasoning | adr-fix | pr-agent | fortify-writeback
    POST /pipeline/cancel/{pipeline_id}   — cooperative cancellation at the next stage boundary
    POST /pipeline/resume/{pipeline_id}   — resume an interrupted/failed/cancelled run from its
                                             last checkpointed stage (full-pipeline runs only)
    POST /pipeline/sweep                  — manually trigger the orphan-job sweep (also runs
                                             automatically in the background on every pod)

  INDIVIDUAL STAGES (can be called in isolation)
    POST /stages/triage            — Stage 1: filter/group raw vulnerabilities
    POST /stages/version-resolver  — Stage 2: resolve safe version candidates
    POST /stages/context           — Stage 3: locate dep in codebase
    POST /stages/api-diff          — Stage 4: run japicmp API diff
    POST /stages/ai-reasoning      — Stage 5: AI safety verdict
    POST /stages/adr-fix           — Stage 6: invoke adr.py --commit --push
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
from typing import Any, Dict, Literal, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# ── Internal imports ──────────────────────────────────────────────────────────
from config import FortifyAIConfig, load_config
from job_store import create_job_store, ALL_STAGE_NAMES
from runtime_config import apply_overrides, persist_overrides, is_persisted
from state import AgentState

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


def _run_orphan_sweep(timeout_seconds: float | None = None) -> list[str]:
    """
    Find jobs stuck at status='running' with no stage progress for longer
    than *timeout_seconds* (default ORPHAN_SWEEP_TIMEOUT_SECONDS) and flip
    them to 'failed'. This closes the "stuck forever" gap left when a pod
    dies (OOM kill, node eviction, hard crash) mid-job without ever reaching
    finish_job — no SIGTERM is delivered in that case, so the shutdown
    handler below never runs.

    The checkpoint (if any) is preserved — finish_job only clears it on
    status='completed' — so a swept job still exposes a resumable
    checkpoint via POST /pipeline/resume/{pipeline_id}.

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
    _store.finish_job(pipeline_id, status, result=result, error=error, t0=t0)


class PipelineCancelled(Exception):
    """Raised internally when a job's cancel flag is observed between stages."""


def _check_cancelled(pipeline_id: str | None) -> None:
    """
    Cooperative cancellation checkpoint. Called between pipeline stages (and
    inside long per-group loops) so a POST /pipeline/cancel/{id} actually
    stops the run from advancing to the next stage/side-effect, instead of
    just being ignored while the job runs to completion in the background.
    """
    if pipeline_id and _store.is_cancel_requested(pipeline_id):
        raise PipelineCancelled()

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


class AiCodeFixRequest(BaseModel):
    groups: list[dict] = Field(..., description="Groups that failed build — need AI patching")
    project_path: str = Field(..., description="Absolute path to Maven project root")
    gcp_project: str = Field(default="")
    gcp_location: str = Field(default="us-central1")


class PrAgentRequest(BaseModel):
    groups: list[dict] = Field(..., description="Reasoned groups")
    adr_results: list[dict] = Field(..., description="Results from /stages/adr-fix")
    release_id: int = Field(..., description="Fortify release ID (used in PR body)")
    github_token: str = Field(..., description="GitHub personal access token")
    github_repo: str = Field(..., description="GitHub repo in owner/repo format")
    reviewers: list[str] = Field(default_factory=list)


class FortifyWritebackRequest(BaseModel):
    groups: list[dict] = Field(..., description="Reasoned groups")
    adr_results: list[dict] = Field(..., description="Results from /stages/adr-fix")
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
    side-effecting stages: adr-fix (git commit/push) and pr-agent (opens a
    GitHub PR) are NOT re-run once checkpointed — only stages after the
    checkpoint's resume_stage actually execute. pr-agent additionally
    guards against duplicate PRs via branch-name lookup (see
    pr_agent._find_existing_pr) in case a checkpoint boundary is ever
    re-crossed.
    """
    from pathlib import Path
    from agents.triage import group_by_dependency, apply_max_upgrades
    from agents.version_resolver import resolve_all_groups
    from agents.context import locate_all_groups
    from agents.api_diff import run_api_diff_all_groups
    from agents.ai_reasoning import reason_all_groups
    from agents.adr_fix import run_adr_fix
    from agents.pr_agent import create_prs_for_all_groups
    from agents.fortify_writeback import run_all_reports
    from state import AdrResult

    def _stage_start(name: str) -> float:
        t = time.time()
        if pipeline_id:
            _update_stage(pipeline_id, name, status="running", started_at=_now())
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
                      "ai-reasoning", "adr-fix", "pr-agent", "fortify-writeback"]:
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
    else:
        _check_cancelled(pipeline_id)
        t = _stage_start("context")
        context = locate_all_groups(project_path, resolved)
        _stage_done("context", t, {"groups_count": len(context)})
        _checkpoint("api-diff", context=context)

    # Stage 4 — api diff
    if _already_done("api-diff"):
        diffed = acc["diffed"]
    else:
        _check_cancelled(pipeline_id)
        t = _stage_start("api-diff")
        diffed = run_api_diff_all_groups(context, project_path, japicmp_path)
        _stage_done("api-diff", t, {"groups_count": len(diffed)})
        _checkpoint("ai-reasoning", diffed=diffed)

    # Stage 5 — ai reasoning
    if _already_done("ai-reasoning"):
        reasoned = acc["reasoned"]
    else:
        _check_cancelled(pipeline_id)
        t = _stage_start("ai-reasoning")
        try:
            reasoned = reason_all_groups(diffed, cfg.gcp_project, cfg.gcp_location)
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

    # Stage 6 — adr fix (side-effecting: commits + pushes — never re-run once checkpointed)
    if _already_done("adr-fix"):
        adr_results = acc["adr_results"]
    else:
        _check_cancelled(pipeline_id)
        t = _stage_start("adr-fix")
        adr_results: list[dict] = []
        for group in reasoned:
            _check_cancelled(pipeline_id)  # stop before pushing the next commit
            artifact_id = group["parsed"]["artifact_id"]
            if group.get("next_node") == "escalate":
                adr_results.append({
                    "artifact_id": artifact_id,
                    "result": AdrResult(
                        success=False, branch_name=None, commit_hash=None,
                        build_time_seconds=None, pdf_path=None,
                        error_reason=_escalation_reason(group),
                    ),
                })
                continue
            if dry_run or not cfg.adr_path:
                adr_results.append({
                    "artifact_id": artifact_id,
                    "result": AdrResult(
                        success=False, branch_name=None, commit_hash=None,
                        build_time_seconds=None, pdf_path=None,
                        error_reason="dry_run=True — ADR not invoked" if dry_run else "ADR_PATH not configured",
                    ),
                })
            else:
                result = run_adr_fix(
                    group, adr_path=cfg.adr_path,
                    project_path=str(project_path),
                    jira_prefix=cfg.jira_id_prefix,
                    release_id=release_id,
                )
                adr_results.append({"artifact_id": artifact_id, "result": result})
        _adr_ok = sum(1 for r in adr_results if r.get("result", {}).get("success"))
        _stage_done("adr-fix", t, {"fixed": _adr_ok, "total": len(adr_results)})
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
            ai-reasoning → adr-fix → pr-agent → fortify-writeback
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
            _store.update_job(pid, resume_meta={
                "release_id": release_id,
                "report_path": None,
                "app_name": None,
                "app_id": None,
                "repo": req.repo,
                "dry_run": False,
                "max_upgrades": req.max_upgrades,
                "config_overrides": req.config.model_dump(),
            })
            result = await loop.run_in_executor(
                _EXECUTOR,
                lambda: _run_full_pipeline(cfg, client, raw_vulns, release_id,
                                           max_upgrades=req.max_upgrades,
                                           pipeline_id=pid),
            )
            if req.repo:
                result["repo"] = req.repo
            _finish_job(pid, "completed", result=result, t0=t0)
        except PipelineCancelled:
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
            ai-reasoning → adr-fix → pr-agent → fortify-writeback
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
            _store.update_job(pid, resume_meta={
                "release_id": release_id,
                "report_path": req.report_path,
                "app_name": None,
                "app_id": None,
                "repo": req.repo,
                "dry_run": False,
                "max_upgrades": req.max_upgrades,
                "config_overrides": req.config.model_dump(),
            })
            result = await loop.run_in_executor(
                _EXECUTOR,
                lambda: _run_full_pipeline(cfg, client, raw_vulns, release_id,
                                           max_upgrades=req.max_upgrades,
                                           pipeline_id=pid),
            )
            if req.repo:
                result["repo"] = req.repo
            _finish_job(pid, "completed", result=result, t0=t0)
        except PipelineCancelled:
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
            ai-reasoning → adr-fix → pr-agent → fortify-writeback
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
            _store.update_job(pid, resume_meta={
                "release_id": release_id,
                "report_path": None,
                "app_name": None,
                "app_id": None,
                "repo": req.repo,
                "dry_run": False,
                "max_upgrades": req.max_upgrades,
                "config_overrides": req.config.model_dump(),
            })
            result = await loop.run_in_executor(
                _EXECUTOR,
                lambda: _run_full_pipeline(cfg, client, raw_vulns, release_id,
                                           max_upgrades=req.max_upgrades,
                                           pipeline_id=pid),
            )
            result["app_id"] = app_id
            result["repo"] = req.repo  # echo back so callers know which repo was used
            _finish_job(pid, "completed", result=result, t0=t0)
        except PipelineCancelled:
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
            ai-reasoning → adr-fix → pr-agent → fortify-writeback
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
            _store.update_job(pid, resume_meta={
                "release_id": release_id,
                "report_path": None,
                "app_name": None,
                "app_id": None,
                "repo": req.repo,
                "dry_run": False,
                "max_upgrades": req.max_upgrades,
                "config_overrides": req.config.model_dump(),
            })
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
        except PipelineCancelled:
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

    ADR (git commit/push), PR creation, and Fortify writeback are **skipped**.
    Everything up to and including AI reasoning runs normally.
    Useful for previewing what the pipeline would do.
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
            _store.update_job(pid, resume_meta={
                "release_id": release_id,
                "report_path": req.report_path,
                "app_name": None,
                "app_id": None,
                "repo": req.repo,
                "dry_run": True,
                "max_upgrades": req.max_upgrades,
                "config_overrides": req.config.model_dump(),
            })
            result = await loop.run_in_executor(
                _EXECUTOR,
                lambda: _run_full_pipeline(cfg, client, raw_vulns, release_id,
                                           dry_run=True, max_upgrades=req.max_upgrades,
                                           pipeline_id=pid),
            )
            if req.repo:
                result["repo"] = req.repo
            _finish_job(pid, "completed", result=result, t0=t0)
        except PipelineCancelled:
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
    jobs = _store.list_jobs(limit=limit, offset=offset)
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
    return ok(job)


@app.get("/pipeline/status/{pipeline_id}/{stage_name}", tags=["Pipeline Status"])
def pipeline_stage_status(pipeline_id: str, stage_name: str):
    """
    Return the status of a **single stage** within a pipeline run.

    Valid `stage_name` values:
    `triage` · `version-resolver` · `context` · `api-diff` ·
    `ai-reasoning` · `adr-fix` · `pr-agent` · `fortify-writeback`

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
    (and, for the `adr-fix` stage, between each dependency in the loop),
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

    Side-effecting stages already checkpointed (adr-fix, pr-agent) are
    reused as-is and NOT re-run — see `_run_full_pipeline`'s
    `resume_checkpoint` handling and `pr_agent._find_existing_pr` for the
    duplicate-PR guard.

    Returns a *pipeline_id* (the SAME one — resume continues the existing
    job record rather than minting a new one) immediately; poll
    **GET /pipeline/status/{pipeline_id}** as usual.
    """
    job = _store.get_job(pipeline_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"pipeline_id '{pipeline_id}' not found")

    if job.get("status") in ("running", "completed"):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot resume a job with status '{job['status']}'",
        )

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

    checkpoint = _store.get_checkpoint(pipeline_id)
    if not checkpoint:
        raise HTTPException(
            status_code=400,
            detail="No checkpoint found for this job — no stage completed "
                   "yet, so there is nothing to resume from. Start a new "
                   "pipeline run instead.",
        )

    pid = pipeline_id
    t0 = time.time()
    _store.update_job(pid, status="running", cancel_requested=False, error=None)

    async def _run():
        loop = asyncio.get_event_loop()
        clone_dir: str | None = None
        _track_start(pid)
        try:
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
        except PipelineCancelled:
            _finish_job(pid, "cancelled", error="Cancelled by user", t0=t0)
        except Exception as exc:
            _finish_job(pid, "failed", error=str(exc), t0=t0)
        finally:
            _track_end(pid)
            if clone_dir:
                import shutil
                shutil.rmtree(clone_dir, ignore_errors=True)

    asyncio.create_task(_run())
    return ok({
        "pipeline_id": pid,
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
    **Stage 6 — ADR Fix**

    Invoke `adr.py --commit JIRA_ID --push` for each actionable group.
    Parses exit code, branch name, commit hash, and PDF path from stdout.

    Input:  groups[]       (from /stages/ai-reasoning)
            adr_path       (absolute path to adr.py)
            project_path   (absolute path to Maven project root)
            jira_prefix    (e.g. "FORTIFY")
    Output: adr_results[] with success/failure per dependency
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
                        success=False, branch_name=None, commit_hash=None,
                        build_time_seconds=None, pdf_path=None,
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
            adr_results[]  (from /stages/adr-fix)
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
            adr_results[]  (from /stages/adr-fix)
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
    "api-diff", "ai-reasoning", "adr-fix", "pr-agent",
]

STAGE_ORDER: list[StageLabel] = [
    "triage", "version-resolver", "context",
    "api-diff", "ai-reasoning", "adr-fix", "pr-agent",
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
    from pathlib import Path
    from agents.triage import group_by_dependency, apply_max_upgrades
    from agents.version_resolver import resolve_all_groups
    from agents.context import locate_all_groups
    from agents.api_diff import run_api_diff_all_groups
    from agents.ai_reasoning import reason_all_groups
    from agents.adr_fix import run_adr_fix
    from agents.pr_agent import create_prs_for_all_groups
    from state import AdrResult

    def _s_start(name: str) -> float:
        t = time.time()
        if pipeline_id:
            _update_stage(pipeline_id, name, status="running", started_at=_now())
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
    diff_groups = run_api_diff_all_groups(
        context_groups, project_path,
        cfg.japicmp_jar_path or "/nonexistent/japicmp.jar",
    )
    result["groups"] = diff_groups
    _s_done("api-diff", t, {"groups_count": len(diff_groups)})
    if idx == 3:
        for s in STAGE_ORDER[4:]:
            _s_skip(s)
        return result

    # Stage 4 — ai reasoning
    _check_cancelled(pipeline_id)
    t = _s_start("ai-reasoning")
    try:
        reasoned = reason_all_groups(diff_groups, cfg.gcp_project, cfg.gcp_location)
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

    # Stage 5 — adr fix
    _check_cancelled(pipeline_id)
    t = _s_start("adr-fix")
    adr_results: list[dict] = []
    for group in reasoned:
        _check_cancelled(pipeline_id)  # stop before pushing the next commit
        artifact_id = group["parsed"]["artifact_id"]
        if group.get("next_node") == "escalate" or not cfg.adr_path:
            adr_results.append({
                "artifact_id": artifact_id,
                "result": AdrResult(
                    success=False, branch_name=None, commit_hash=None,
                    build_time_seconds=None, pdf_path=None,
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
                ),
            })
    _adr_ok = sum(1 for r in adr_results if r.get("result", {}).get("success"))
    result["adr_results"] = adr_results
    _s_done("adr-fix", t, {"fixed": _adr_ok, "total": len(adr_results)})
    if idx == 5:
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
            except PipelineCancelled:
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
        "adr-fix":          "Run up to **Stage 6 — ADR Fix**. Commits and pushes version bumps to git.",
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