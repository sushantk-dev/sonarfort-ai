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
from token_tracker import token_tracker
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


def _resolve_vulnerabilities(
    cfg: FortifyAIConfig,
    release_id: int,
    report_path: str | None,
    app_name: str | None,
    app_id: int | None = None,
):
    """
    Returns (client, raw_vulns, resolved_release_id, resolved_app_id).

    Resolution priority:
      1. report_path  — offline mode, no SSC calls
      2. release_id   — direct, fastest
      3. app_id       — skips name lookup, calls GET /releases?limit=1
      4. app_name     — name → app_id → release_id (two API calls)
    """
    from fortify_client import FortifyClient
    from offline_loader import load_report, NullFortifyClient

    if report_path:
        raw_vulns, file_release_id = load_report(report_path)
        effective_release_id = file_release_id if file_release_id else release_id
        client = NullFortifyClient(raw_vulns)
        return client, raw_vulns, effective_release_id, None

    client = FortifyClient.from_config(cfg)
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
) -> dict:
    """
    Execute the full pipeline and return a summary dict.
    When *pipeline_id* is supplied, each stage updates the shared job store so
    callers can poll /pipeline/status/{pipeline_id} for live progress.
    """
    if pipeline_id:
        token_tracker.start_run(pipeline_id)   # bind LLM token accounting to this run
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

    project_path = Path(cfg.project_path) if cfg.project_path else Path(".")
    japicmp_path = cfg.japicmp_jar_path or "/nonexistent/japicmp.jar"

    # Stage 1 — triage
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

    # Stage 2 — version resolver
    _check_cancelled(pipeline_id)
    t = _stage_start("version-resolver")
    resolved = resolve_all_groups(client, release_id, groups)
    _stage_done("version-resolver", t, {"groups_count": len(resolved)})

    # Stage 3 — context
    _check_cancelled(pipeline_id)
    t = _stage_start("context")
    context = locate_all_groups(project_path, resolved)
    _stage_done("context", t, {"groups_count": len(context)})

    # Stage 4 — api diff
    _check_cancelled(pipeline_id)
    t = _stage_start("api-diff")
    diffed = run_api_diff_all_groups(context, project_path, japicmp_path)
    _stage_done("api-diff", t, {"groups_count": len(diffed)})

    # Stage 5 — ai reasoning
    _check_cancelled(pipeline_id)
    t = _stage_start("ai-reasoning")
    reasoned = reason_all_groups(diffed, cfg.gcp_project, cfg.gcp_location)
    _stage_done("ai-reasoning", t, {
        "safe": sum(1 for g in reasoned if g.get("next_node") != "escalate"),
        "escalated": sum(1 for g in reasoned if g.get("next_node") == "escalate"),
    })

    # Stage 6 — adr fix
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
                    error_reason=group.get("escalation_reason", "Escalated by AI reasoning"),
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

    # Stage 7 — pr agent
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

    # Stage 8 — writeback + summary
    _check_cancelled(pipeline_id)
    if not dry_run:
        t = _stage_start("fortify-writeback")
        summary = run_all_reports(
            groups=reasoned, adr_results=adr_results,
            pr_results=pr_results, output_dir=cfg.adr_output_dir,
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
        "github_token":                "GITHUB_TOKEN",
        "sonar_token":                 "SONAR_TOKEN",
        "fortify_token":               "FORTIFY_API_TOKEN",
    }

    updates: dict[str, str] = {}
    for field, env_key in field_map.items():
        val = getattr(req, field, None)
        if val is None:
            continue
        # For token fields: skip if empty string (keep existing value)
        if field in ("github_token", "sonar_token", "fortify_token") and not str(val):
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
        try:
            cfg = _apply_overrides(load_config(), req.config)
            cfg, clone_dir = await loop.run_in_executor(
                _EXECUTOR,
                lambda: _clone_repo_if_needed(cfg, req.repo),
            )
            client, raw_vulns, release_id, app_id = await loop.run_in_executor(
                _EXECUTOR,
                lambda: _resolve_vulnerabilities(cfg, req.release_id, None, None),
            )
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
        try:
            cfg = _apply_overrides(load_config(), req.config)
            cfg, clone_dir = await loop.run_in_executor(
                _EXECUTOR,
                lambda: _clone_repo_if_needed(cfg, req.repo),
            )
            client, raw_vulns, release_id, app_id = await loop.run_in_executor(
                _EXECUTOR,
                lambda: _resolve_vulnerabilities(cfg, req.release_id, req.report_path, None),
            )
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
                lambda: _resolve_vulnerabilities(cfg, 0, None, req.app_name),
            )
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
        try:
            cfg = _apply_overrides(load_config(), req.config)
            cfg, clone_dir = await loop.run_in_executor(
                _EXECUTOR,
                lambda: _clone_repo_if_needed(cfg, req.repo),
            )
            client, raw_vulns, release_id, app_id = await loop.run_in_executor(
                _EXECUTOR,
                lambda: _resolve_vulnerabilities(cfg, 0, None, None, req.app_id),
            )
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
                ),
            )
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
            if clone_dir:
                import shutil
                shutil.rmtree(clone_dir, ignore_errors=True)

    asyncio.create_task(_run())
    return ok({"pipeline_id": pid, "status": "queued"})


# ═══════════════════════════════════════════════════════════════════════════════
# PIPELINE STATUS ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/pipeline/status/{pipeline_id}", tags=["Pipeline Status"])
def pipeline_status(pipeline_id: str):
    """
    Return the overall status of a pipeline job **and** the per-stage breakdown.

    **Overall status values**
    | Value       | Meaning                                    |
    |-------------|--------------------------------------------|
    | `queued`    | Accepted but thread not yet started        |
    | `running`   | At least one stage is executing            |
    | `completed` | All stages finished successfully           |
    | `failed`    | Pipeline aborted due to an unhandled error |

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
        client = FortifyClient.from_config(cfg)
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
                        error_reason=group.get("escalation_reason", "Escalated"),
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
    if pipeline_id:
        token_tracker.start_run(pipeline_id)   # bind LLM token accounting to this run
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
    reasoned = reason_all_groups(diff_groups, cfg.gcp_project, cfg.gcp_location)
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


# Reused across requests — constructing storage.Client() does an auth
# handshake, so building a fresh one per request was a major slowdown.
_gcs_client_singleton = None

# For legacy blobs written before we started stamping parsed fields as blob
# metadata: cache the parsed result per blob name, invalidated by blob.updated.
# Avoids re-downloading + re-parsing the same old file's full text on every
# single list request.
_legacy_parse_cache: dict[str, tuple[float, dict]] = {}

# Local-mode parse cache keyed by absolute file path, invalidated by mtime.
# Escalation files are write-once, so this turns a full re-read of every
# file on every request into just a stat() call once the cache is warm.
_local_parse_cache: dict[str, tuple[float, dict]] = {}


def _esc_backend():
    """
    Return ("gcs", bucket, bucket_name, prefix, client) when GCS_BUCKET is
    set and reachable, else ("local",). Env vars are read fresh on every
    call so runtime-config overrides apply immediately, but the underlying
    storage.Client() is created once and reused.
    """
    bucket_name = os.environ.get("GCS_BUCKET", "").strip()
    if bucket_name:
        try:
            global _gcs_client_singleton
            if _gcs_client_singleton is None:
                from google.cloud import storage
                _gcs_client_singleton = storage.Client()
            client = _gcs_client_singleton
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
        # list_blobs() already returns metadata (including custom metadata)
        # for free as part of the listing call — no per-blob GET needed
        # unless we hit an older file written before metadata was stamped.
        for blob in client.list_blobs(bucket_name, prefix=prefix):
            if not blob.name.endswith(".txt"):
                continue
            filename = blob.name[len(prefix):]
            if "/" in filename or not filename.startswith("escalation_"):
                continue

            modified_at = blob.updated.timestamp() if blob.updated else 0.0
            meta = blob.metadata or {}

            if meta.get("artifact_id") is not None:
                # Fast path: fields were stamped at write time, no download.
                parsed = {
                    "artifact_id": meta.get("artifact_id", ""),
                    "cves":        [v for v in meta.get("cves", "").split(",") if v],
                    "reason":      meta.get("reason", ""),
                    "tried":       [v for v in meta.get("tried", "").split(",") if v],
                    "severity":    meta.get("severity", "HIGH"),
                }
            else:
                # Legacy blob with no stamped metadata — parse full content,
                # but only once per (blob, modified_at); cache the result.
                cached = _legacy_parse_cache.get(blob.name)
                if cached and cached[0] == modified_at:
                    parsed = cached[1]
                else:
                    try:
                        content = blob.download_as_bytes().decode("utf-8", errors="replace")
                    except Exception:
                        continue
                    parsed = _parse_escalation_text(content)
                    _legacy_parse_cache[blob.name] = (modified_at, parsed)

            items.append({
                "filename":    filename,
                "artifact_id": parsed["artifact_id"] or filename.rsplit(".", 1)[0],
                "cves":        parsed["cves"],
                "reason":      parsed["reason"],
                "tried":       parsed["tried"],
                "severity":    parsed["severity"],
                "size_bytes":  blob.size or 0,
                "modified_at": modified_at,
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
        path_key = str(txt_file.resolve())
        cached = _local_parse_cache.get(path_key)
        if cached and cached[0] == stat.st_mtime:
            parsed = cached[1]
        else:
            content = txt_file.read_text(encoding="utf-8", errors="replace")
            parsed = _parse_escalation_text(content)
            _local_parse_cache[path_key] = (stat.st_mtime, parsed)

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