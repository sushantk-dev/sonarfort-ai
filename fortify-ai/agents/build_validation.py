"""
FortifyAI — Build Validation Agent (Iteration 9 — remote build)
------------------------------------------------------------------
Responsibility:
  Runs immediately after adr_fix in the graph. adr_fix only edits pom.xml
  and creates a local git commit on a fresh feature branch — this node
  owns everything downstream of that commit:

    1. Check out the branch adr_fix just committed.
    2. Push it to origin (the build always runs on a GitHub Actions
       runner, not on this pod — see _run_maven_build_via_actions below —
       so the branch has to exist on origin before anything can build it).
    3. Dispatch `workflow_file` (default runMavenSharedWorkflow.yml, must
       declare `on: workflow_dispatch`) against that branch and poll until
       it completes.
    4. On success → nothing further to push (already pushed in step 2).
       pr_agent only opens a PR for a group whose build_validation result
       is a *pushed* branch (this node overwrites state["_adr_results"]/
       state["adr_result"] in place with the merged outcome, since
       pr_agent_node downstream still reads those keys — see the "Merge"
       comment in build_validation_node).
    5. On failure → roll the branch back: checkout base_branch, delete the
       feature branch locally AND on origin (it was pushed in step 2, so
       origin needs cleaning up too, not just the local checkout), and
       extract the Maven error (from the failed run's downloaded logs) for
       failure_analysis.

  Why the build runs on GitHub Actions rather than as a local subprocess:
    This pod doesn't carry the corporate proxy / internal Nexus mirror
    settings.xml, JDK registry, etc. that the existing CI runner already
    has configured and known-working. Building there instead of
    replicating that environment on every pipeline pod avoids drift
    between "what this pipeline validates" and "what CI actually builds".

Console output (done-when):
  [Build Validation] Checking out feature/fortify-fix-1697672-c6266fa8
  [Build Validation] Pushed feature/fortify-fix-1697672-c6266fa8 — dispatching runMavenSharedWorkflow.yml
  [Build Validation] Tracking run https://github.com/OWNER/REPO/actions/runs/123456
  [Build Validation]   build › Set up job: completed
  [Build Validation]   build › Run mvn clean compile: in_progress
  [Build Validation]   build › Run mvn clean compile: completed
  [Build Validation] ── build log ──
  [Build Validation]   ##[group]Run mvn clean compile ...
  [Build Validation]   [INFO] Scanning for projects...
  [Build Validation]   ...
  [Build Validation] ✅ succeeded (87s) — https://github.com/OWNER/REPO/actions/runs/123456
"""

from __future__ import annotations

import io
import os
import subprocess
import time
import zipfile
from datetime import datetime, timezone
from typing import Callable, Optional

import requests
from loguru import logger

from state import AgentState, BuildValidationResult, PipelineCancelledError

try:  # flat layout (adr_fix.py at repo root, next to state.py)
    from adr_fix import _extract_maven_error
except ImportError:  # package layout
    from agents.adr_fix import _extract_maven_error  # type: ignore

_DEFAULT_WORKFLOW_FILE = "runMavenSharedWorkflow.yml"

# Overall wall-clock budget for a dispatched run: dispatch lookup + CI queue
# time + the build itself. Generous relative to the old local-subprocess
# timeout since a shared runner can be queued behind other jobs.
_GH_ACTIONS_TIMEOUT_SECONDS = int(os.environ.get("FORTIFYAI_GH_ACTIONS_TIMEOUT", 1200))
_GH_ACTIONS_POLL_SECONDS = 10
# How long to wait for the dispatched run to show up in the workflow's run
# list before giving up — workflow_dispatch's REST response is just a 204,
# it never returns a run id, so the run has to be found by polling.
_GH_ACTIONS_RUN_LOOKUP_TIMEOUT_SECONDS = 60



# ── lock cleanup ──────────────────────────────────────────────────────────────

def _clear_git_index_lock(project_path: str) -> bool:
    """Remove a stale .git/index.lock in project_path, if present — e.g. left
    behind by a previous killed/timed-out run against this same project_path,
    which would otherwise block this run's checkout/push indefinitely."""
    lock_path = os.path.join(project_path, ".git", "index.lock")
    if os.path.exists(lock_path):
        try:
            os.remove(lock_path)
            logger.info(f"[Build Validation] Removed stale git lock: {lock_path}")
            return True
        except OSError as exc:
            logger.warning(f"[Build Validation] Could not remove git lock {lock_path}: {exc}")
    return False


# ── git helpers ────────────────────────────────────────────────────────────────

def _run_git(cmd: list[str], project_path: str, desc: str) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            cmd, cwd=project_path, capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            err = (result.stderr or result.stdout or "").strip()
            logger.warning(f"[Build Validation] git {desc} failed: {err}")
            return False, err
        return True, ""
    except Exception as exc:
        logger.warning(f"[Build Validation] git {desc} raised: {exc}")
        return False, str(exc)


def _rollback_branch(
    project_path: str, branch_name: str, base_branch: Optional[str], delete_remote: bool = False,
) -> None:
    """
    Discard a feature branch whose build failed: checkout base, delete the
    local branch. delete_remote=True additionally deletes it on origin —
    needed here because the branch is always pushed *before* the GitHub
    Actions build runs (the runner can only build what's already on
    origin), so a failed build has already left the branch on origin and
    it must be cleaned up there too, not just locally.
    """
    target = base_branch or "main"
    ok, _ = _run_git(["git", "checkout", target], project_path, f"checkout {target}")
    if not ok and target != "master":
        _run_git(["git", "checkout", "master"], project_path, "checkout master (fallback)")
    _run_git(["git", "branch", "-D", branch_name], project_path, f"delete {branch_name}")
    if delete_remote:
        ok, err = _run_git(
            ["git", "push", "origin", "--delete", branch_name], project_path, f"delete origin/{branch_name}",
        )
        if not ok:
            logger.warning(f"[Build Validation] Could not delete origin/{branch_name}: {err}")
    logger.warning(
        f"[Build Validation] ⚠️  Rolled back — deleted local"
        f"{' + remote' if delete_remote else ''} branch {branch_name}"
    )


# ── Remote build via GitHub Actions ─────────────────────────────────────────
#
# The build always runs on a GitHub Actions runner, not on this pod: push
# the branch, dispatch `workflow_file` (must declare `on: workflow_dispatch`)
# against it, and poll until the run completes. workflow_dispatch's REST
# response is just a 204 (no run id), so the run has to be located by
# listing recent runs on that branch/event after the dispatch.

def _download_run_log_text(run, github_token: str) -> str:
    """
    Fetch the full combined text of every job's log for a finished
    WorkflowRun, so build-failure output flows into _extract_maven_error
    exactly the way local mvn output used to. GitHub's logs endpoint
    returns a zip archive (one .txt per job/step group); PyGithub has no
    built-in helper for it, so it's fetched directly here with `requests`.
    Returns "" on any failure (network, auth, malformed zip) — callers
    should treat that as "no log text available", not as a build failure.
    """
    try:
        resp = requests.get(
            run.logs_url,
            headers={
                "Authorization": f"Bearer {github_token}",
                "Accept": "application/vnd.github+json",
            },
            timeout=30,
        )
        resp.raise_for_status()
        chunks: list[str] = []
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            for name in sorted(zf.namelist()):
                if not name.endswith(".txt"):
                    continue
                chunks.append(f"── {name} ──")
                chunks.append(zf.read(name).decode("utf-8", errors="replace"))
        return "\n".join(chunks)
    except Exception as exc:
        logger.warning(f"[Build Validation] Could not download GitHub Actions run logs: {exc}")
        return ""


def _download_job_log_text(github_repo: str, job_id: int, github_token: str) -> str:
    """
    Fetch the raw text log for a single completed job (plain text, not a
    zip — that's only for the whole-run endpoint used by
    _download_run_log_text). Used to print a job's output the moment it
    finishes, for live progress, rather than waiting for the whole run.
    Returns "" on any failure — logs may briefly 404 right after a job
    transitions to completed, before GitHub finishes persisting them.
    """
    try:
        resp = requests.get(
            f"https://api.github.com/repos/{github_repo}/actions/jobs/{job_id}/logs",
            headers={
                "Authorization": f"Bearer {github_token}",
                "Accept": "application/vnd.github+json",
            },
            timeout=30,
        )
        resp.raise_for_status()
        return resp.text
        # NOTE: requests strips the Authorization header on any redirect to a
        # different host by default — this endpoint 302s to short-lived blob
        # storage, so the token is never sent there.
    except Exception as exc:
        logger.debug(f"[Build Validation] Could not download job {job_id} log yet: {exc}")
        return ""


def _stream_run_progress(
    run, github_repo: str, github_token: str, printed_steps: set, printed_job_logs: set,
) -> None:
    """
    Called on every poll iteration while a run is in progress. Prints:
      - each step's status the first time it's seen in a new state
        (queued → in_progress → completed), so progress is visible turn by
        turn even though GitHub has no true log-streaming API for a run
        that's still executing;
      - the full log text of a job the moment that job completes, rather
        than waiting for the whole run to finish (multi-job workflows then
        show earlier jobs' output while later jobs are still running).

    printed_steps / printed_job_logs are caller-owned sets used to avoid
    re-printing the same step transition or job log on the next poll.
    """
    try:
        jobs = list(run.jobs())
    except Exception as exc:
        logger.debug(f"[Build Validation] Could not list jobs for run {run.id}: {exc}")
        return

    for job in jobs:
        for step in (job.raw_data or {}).get("steps", []):
            key = (job.id, step["name"], step["status"], step.get("conclusion"))
            if key in printed_steps:
                continue
            printed_steps.add(key)
            state = step.get("conclusion") or step["status"]
            logger.info(f"[Build Validation]   {job.name} › {step['name']}: {state}")

        if job.status == "completed" and job.id not in printed_job_logs:
            printed_job_logs.add(job.id)
            log_text = _download_job_log_text(github_repo, job.id, github_token)
            if log_text:
                logger.info(f"[Build Validation] ── {job.name} log ──")
                for line in log_text.splitlines():
                    logger.info(f"[Build Validation]   {line}")


def _find_dispatched_run(repo, workflow, ref: str, dispatched_after: "datetime", cancel_check):
    """
    Poll the workflow's run list for the run created by our dispatch: the
    newest workflow_dispatch run on `ref` whose created_at is at/after
    dispatched_after. Returns the WorkflowRun, or None if it never showed
    up within _GH_ACTIONS_RUN_LOOKUP_TIMEOUT_SECONDS (dispatch may have
    silently failed — e.g. workflow_dispatch not declared in the yml on
    that ref, or a permissions error that the 204 response hides).
    """
    deadline = time.time() + _GH_ACTIONS_RUN_LOOKUP_TIMEOUT_SECONDS
    while time.time() < deadline:
        if cancel_check is not None and cancel_check():
            raise PipelineCancelledError("Cancelled while waiting for the GitHub Actions run to start")
        try:
            runs = workflow.get_runs(branch=ref, event="workflow_dispatch")
            for run in runs:  # PagedList, newest first
                if run.created_at.replace(tzinfo=timezone.utc) >= dispatched_after:
                    return run
        except Exception as exc:
            logger.warning(f"[Build Validation] Error polling for dispatched run: {exc}")
        time.sleep(3)
    return None


def _cancel_run(run) -> None:
    """
    Best-effort: ask GitHub to cancel an in-progress run. Called whenever
    this function is about to give up on a run for a reason that has
    nothing to do with the run's own conclusion (our timeout, a user
    cancellation, or polling itself breaking) — otherwise the run keeps
    consuming a runner and can still push/succeed *after* we've already
    reported failure and rolled the branch back, leaving an orphaned run
    racing an already-deleted branch. Never raises.
    """
    try:
        run.cancel()
        logger.warning(f"[Build Validation] Requested cancellation of {run.html_url}")
    except Exception as exc:
        logger.warning(f"[Build Validation] Could not cancel {run.html_url}: {exc}")


# Consecutive polling failures (network blip, transient 5xx, rate limiting)
# tolerated before giving up — a single run.update() exception here used to
# crash the whole node uncaught; now it's retried with backoff and only
# treated as a real failure once it's persistent, not transient.
_GH_ACTIONS_MAX_CONSECUTIVE_POLL_ERRORS = 5


def _run_maven_build_via_actions(
    branch_name: str,
    github_token: str,
    github_repo: str,
    workflow_file: str = _DEFAULT_WORKFLOW_FILE,
    workflow_inputs: Optional[dict] = None,
    cancel_check: Optional[Callable[[], bool]] = None,
) -> tuple[bool, int, str, str, bool]:
    """
    Dispatch `workflow_file` against `branch_name` in `github_repo`, stream
    step-level progress + each job's log as it finishes (see
    _stream_run_progress) while waiting for it to complete, and return
    (success, duration_seconds, stdout, stderr, triggered).

    `triggered` distinguishes "the pipeline never actually started" (bad
    token/repo/workflow_file, or workflow_dispatch not declared on this
    branch — stop conditions #1/#2 below) from "the pipeline ran and then
    failed/timed out/lost contact" (#3-6). validate_one uses this to skip
    build validation (leave the pushed branch alone, no rollback) rather
    than treat an infra/config problem as a build failure.

    branch_name must already be pushed to origin — GitHub Actions builds
    what's on the remote, not this pod's working tree (see validate_one,
    which pushes before calling this).

    Stop conditions:
      1. Dispatch itself fails (bad token/repo/workflow_file, network) —
         stops immediately, nothing to cancel remotely (no run exists yet).
         triggered=False → validate_one skips build validation instead of
         rolling back.
      2. No matching run appears within _GH_ACTIONS_RUN_LOOKUP_TIMEOUT_SECONDS
         (60s) of dispatching — usually means workflow_file doesn't declare
         `on: workflow_dispatch` on this branch, or the token lacks
         actions:write. Nothing to cancel (dispatch may not have created a
         run at all). triggered=False → same skip treatment as #1.
      3. The run reaches GitHub's own "completed" status with any
         conclusion other than "success" (failure, cancelled, timed_out,
         action_required, stale, neutral, skipped) — the run finished on
         its own; nothing to cancel, just report it. triggered=True → a
         real build failure, validate_one rolls the branch back.
      4. cancel_check() returns True (user/pipeline cancellation) — the
         run is actively cancelled on GitHub via _cancel_run before
         PipelineCancelledError propagates, so a user-cancelled pipeline
         doesn't leave an orphaned run still building on GitHub's infra.
      5. Wall-clock exceeds _GH_ACTIONS_TIMEOUT_SECONDS (1200s default,
         override via FORTIFYAI_GH_ACTIONS_TIMEOUT) while the run is still
         in progress — the run is actively cancelled via _cancel_run before
         returning failure, for the same orphaned-run reason as #4.
         triggered=True → treated as a real build failure (the run did
         start; it just didn't finish in time).
      6. Polling the run's status itself fails
         _GH_ACTIONS_MAX_CONSECUTIVE_POLL_ERRORS (5) times in a row — a
         persistent API/network problem, not a build failure. The run is
         left running in this case (we can't reliably talk to the API to
         cancel it either) and reported as an inconclusive failure.
         triggered=True → still rolled back, since we can't confirm the
         branch is safe to leave pushed without knowing the outcome.
    """
    try:
        from github import Github  # type: ignore
    except ImportError:
        return False, 0, "", "PyGithub not installed — cannot dispatch GitHub Actions build", False

    t0 = time.time()
    dispatched_at = datetime.now(timezone.utc)
    try:
        gh = Github(github_token)
        repo = gh.get_repo(github_repo)
        workflow = repo.get_workflow(workflow_file)
        ok = workflow.create_dispatch(ref=branch_name, inputs=workflow_inputs or {})
        if not ok:
            return False, 0, "", f"GitHub rejected the dispatch request for {workflow_file} @ {branch_name}", False
    except Exception as exc:
        return False, 0, "", f"Could not dispatch {workflow_file}: {exc}", False

    logger.info(f"[Build Validation] Dispatched {workflow_file} for {branch_name} — waiting for run to start")
    try:
        run = _find_dispatched_run(repo, workflow, branch_name, dispatched_at, cancel_check)
    except PipelineCancelledError:
        raise
    if run is None:
        duration = int(time.time() - t0)
        return False, duration, "", (
            f"Dispatched {workflow_file} but no matching run appeared within "
            f"{_GH_ACTIONS_RUN_LOOKUP_TIMEOUT_SECONDS}s — check that the workflow file on "
            f"{branch_name} declares 'on: workflow_dispatch' and that the token has actions:write."
        ), False

    logger.info(f"[Build Validation] Tracking run {run.html_url}")
    printed_steps: set = set()
    printed_job_logs: set = set()
    consecutive_poll_errors = 0
    while True:
        if cancel_check is not None and cancel_check():
            _cancel_run(run)
            raise PipelineCancelledError(
                f"Cancelled while the GitHub Actions build was running ({run.html_url})"
            )
        if time.time() - t0 > _GH_ACTIONS_TIMEOUT_SECONDS:
            duration = int(time.time() - t0)
            _cancel_run(run)
            return False, duration, "", (
                f"GitHub Actions run did not complete within {_GH_ACTIONS_TIMEOUT_SECONDS}s "
                f"and was cancelled: {run.html_url}"
            ), True
        try:
            run.update()  # refresh status/conclusion from the API
            consecutive_poll_errors = 0
        except Exception as exc:
            consecutive_poll_errors += 1
            logger.warning(
                f"[Build Validation] Error polling run status "
                f"({consecutive_poll_errors}/{_GH_ACTIONS_MAX_CONSECUTIVE_POLL_ERRORS}): {exc}"
            )
            if consecutive_poll_errors >= _GH_ACTIONS_MAX_CONSECUTIVE_POLL_ERRORS:
                duration = int(time.time() - t0)
                return False, duration, "", (
                    f"Lost contact with the GitHub API after {consecutive_poll_errors} consecutive "
                    f"polling failures — run may still be in progress, check manually: {run.html_url}"
                ), True
            time.sleep(_GH_ACTIONS_POLL_SECONDS)
            continue
        _stream_run_progress(run, github_repo, github_token, printed_steps, printed_job_logs)
        if run.status == "completed":
            break
        time.sleep(_GH_ACTIONS_POLL_SECONDS)

    # One last pass — the final job(s) may have completed between the last
    # poll's status check and run.status flipping to "completed", so their
    # step transitions/log might not have been printed yet above.
    _stream_run_progress(run, github_repo, github_token, printed_steps, printed_job_logs)

    duration = int(time.time() - t0)
    success = run.conclusion == "success"
    log_text = "" if success else _download_run_log_text(run, github_token)
    stderr = "" if success else f"GitHub Actions run concluded '{run.conclusion}': {run.html_url}"
    logger.info(
        f"[Build Validation] Run {'✅ succeeded' if success else f'❌ {run.conclusion}'} "
        f"({duration}s) — {run.html_url}"
    )
    return success, duration, log_text, stderr, True



# ── Per-group validation ──────────────────────────────────────────────────────

def validate_one(
    artifact_id: str,
    adr_result: dict,
    project_path: str,
    github_token: str = "",
    github_repo: str = "",
    workflow_file: str = _DEFAULT_WORKFLOW_FILE,
    workflow_inputs: Optional[dict] = None,
    cancel_check: Optional[Callable[[], bool]] = None,
) -> BuildValidationResult:
    """
    Build-validate a single committed group. Assumes adr_result["success"]
    is True and a branch was actually created — callers should pass through
    a synthetic failed result for groups where adr_fix itself failed,
    without calling this (there's nothing to build).

    The build always runs on GitHub Actions (see _run_maven_build_via_actions):
    the branch is checked out locally then pushed to origin *before* the
    build starts (the runner can only build what's on origin) — a build
    that actually ran and failed therefore also deletes the now-stale
    branch on origin, not just the local checkout.

    If the pipeline itself couldn't be triggered (dispatch rejected, or no
    matching run ever showed up — see _run_maven_build_via_actions'
    `triggered` flag), that's treated as a skip, not a build failure: the
    branch is left pushed and unrolled-back, success=False, and
    error_reason is prefixed "SKIPPED — ..." so callers can tell the
    difference from an actual failed build.

    workflow_file must declare `on: workflow_dispatch`. workflow_inputs is
    passed through to the dispatch as-is — only pass keys the workflow
    actually declares under `on.workflow_dispatch.inputs`.
    """
    branch_name = adr_result.get("branch_name")
    base_branch = adr_result.get("base_branch")

    if cancel_check is not None and cancel_check():
        raise PipelineCancelledError(
            f"Cancelled by user before build-validating {artifact_id}"
        )

    if not branch_name:
        return BuildValidationResult(
            success=False, branch_name=None, pushed=False,
            build_time_seconds=None,
            error_reason="No branch to validate (adr_fix did not create one).",
        )

    if not github_token or not github_repo:
        return BuildValidationResult(
            success=False, branch_name=branch_name, pushed=False,
            build_time_seconds=None,
            error_reason="github_token/github_repo not provided — cannot dispatch a GitHub Actions build.",
        )

    # Clear a stale git index.lock (e.g. left behind by a previous killed/
    # timed-out run against this same project_path) before touching git,
    # so this attempt doesn't hang waiting on it.
    _clear_git_index_lock(project_path)

    ok, err = _run_git(["git", "checkout", branch_name], project_path, f"checkout {branch_name}")
    if not ok:
        return BuildValidationResult(
            success=False, branch_name=branch_name, pushed=False,
            build_time_seconds=None,
            error_reason=f"Could not check out {branch_name} for build validation: {err}",
        )
    logger.info(f"[Build Validation] Checking out {branch_name}")

    # Runner builds whatever is on origin, so the branch has to exist there
    # before we can dispatch a run against it.
    pushed, push_err = _run_git(
        ["git", "push", "-u", "origin", branch_name], project_path, "push branch (pre-build)",
    )
    if not pushed:
        return BuildValidationResult(
            success=False, branch_name=branch_name, pushed=False,
            build_time_seconds=None,
            error_reason=f"Could not push {branch_name} for remote build: {push_err}",
        )
    logger.info(f"[Build Validation] Pushed {branch_name} — dispatching {workflow_file}")

    success, duration, stdout, stderr, triggered = _run_maven_build_via_actions(
        branch_name, github_token=github_token, github_repo=github_repo,
        workflow_file=workflow_file, workflow_inputs=workflow_inputs,
        cancel_check=cancel_check,
    )

    if success:
        return BuildValidationResult(
            success=True, branch_name=branch_name, pushed=True,
            build_time_seconds=duration, error_reason=None,
        )

    if not triggered:
        # The pipeline itself never started (dispatch failed, or no matching
        # run showed up — bad token/repo/workflow_file, or workflow_dispatch
        # not declared on this branch). Not a build failure: skip validation
        # rather than rolling back a branch whose build was never attempted.
        # The branch stays pushed on origin, unvalidated.
        logger.warning(f"[Build Validation] ⚠️  Skipped — could not trigger the pipeline: {stderr}")
        return BuildValidationResult(
            success=False, branch_name=branch_name, pushed=True,
            build_time_seconds=duration,
            error_reason=f"SKIPPED — could not trigger build pipeline: {stderr}",
        )

    error_reason = _extract_maven_error(stdout, stderr) if stdout else (stderr or "Remote build failed")
    logger.error(f"[Build Validation] ❌ Remote build failed ({duration}s) — rolling back")
    logger.debug(f"[Build Validation] Error:\n{error_reason[:500]}")
    _rollback_branch(project_path, branch_name, base_branch, delete_remote=True)

    return BuildValidationResult(
        success=False,
        branch_name=None,   # branch was deleted (local + origin) — nothing downstream should reference it
        pushed=False,
        build_time_seconds=duration,
        error_reason=error_reason,
    )


# ── LangGraph node ────────────────────────────────────────────────────────────

def build_validation_node(
    state: AgentState,
    project_path: str,
    github_token: str = "",
    github_repo: str = "",
    workflow_file: str = _DEFAULT_WORKFLOW_FILE,
    workflow_inputs: Optional[dict] = None,
) -> AgentState:
    """
    LangGraph node: build_validation. Runs unconditionally after adr_fix.
    The actual `mvn` build always runs on a GitHub Actions runner (see
    validate_one / _run_maven_build_via_actions) — this node never shells
    out to mvn locally.

    Reads:  state["_adr_results"]          list of {"artifact_id", "result": AdrResult}
            state["_cancel_check"]         optional zero-arg callable
    Writes: state["_build_validation_results"]  list of {"artifact_id", "result": BuildValidationResult}
            state["build_validation_result"]     result of the first group (for routing)
            state["last_build_error"]            overwritten with this node's error, if any
            state["audit_trail"]

    workflow_file must declare `on: workflow_dispatch`. github_token /
    github_repo are required — typically the same values config.py already
    holds for pr_agent.py's PR creation.

    Raises: PipelineCancelledError if cancel_check() reports cancellation.
    """
    adr_results: list[dict] = state.get("_adr_results", [])  # type: ignore[attr-defined]
    cancel_check = state.get("_cancel_check")  # type: ignore[attr-defined]

    if not adr_results:
        logger.warning("[Build Validation] No ADR results in state — skipping")
        state["status"] = "skipped"
        state["skip_reason"] = "No committed groups to build-validate"
        state["audit_trail"].append({"node": "build_validation", "status": "skipped"})
        return state

    bv_results: list[dict] = []
    for entry in adr_results:
        artifact_id = entry["artifact_id"]
        adr_result = entry["result"]

        if not adr_result.get("success"):
            # adr_fix never committed anything for this group (no-op or commit
            # failure) — nothing to build. Pass the failure through unchanged
            # so routing/PR-gating still sees a coherent failed result.
            bv_result = BuildValidationResult(
                success=False, branch_name=None, pushed=False,
                build_time_seconds=None,
                error_reason=adr_result.get("error_reason") or "adr_fix did not commit — nothing to build",
            )
        else:
            bv_result = validate_one(
                artifact_id, adr_result, project_path,
                github_token=github_token, github_repo=github_repo,
                workflow_file=workflow_file, workflow_inputs=workflow_inputs,
                cancel_check=cancel_check,
            )

        bv_results.append({"artifact_id": artifact_id, "result": bv_result})

    first_result = bv_results[0]["result"] if bv_results else None
    state["build_validation_result"] = first_result  # type: ignore[typeddict-item]
    state["_build_validation_results"] = bv_results   # type: ignore[typeddict-unknown-key]

    # Merge the build outcome back into _adr_results / adr_result. pr_agent_node
    # (downstream in graph.py) reads state["_adr_results"] and gates PR creation
    # on result["success"] + result["branch_name"] — without this merge it would
    # still see adr_fix's "commit succeeded" result and try to open a PR against
    # a branch that build_validation just rolled back and deleted on failure.
    merged_adr_results: list[dict] = []
    for adr_entry, bv_entry in zip(adr_results, bv_results):
        ar = adr_entry["result"]
        br = bv_entry["result"]
        merged_adr_results.append({
            "artifact_id": adr_entry["artifact_id"],
            "result": {
                **ar,
                "success": br["success"],
                "branch_name": br["branch_name"],  # None if rolled back
                "build_time_seconds": br["build_time_seconds"],
                "error_reason": br["error_reason"] or ar.get("error_reason"),
            },
        })
    state["_adr_results"] = merged_adr_results  # type: ignore[typeddict-unknown-key]
    if merged_adr_results:
        state["adr_result"] = merged_adr_results[0]["result"]  # type: ignore[typeddict-item]

    state["audit_trail"].append({
        "node": "build_validation",
        "status": "ok",
        "passed": sum(1 for r in bv_results if r["result"]["success"]),
        "failed": sum(1 for r in bv_results if not r["result"]["success"]),
    })

    if first_result and not first_result["success"]:
        state["last_build_error"] = first_result["error_reason"]

    return state