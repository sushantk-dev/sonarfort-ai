"""
FortifyAI — Build Validation Agent (Iteration 10 — local build)
------------------------------------------------------------------
Responsibility:
  Runs immediately after adr_fix in the graph. adr_fix only edits pom.xml
  and creates a local git commit on a fresh feature branch — this node
  owns everything downstream of that commit:

    1. Check out the branch adr_fix just committed.
    2. Run 'mvn clean install' LOCALLY on this pod, via adr_fortify.py's
       own _run_maven_build() — the same heap-capped, thread-safety-aware
       Maven runner adr_fortify.py's own --fix/--commit modes use.
       Imported directly rather than reimplemented here, so there's
       exactly one Maven-invocation implementation in this codebase to
       keep in sync (heap sizing, timeout, JDK selection, the
       single-threaded retry-on-failure fallback for parallel reactor
       builds — all of that lives in adr_fortify.py; this module just
       calls it).
    3. On success → push the branch to origin now. A branch is only ever
       pushed once its build has already succeeded locally — unlike the
       previous remote-dispatch design, nothing unbuilt/broken ever
       reaches origin. pr_agent only opens a PR for a group whose
       build_validation result is a *pushed* branch (this node overwrites
       state["_adr_results"]/state["adr_result"] in place with the merged
       outcome, since pr_agent_node downstream still reads those keys —
       see the "Merge" comment in build_validation_node).
    4. On failure → roll the branch back: checkout base_branch, delete the
       feature branch locally. No remote cleanup needed — the branch was
       never pushed in the first place, since push only happens after a
       successful build (see step 3).

  Why local instead of a remote GitHub Actions dispatch (as this file used
  to do, Iteration 9): running mvn directly on this pod removes the extra
  network round-trip, workflow-file coupling, and remote-runner queue
  time — at the cost of needing this pod's own JDK/Maven/proxy/Nexus
  settings to be correctly configured. See adr_fortify.py's
  --java-home/--required-jdk handling and _build_subprocess_env for how
  JDK selection and the MAVEN_OPTS heap cap are applied to that local
  subprocess.

  Known limitation vs. the old remote path: _run_maven_build() streams
  Maven's output straight to this process's stdout/logs (for live
  visibility) but does not capture and return it as a string, so
  error_reason on a build failure here is a short summary, not an
  extracted Maven error snippet — the actual failure text is only in the
  pipeline pod's own console/log output, not in the BuildValidationResult
  itself. If you want that back, _run_maven_build would need to also
  capture and return its output text (currently prints only).

Console output (done-when):
  [Build Validation] Checking out feature/fortify-fix-1697672-c6266fa8
  [Build Validation] Running mvn clean install locally...
  [Build Validation]   [INFO] Scanning for projects...
  [Build Validation]   ...
  [Build Validation] ✅ Build succeeded (87s) — pushed feature/fortify-fix-1697672-c6266fa8
"""

from __future__ import annotations

import os
import subprocess
from typing import Callable, Optional

from loguru import logger

from state import AgentState, BuildValidationResult, PipelineCancelledError

try:  # flat layout (adr_fortify.py at repo root, next to state.py)
    from adr_fortify import _run_maven_build, _DEFAULT_MAVEN_HEAP_MB
except ImportError:  # package layout
    from agents.adr_fortify import _run_maven_build, _DEFAULT_MAVEN_HEAP_MB  # type: ignore


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


def _rollback_branch(project_path: str, branch_name: str, base_branch: Optional[str]) -> None:
    """
    Discard a feature branch whose local build failed: checkout base,
    delete the local branch. No remote cleanup is needed here — unlike the
    previous GitHub-Actions-dispatch design (which had to push before a
    remote runner could even attempt the build, so a failed build had
    already reached origin), a branch is only ever pushed AFTER its build
    has already succeeded locally (see validate_one), so a failed build
    never reaches origin in the first place.
    """
    target = base_branch or "main"
    ok, _ = _run_git(["git", "checkout", target], project_path, f"checkout {target}")
    if not ok and target != "master":
        _run_git(["git", "checkout", "master"], project_path, "checkout master (fallback)")
    _run_git(["git", "branch", "-D", branch_name], project_path, f"delete {branch_name}")
    logger.warning(f"[Build Validation] ⚠️  Rolled back — deleted local branch {branch_name}")


# ── Per-group validation ──────────────────────────────────────────────────────

def validate_one(
    artifact_id: str,
    adr_result: dict,
    project_path: str,
    mvn_exe: str = "",
    skip_tests: bool = False,
    java_home: str = "",
    build_threads: str = "1C",
    maven_heap_mb: int = _DEFAULT_MAVEN_HEAP_MB,
    cancel_check: Optional[Callable[[], bool]] = None,
) -> BuildValidationResult:
    """
    Build-validate a single committed group by running 'mvn clean install'
    LOCALLY on this pod (via adr_fortify.py's _run_maven_build — see module
    docstring), then push the branch on success or roll it back on failure.

    Assumes adr_result["success"] is True and a branch was actually
    created — callers should pass through a synthetic failed result for
    groups where adr_fix itself failed, without calling this (there's
    nothing to build).

    mvn_exe / java_home / build_threads / maven_heap_mb: forwarded as-is to
    _run_maven_build — see its docstring in adr_fortify.py. maven_heap_mb
    in particular is the MAVEN_OPTS -Xmx cap applied to this subprocess
    (default from adr_fortify.py's own _DEFAULT_MAVEN_HEAP_MB); 0 disables
    the cap and restores the JVM's own default heap sizing.

    cancel_check is honored BEFORE the local Maven subprocess starts (same
    as every other cancel_check use in this pipeline). Once
    _run_maven_build is actually running, it is NOT interruptible — it's a
    plain blocking subprocess call with its own internal 600s timeout and
    no cancellation hook, so a cancel request made mid-build has no effect
    until that subprocess finishes or times out on its own. This mirrors
    the same trade-off adr_fix.py's local-subprocess calls document
    elsewhere in this pipeline.
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

    logger.info("[Build Validation] Running mvn clean install locally...")
    success, duration = _run_maven_build(
        project_path, mvn_exe=mvn_exe, skip_tests=skip_tests,
        java_home=java_home, build_threads=build_threads,
        maven_heap_mb=maven_heap_mb,
    )

    if success is None:
        # Maven not found on this pod — nothing was actually attempted.
        # Treat like the old remote path's "could not trigger the
        # pipeline" case: skip rather than roll back an otherwise-fine
        # commit just because this pod can't validate it.
        logger.warning("[Build Validation] ⚠️  Skipped — Maven ('mvn') not found on this pod")
        return BuildValidationResult(
            success=False, branch_name=branch_name, pushed=False,
            build_time_seconds=None,
            error_reason="SKIPPED — Maven ('mvn') not found on this pod; branch left committed but unpushed.",
        )

    build_time_seconds = int(round(duration)) if duration is not None else None

    if success:
        pushed, push_err = _run_git(
            ["git", "push", "-u", "origin", branch_name], project_path, "push branch (post-build)",
        )
        if not pushed:
            return BuildValidationResult(
                success=False, branch_name=branch_name, pushed=False,
                build_time_seconds=build_time_seconds,
                error_reason=f"Build succeeded but could not push {branch_name}: {push_err}",
            )
        logger.info(
            f"[Build Validation] ✅ Build succeeded ({build_time_seconds}s) — pushed {branch_name}"
        )
        return BuildValidationResult(
            success=True, branch_name=branch_name, pushed=True,
            build_time_seconds=build_time_seconds, error_reason=None,
        )

    # success is False — Maven ran locally and the build itself failed.
    logger.error(f"[Build Validation] ❌ Local build failed ({build_time_seconds}s) — rolling back")
    _rollback_branch(project_path, branch_name, base_branch)

    return BuildValidationResult(
        success=False,
        branch_name=None,   # branch was deleted locally — nothing downstream should reference it
        pushed=False,
        build_time_seconds=build_time_seconds,
        error_reason=(
            f"Local Maven build failed after {build_time_seconds}s — see the pipeline "
            f"pod's console/log output for the actual Maven error (not captured into "
            f"this result; see module docstring's 'Known limitation')."
        ),
    )


# ── LangGraph node ────────────────────────────────────────────────────────────

def build_validation_node(
    state: AgentState,
    project_path: str,
    mvn_exe: str = "",
    skip_tests: bool = False,
    java_home: str = "",
    build_threads: str = "1C",
    maven_heap_mb: int = _DEFAULT_MAVEN_HEAP_MB,
) -> AgentState:
    """
    LangGraph node: build_validation. Runs unconditionally after adr_fix.
    The 'mvn' build now runs LOCALLY on this pod via adr_fortify.py's
    _run_maven_build() — see module docstring for why this changed from
    the previous remote GitHub-Actions-dispatch design (Iteration 9).

    Reads:  state["_adr_results"]          list of {"artifact_id", "result": AdrResult}
            state["_cancel_check"]         optional zero-arg callable
    Writes: state["_build_validation_results"]  list of {"artifact_id", "result": BuildValidationResult}
            state["build_validation_result"]     result of the first group (for routing)
            state["last_build_error"]            overwritten with this node's error, if any
            state["audit_trail"]

    mvn_exe / java_home / build_threads / maven_heap_mb: forwarded to
    _run_maven_build for every group — see validate_one's docstring.

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
                mvn_exe=mvn_exe, skip_tests=skip_tests,
                java_home=java_home, build_threads=build_threads,
                maven_heap_mb=maven_heap_mb, cancel_check=cancel_check,
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