"""
FortifyAI — ADR Fix Agent (Iteration 8 — commit only, build split out)
------------------------------------------------------------------------
Responsibility:
  Invoke adr.py with --commit and --skip-build to apply the version fix and
  create a local git commit on a fresh feature branch. Maven build
  verification and pushing to origin are NOT done here — see
  agents/build_validation.py (Iteration 8b), which runs immediately after
  this node in the graph and owns: mvn clean install, push-on-success,
  rollback-on-failure.

  adr_fortify.py invocation:
    python <adr_path> <project_path> \\
        --commit feature/fortify-fix-{releaseId}-{randId} \\
        --skip-build \\
        --target-versions '{"groupId:artifactId": {"safe_version": "..."}}'

  Exit 0  → parse branch name, base branch, commit hash, PDF path from stdout
  Non-zero → a commit-step failure (not a build failure — build never ran)

  The JIRA/commit ID uses the first 8 chars of the representative_vuln_id from
  the Fortify API — e.g. FORTIFY-a4105c54 — matching the branch naming convention
  in the ADR spec: feature/fortify-fix-{releaseId}-{randId}

Console output (done-when):
  [ADR Fix] Applying spring-context 5.3.31 → 6.1.20
  [ADR Fix] ✅ Committed (build not yet verified)
  [ADR Fix] ✅ Branch: feature/fortify-fix-1697672-c6266fa8 (from main)
  [ADR Fix] ✅ Commit: 3f8a21bc
"""

from __future__ import annotations

import json
import queue
import re
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from loguru import logger

from state import AgentState, AdrResult, PipelineCancelledError

# How often the subprocess-watching loop checks cancel_check() while waiting
# for ADR's stdout, and how long we give the subprocess to exit cleanly after
# SIGTERM before escalating to SIGKILL.
_CANCEL_POLL_SECONDS = 0.5
_CANCEL_GRACE_SECONDS = 10.0


# ── Branch name builder ───────────────────────────────────────────────────────

def _build_branch_name(release_id: int) -> str:
    """
    Build the canonical feature branch name.

    Format: feature/fortify-fix-{releaseId}-{randId}

    This value is passed verbatim to adr_fortify.py --commit.
    adr_fortify.py detects the 'feature/' prefix and uses it as-is,
    so both sides always produce the exact same branch name.
    """
    rand_id = uuid.uuid4().hex[:8]
    return f"feature/fortify-fix-{release_id}-{rand_id}"


# ── ADR stdout parser ─────────────────────────────────────────────────────────

def _parse_adr_output(stdout: str, stderr: str) -> dict:
    """
    Extract structured data from ADR's stdout.

    ADR prints lines like:
      Branch created: feature/fortify-fix-1697672-c6266fa8
      Commit: 3f8a21bc
      PDF report: /path/to/ADR_scan_report_20260517_143022.pdf
      Build passed in 87s
      BUILD SUCCESS     (Maven line — also accepted)

    Returns dict with keys: branch_name, commit_hash, pdf_path, build_time_seconds
    All values are Optional[str/int].
    """
    combined = stdout + "\n" + stderr
    result: dict = {
        "branch_name": None,
        "base_branch": None,     # e.g. "main" — parsed from ADR_BRANCH_INFO, needed for rollback
        "commit_hash": None,
        "pdf_path": None,
        "build_time_seconds": None,
        "fixes_applied": None,   # int parsed from "Fixes applied : N"
        "findings_count": None,  # int parsed from "Findings       : N unique package(s)"
        "machine_result": None,  # dict parsed from "ADR_MACHINE_RESULT:{...}" line, if present
    }

    for line in combined.splitlines():
        line_s = line.strip()

        # Per-dependency machine-readable result (preferred source of truth —
        # see _parse_adr_output usage below for how it overrides the fallback
        # count-based heuristics).
        if line_s.startswith("ADR_MACHINE_RESULT:"):
            try:
                result["machine_result"] = json.loads(line_s[len("ADR_MACHINE_RESULT:"):])
            except json.JSONDecodeError:
                pass
            continue

        # Branch/base-branch pair, emitted once by adr_fortify.py right after
        # branch creation. Preferred over the regex branch-name matches below —
        # this is the only source for base_branch, which build_validation needs
        # to roll back to on a failed build.
        if line_s.startswith("ADR_BRANCH_INFO:"):
            try:
                info = json.loads(line_s[len("ADR_BRANCH_INFO:"):])
                result["branch_name"] = info.get("branch") or result["branch_name"]
                result["base_branch"] = info.get("base_branch")
            except json.JSONDecodeError:
                pass
            continue

        # Branch name
        m = re.search(
            r"(?:Branch(?:\s+created)?|Pushed(?:\s+branch)?)[:\s]+\s*([\w/\-\.]+)",
            line_s, re.IGNORECASE,
        )
        if m and not result["branch_name"]:
            candidate = m.group(1).strip()
            if candidate.startswith("feature/") or "fix" in candidate.lower():
                result["branch_name"] = candidate

        # Also match "git checkout -b feature/..." lines from verbose ADR output
        m2 = re.search(r"feature/[\w\-\.]+", line_s)
        if m2 and not result["branch_name"]:
            result["branch_name"] = m2.group(0)

        # Commit hash — short SHA (7-8 hex chars) or full SHA
        m3 = re.search(
            r"(?:Commit(?:\s+hash)?|commit)[:\s]+\s*([0-9a-f]{7,40})",
            line_s, re.IGNORECASE,
        )
        if m3 and not result["commit_hash"]:
            result["commit_hash"] = m3.group(1)[:8]

        # Also catch "[main 3f8a21b]" style from git output
        m4 = re.search(r"\[(?:main|master|[\w/\-]+)\s+([0-9a-f]{7,40})\]", line_s)
        if m4 and not result["commit_hash"]:
            result["commit_hash"] = m4.group(1)[:8]

        # PDF report path
        m5 = re.search(r"([\w/\\\-\.]+ADR_scan_report[\w/\\\-\.]+\.pdf)", line_s, re.IGNORECASE)
        if m5 and not result["pdf_path"]:
            result["pdf_path"] = m5.group(1)

        # Build time in seconds
        m6 = re.search(r"(?:Build|BUILD)\s+(?:passed|SUCCESS)\s+(?:in\s+)?(\d+)\s*s", line_s, re.IGNORECASE)
        if m6 and not result["build_time_seconds"]:
            result["build_time_seconds"] = int(m6.group(1))

        # Maven "BUILD SUCCESS" with time "Total time: 1:27 min" or "87 s"
        m7 = re.search(r"Total time:\s+(?:(\d+):(\d+)\s+min|(\d+(?:\.\d+)?)\s*s)", line_s)
        if m7 and not result["build_time_seconds"]:
            if m7.group(1) is not None:
                result["build_time_seconds"] = int(m7.group(1)) * 60 + int(m7.group(2))
            elif m7.group(3) is not None:
                result["build_time_seconds"] = int(float(m7.group(3)))

        # ADR execution summary — "Fixes applied : 2   Manual needed: 0"
        m8 = re.search(r"Fixes applied\s*:\s*(\d+)", line_s, re.IGNORECASE)
        if m8 and result["fixes_applied"] is None:
            result["fixes_applied"] = int(m8.group(1))

        # ADR execution summary — "Findings       : 3 unique package(s)"
        m9 = re.search(r"Findings\s*:\s*(\d+)\s+unique", line_s, re.IGNORECASE)
        if m9 and result["findings_count"] is None:
            result["findings_count"] = int(m9.group(1))

    return result


def _extract_maven_error(stdout: str, stderr: str) -> str:
    """
    Extract the relevant error block from ADR output.
    Catches Maven build failures, Python tracebacks, and git errors.
    Capped at 4000 chars for state size.
    """
    combined = stdout + "\n" + stderr
    error_lines: list[str] = []
    capture = False

    for line in combined.splitlines():
        if any(trigger in line for trigger in (
            "BUILD FAILURE", "[ERROR]", "Traceback (most recent", "GIT ERROR", "sys.exit"
        )):
            capture = True
        if capture:
            error_lines.append(line)
        if len("\n".join(error_lines)) > 4000:
            break

    if error_lines:
        return "\n".join(error_lines)
    # fallback: return everything we have
    return combined.strip()[-3000:] if combined.strip() else "(no output captured — check adr_fortify.py directly)"


# ── Precise outcome messages ──────────────────────────────────────────────────
# One template per possible per-dependency status reported in the
# ADR_MACHINE_RESULT line. Each describes exactly what happened — no generic
# "no matching dependency" catch-all covering unrelated outcomes.
_STATUS_MESSAGES = {
    "not_found": (
        "No dependency matching '{artifact}' (checked version {current}) was found "
        "in any pom.xml — skipping commit and PR."
    ),
    "already_safe": (
        "'{artifact}' is already at the safe version {safe} in {occurrences} "
        "location(s) — no update needed, skipping commit and PR."
    ),
    "no_safe_version": (
        "'{artifact}' (current version {current}) was found, but no safe version "
        "could be resolved for it — manual review required, skipping commit and PR."
    ),
    "manual_pattern": (
        "'{artifact}' version {current} was located in pom.xml but could not be "
        "safely rewritten automatically — manual update required, skipping commit and PR."
    ),
    "skipped_by_flag": (
        "'{artifact}' was excluded from auto-fix via --skip — manual review required, "
        "skipping commit and PR."
    ),
    "pending_depmanagement_pin": (
        "'{artifact}' {current} is managed by a parent/BOM and needs a "
        "dependencyManagement pin, but the pin could not be confirmed — "
        "manual review required, skipping commit and PR."
    ),
    "unresolved": (
        "'{artifact}' (current version {current}) was located in pom.xml, but its "
        "fix outcome could not be determined — check the ADR log or PDF report, "
        "skipping commit and PR."
    ),
}


def _build_no_fix_reason(
    artifact_id: str,
    current_version: str,
    coord_key: str,
    coord_key_bare: str,
    machine_result: dict | None,
    findings_count: "int | None",
) -> str:
    """
    Build a precise, status-specific reason for why zero fixes were applied.

    Prefers the per-dependency status from ADR_MACHINE_RESULT (exact — reflects
    what actually happened to this dependency). Falls back to a generic,
    count-based message only if the running adr_fortify.py didn't emit that
    line (e.g. an older version).
    """
    entry = None
    if machine_result:
        entry = machine_result.get(coord_key) or machine_result.get(coord_key_bare)

    if entry:
        status   = entry.get("status", "unresolved")
        template = _STATUS_MESSAGES.get(status, _STATUS_MESSAGES["unresolved"])
        versions = entry.get("current_versions") or [current_version]
        return template.format(
            artifact=artifact_id,
            current=", ".join(versions),
            safe=entry.get("safe_version", "?"),
            occurrences=entry.get("occurrences", 0),
        )

    # Fallback: no machine-readable result available at all.
    return (
        f"No fix was applied for '{artifact_id}' (checked version {current_version}) "
        f"(Findings: {findings_count if findings_count is not None else 'unknown'}, "
        f"Fixes applied: 0) — skipping commit and PR."
    )


# ── ADR invocation ────────────────────────────────────────────────────────────

def invoke_adr(
    adr_path: str,
    project_path: str,
    commit_id: str,
    target_versions: dict | None = None,
    cancel_check: Optional[Callable[[], bool]] = None,
    required_jdk: Optional[str] = None,
    push: bool = False,
) -> tuple[bool, str, str]:
    """
    Run adr_fortify.py --commit <commit_id> [--push] --target-versions <json>.

    target_versions: {
        "group_id:artifact_id": {
            "safe_version": "6.1.20",
            "severity":     "High",
            "cve_id":       "CVE-2024-38820"
        }, ...
    }

    required_jdk: Java major version this project needs (from context.py's
        detect_required_jdk, via state["required_jdk"]). Forwarded to
        adr_fortify.py as --required-jdk, which looks it up in the
        FORTIFYAI_JDK_REGISTRY env var to select the right JAVA_HOME for
        this build. None/empty means adr_fortify.py inherits whatever JDK
        is already on PATH — identical to the pre-existing behaviour.

    push: forwarded to adr_fortify.py as --push. adr_fortify.py's --commit
        mode never runs a Maven build itself (that block is disabled — see
        adr_fortify.py's git commit section), so this only controls whether
        the branch is pushed to origin immediately after committing.
        - push=True  (Run Maven Build is OFF): the branch is pushed here,
          right after commit, since there's no later stage that will push it.
        - push=False (Run Maven Build is ON, the default pipeline shape):
          the branch is committed locally only — build_validation_node owns
          running 'mvn clean install' and, on success, pushing the branch
          (or on failure, rolling it back). See build_validation.py.

    cancel_check: optional zero-arg callable returning True once the job has
        been flagged for cancellation (e.g. ``lambda: store.is_cancel_requested(pid)``).
        Without this, a cancel request made while ADR's Maven build is running
        has no effect until the build finishes on its own — this is what makes
        that responsive. Checked every ``_CANCEL_POLL_SECONDS`` while streaming
        ADR's stdout (via a background reader thread, since blocking readline()
        can't be interrupted directly). On a positive check, the subprocess is
        sent SIGTERM, given ``_CANCEL_GRACE_SECONDS`` to exit, then SIGKILL'd —
        and ``PipelineCancelledError`` is raised.

        Note: terminating mid-build can leave the working tree / a partially
        pushed branch in an inconsistent state (ADR's own rollback-on-failure
        logic doesn't get a chance to run). The caller should treat a
        cancelled ADR run as "state unknown — verify manually", not as a
        clean rollback.

    Returns (success: bool, stdout: str, stderr: str).
    success=True means exit code 0 — pom.xml edited + committed locally, and,
    if push=True, pushed to origin too (adr_fortify.py exits non-zero if the
    push itself fails, so a failed push correctly surfaces as success=False
    here rather than being silently swallowed).

    Raises:
        PipelineCancelledError: if cancel_check() reports cancellation while
            the subprocess was running.
    """
    import json as _json
    cmd = [
        sys.executable, adr_path,
        project_path,
        "--commit", commit_id,
    ]
    if push:
        cmd.append("--push")
    if target_versions:

        cmd += ["--target-versions", _json.dumps(target_versions)]
    if required_jdk:
        cmd += ["--required-jdk", str(required_jdk)]

    logger.debug(f"[ADR Fix] Running: {' '.join(cmd)}")

    proc = None
    try:
        t0 = time.time()
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,   # merge stderr into stdout so we see everything
            cwd=project_path,
        )

        stdout_lines: list[str] = []

        # readline() blocks until a line arrives (or EOF), which would starve
        # our cancel_check() polling. Read on a background thread instead and
        # drain a queue with a short timeout so we can check cancellation in
        # between — without this, cancel is invisible for the entire build.
        line_queue: "queue.Queue[bytes | None]" = queue.Queue()

        def _reader() -> None:
            try:
                for raw in iter(proc.stdout.readline, b""):
                    line_queue.put(raw)
            finally:
                line_queue.put(None)  # EOF sentinel

        reader_thread = threading.Thread(target=_reader, daemon=True)
        reader_thread.start()

        cancelled = False
        while True:
            if cancel_check is not None and cancel_check():
                cancelled = True
                break
            try:
                raw = line_queue.get(timeout=_CANCEL_POLL_SECONDS)
            except queue.Empty:
                continue
            if raw is None:   # EOF — subprocess closed stdout
                break
            line = raw.decode("utf-8", errors="replace").rstrip()
            stdout_lines.append(line)
            logger.debug(f"[ADR] {line}")   # streams live to the terminal

        if cancelled:
            logger.warning(
                f"[ADR Fix] Cancellation requested — terminating ADR subprocess "
                f"(pid={proc.pid})"
            )
            proc.terminate()
            try:
                proc.wait(timeout=_CANCEL_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                logger.warning(
                    f"[ADR Fix] ADR subprocess (pid={proc.pid}) did not exit "
                    f"within {_CANCEL_GRACE_SECONDS}s of SIGTERM — sending SIGKILL"
                )
                proc.kill()
                proc.wait()
            # Best-effort: grab whatever output the reader thread already buffered.
            while True:
                try:
                    raw = line_queue.get_nowait()
                except queue.Empty:
                    break
                if raw is None:
                    break
                stdout_lines.append(raw.decode("utf-8", errors="replace").rstrip())
            logger.warning(
                "[ADR Fix] ⚠️  ADR subprocess terminated mid-run due to cancellation — "
                "branch/build/push state is UNKNOWN (ADR's own rollback did not get "
                "a chance to run). Verify the working tree and remote branch manually "
                "before retrying this dependency."
            )
            raise PipelineCancelledError(
                f"Cancelled by user while ADR build/push was in progress "
                f"(pid={proc.pid}); partial output captured for the audit log."
            )

        proc.wait()   # reader hit EOF, so this returns immediately
        elapsed = int(time.time() - t0)
        stdout_text = "\n".join(stdout_lines)

        logger.debug(f"[ADR Fix] ADR exited {proc.returncode} in {elapsed}s")
        if proc.returncode != 0:
            logger.debug(f"[ADR Fix] stdout (last 1000):\n{stdout_text[-1000:]}")
        return proc.returncode == 0, stdout_text, ""

    except PipelineCancelledError:
        raise
    except FileNotFoundError:
        logger.error(f"[ADR Fix] adr.py not found at {adr_path}")
        return False, "", f"adr.py not found at {adr_path}"
    except Exception as exc:
        logger.error(f"[ADR Fix] Unexpected error invoking ADR: {exc}")
        return False, "", str(exc)


# ── Main fix function ─────────────────────────────────────────────────────────

def run_adr_fix(
    group: dict,
    adr_path: str,
    project_path: str,
    jira_prefix: str = "FORTIFY",
    release_id: int = 0,
    cancel_check: Optional[Callable[[], bool]] = None,
    required_jdk: Optional[str] = None,
    push: bool = False,
) -> AdrResult:
    """
    Apply the version fix for one dependency group via ADR.

    Steps:
      1. Build branch name: feature/fortify-fix-{releaseId}-{randId}
      2. Log the doing-when preamble
      3. Invoke adr.py --commit [--push]
      4. Parse stdout for branch/commit/pdf/build_time
      5. Abort with success=False if ADR made 0 fixes (dep not found in poms)
      6. Log done-when result lines
      7. Return AdrResult

    required_jdk: forwarded to invoke_adr() — see its docstring.

    push: forwarded to invoke_adr() — see its docstring. Pass True when Run
        Maven Build is OFF (nothing else will push this branch), False when
        it's ON (build_validation_node pushes after a successful build).

    cancel_check: forwarded to invoke_adr() — see its docstring. If the job is
        cancelled while this group's build is running, PipelineCancelledError
        propagates out of this function (not caught here) so the pipeline
        runner can mark the whole job "cancelled" instead of "failed".
    """
    parsed = group["parsed"]
    artifact_id = parsed["artifact_id"]
    current_version = parsed["current_version"]
    candidate = group.get("current_candidate") or (
        group.get("version_candidates", {}).get("candidates", ["?"])[0]
    )

    branch_name = _build_branch_name(release_id)

    # Build the target-versions payload for adr_fortify.py.
    # Key format must match what adr_fortify.py produces when parsing pom.xml:
    # "groupId:artifactId" — both sides come from the same Fortify primaryLocation.
    # We also include an artifactId-only key as a fallback in case the pom parser
    # resolves the groupId differently (e.g. via ${project.groupId} inheritance).
    coord_key      = f"{parsed['group_id']}:{parsed['artifact_id']}"
    coord_key_bare = parsed['artifact_id']   # fallback: match on artifactId alone

    version_entry = {
        "safe_version": candidate,
        "severity":     group.get("severity", "High"),
        "cve_id":       group.get("cves", [""])[0],
    }
    target_versions = {
        coord_key:      version_entry,
        coord_key_bare: version_entry,   # bare artifactId fallback
    }

    logger.info(f"[ADR Fix] Applying {artifact_id} {current_version} → {candidate}")
    logger.info(f"[ADR Fix] Branch: {branch_name}")
    logger.info(f"[ADR Fix] Target key: '{coord_key}' (bare fallback: '{coord_key_bare}')")

    success, stdout, stderr = invoke_adr(
        adr_path, project_path, branch_name, target_versions=target_versions,
        cancel_check=cancel_check, required_jdk=required_jdk, push=push,
    )

    if success:
        parsed_out = _parse_adr_output(stdout, stderr)

        # ADR exited 0 but made no changes. Treat as a no-op: do NOT create a
        # branch, commit, or PR — but report exactly why, per-dependency.
        fixes_applied  = parsed_out["fixes_applied"]
        findings_count = parsed_out["findings_count"]
        machine_result = parsed_out["machine_result"]
        if fixes_applied is not None and fixes_applied == 0:
            reason = _build_no_fix_reason(
                artifact_id, current_version, coord_key, coord_key_bare,
                machine_result, findings_count,
            )
            logger.warning(f"[ADR Fix] ⚠️  {reason}")
            return AdrResult(
                success=False,
                branch_name=None,
                base_branch=None,
                commit_hash=None,
                pdf_path=parsed_out["pdf_path"],
                build_time_seconds=None,
                error_reason=reason,
            )

        branch = parsed_out["branch_name"] or branch_name  # use pre-built name as fallback
        base_branch = parsed_out["base_branch"]
        commit = parsed_out["commit_hash"] or "unknown"
        pdf = parsed_out["pdf_path"]

        logger.info(f"[ADR Fix] ✅ Committed" + (" and pushed" if push else " (build not yet verified)"))
        logger.info(f"[ADR Fix] ✅ Branch: {branch}" + (f" (from {base_branch})" if base_branch else ""))
        logger.info(f"[ADR Fix] ✅ Commit: {commit}")
        if pdf:
            logger.info(f"[ADR Fix] ✅ PDF: {pdf}")

        return AdrResult(
            success=True,
            branch_name=branch,
            base_branch=base_branch,
            commit_hash=commit,
            pdf_path=pdf,
            build_time_seconds=None,  # not run here — see build_validation_node
            error_reason=None,
        )

    else:
        # ADR exited non-zero. adr_fortify.py's --commit mode never runs Maven
        # itself (that block is disabled), so this is either a commit-step
        # failure (git error, unexpected exception, backup-restore failure)
        # or — when push=True — a failed 'git push' (adr_fortify.py exits 1
        # on push failure too, so both surface here the same way).
        error_reason = _extract_maven_error(stdout, stderr)
        logger.error(f"[ADR Fix] ❌ {'Commit/push' if push else 'Commit'} step failed — see error below")
        logger.debug(f"[ADR Fix] Error:\n{error_reason[:500]}")

        return AdrResult(
            success=False,
            branch_name=None,
            base_branch=None,
            commit_hash=None,
            pdf_path=None,
            build_time_seconds=None,
            error_reason=error_reason,
        )


# ── LangGraph node ────────────────────────────────────────────────────────────

def adr_fix_node(
    state: AgentState,
    adr_path: str,
    project_path: str,
    jira_prefix: str = "FORTIFY",
) -> AgentState:
    """
    LangGraph node: adr_fix. Commit-only — does NOT build or push. Always
    followed unconditionally by build_validation (see graph.py), which runs
    the actual Maven build and decides push vs. rollback.

    Reads:  state["_reasoned_groups"]   (or _diff_groups as fallback)
            state["_cancel_check"]      optional zero-arg callable — see
                                         invoke_adr()'s docstring. Not required;
                                         without it this node behaves as before
                                         (cancel has no effect mid-commit).
    Writes: state["_adr_results"]       list of AdrResult dicts, one per group
                                         (success here means "committed", not
                                         "build passed")
            state["adr_result"]         result of the first group (for routing)
            state["audit_trail"]

    Raises: PipelineCancelledError if cancel_check() reports cancellation —
            propagates uncaught so the caller can mark the job "cancelled".
    """
    groups: list[dict] = (
        state.get("_reasoned_groups")  # type: ignore[attr-defined]
        or state.get("_diff_groups")   # type: ignore[attr-defined]
        or []
    )

    if not groups:
        logger.warning("[ADR Fix] No groups in state — skipping")
        state["status"] = "skipped"
        state["skip_reason"] = "No groups to fix"
        state["audit_trail"].append({"node": "adr_fix", "status": "skipped"})
        return state

    adr_results: list[dict] = []
    release_id: int = state.get("release_id", 0)  # type: ignore[attr-defined]
    cancel_check = state.get("_cancel_check")  # type: ignore[attr-defined]
    required_jdk = state.get("required_jdk")  # type: ignore[attr-defined] — set by context_node

    for group in groups:
        if cancel_check is not None and cancel_check():
            raise PipelineCancelledError("Cancelled by user before starting next ADR group")
        result = run_adr_fix(
            group, adr_path, project_path, jira_prefix,
            release_id=release_id, cancel_check=cancel_check,
            required_jdk=required_jdk,
        )
        adr_results.append({
            "artifact_id": group["parsed"]["artifact_id"],
            "result": result,
        })

    # Expose the first result on top-level state for routing in graph.py
    first_result = adr_results[0]["result"] if adr_results else None
    state["adr_result"] = first_result  # type: ignore[typeddict-item]

    state["_adr_results"] = adr_results  # type: ignore[typeddict-unknown-key]
    state["audit_trail"].append({
        "node": "adr_fix",
        "status": "ok",
        "passed": sum(1 for r in adr_results if r["result"]["success"]),
        "failed": sum(1 for r in adr_results if not r["result"]["success"]),
    })

    if first_result and not first_result["success"]:
        state["last_build_error"] = first_result["error_reason"]

    return state