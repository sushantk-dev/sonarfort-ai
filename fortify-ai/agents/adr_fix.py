"""
FortifyAI — ADR Fix + Build Agent (Iteration 8)
-------------------------------------------------
Responsibility:
  Invoke adr.py with --commit and --push to apply the version fix, run the
  Maven build, and push the feature branch to origin.

  adr_fortify.py invocation:
    python <adr_path> <project_path> \\
        --commit FORTIFY-<vuln_id_prefix> \\
        --push \\
        --target-versions '{"groupId:artifactId": {"safe_version": "..."}}'

  Exit 0  → parse branch name, commit hash, PDF path from stdout
  Non-zero → rollback already done by ADR; capture Maven error log for Iteration 9

  The JIRA/commit ID uses the first 8 chars of the representative_vuln_id from
  the Fortify API — e.g. FORTIFY-a4105c54 — matching the branch naming convention
  in the ADR spec: feature/FORTIFY-a4105c54_fix_YYYYMMDD

Console output (done-when):
  [ADR Fix] Applying spring-context 5.3.31 → 6.1.20
  [ADR Fix] ✅ Build passed (87s)
  [ADR Fix] ✅ Branch: feature/FORTIFY-a4105c54_fix_20260517
  [ADR Fix] ✅ Commit: 3f8a21bc
"""

from __future__ import annotations

import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from loguru import logger

from state import AgentState, AdrResult


# ── Commit ID builder ─────────────────────────────────────────────────────────

def _build_commit_id(group: dict, jira_prefix: str = "FORTIFY") -> str:
    """
    Build the JIRA-style commit ID for ADR's --commit flag.

    Uses first 8 chars of the representative_vuln_id so the branch name is
    stable and traceable back to the Fortify finding:
      FORTIFY-a4105c54
    """
    vuln_id = group.get("representative_vuln_id", "")
    short = vuln_id.replace("-", "")[:8] if vuln_id else datetime.now().strftime("%Y%m%d")
    return f"{jira_prefix}-{short}"


# ── ADR stdout parser ─────────────────────────────────────────────────────────

def _parse_adr_output(stdout: str, stderr: str) -> dict:
    """
    Extract structured data from ADR's stdout.

    ADR prints lines like:
      Branch created: feature/FORTIFY-a4105c54_fix_20260517
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
        "commit_hash": None,
        "pdf_path": None,
        "build_time_seconds": None,
    }

    for line in combined.splitlines():
        line_s = line.strip()

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


# ── ADR invocation ────────────────────────────────────────────────────────────

def invoke_adr(
    adr_path: str,
    project_path: str,
    commit_id: str,
    target_versions: dict | None = None,
) -> tuple[bool, str, str]:
    """
    Run adr_fortify.py --commit <commit_id> --push --target-versions <json>.

    target_versions: {
        "group_id:artifact_id": {
            "safe_version": "6.1.20",
            "severity":     "High",
            "cve_id":       "CVE-2024-38820"
        }, ...
    }

    Returns (success: bool, stdout: str, stderr: str).
    success=True means exit code 0 (build passed, branch pushed).
    """
    import json as _json
    cmd = [
        sys.executable, adr_path,
        project_path,
        "--commit", commit_id,
        "--push",
    ]
    if target_versions:
        cmd += ["--target-versions", _json.dumps(target_versions)]

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
        for raw in iter(proc.stdout.readline, b""):
            line = raw.decode("utf-8", errors="replace").rstrip()
            stdout_lines.append(line)
            logger.debug(f"[ADR] {line}")   # streams live to the terminal

        proc.wait()   # no timeout — wait until ADR fully completes
        elapsed = int(time.time() - t0)
        stdout_text = "\n".join(stdout_lines)

        logger.debug(f"[ADR Fix] ADR exited {proc.returncode} in {elapsed}s")
        if proc.returncode != 0:
            logger.debug(f"[ADR Fix] stdout (last 1000):\n{stdout_text[-1000:]}")
        return proc.returncode == 0, stdout_text, ""

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
) -> AdrResult:
    """
    Apply the version fix for one dependency group via ADR.

    Steps:
      1. Build commit ID from vuln_id
      2. Log the doing-when preamble
      3. Invoke adr.py --commit --push
      4. Parse stdout for branch/commit/pdf/build_time
      5. Log done-when result lines
      6. Return AdrResult
    """
    parsed = group["parsed"]
    artifact_id = parsed["artifact_id"]
    current_version = parsed["current_version"]
    candidate = group.get("current_candidate") or (
        group.get("version_candidates", {}).get("candidates", ["?"])[0]
    )

    commit_id = _build_commit_id(group, jira_prefix)

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
    logger.info(f"[ADR Fix] Commit ID: {commit_id}")
    logger.info(f"[ADR Fix] Target key: '{coord_key}' (bare fallback: '{coord_key_bare}')")

    success, stdout, stderr = invoke_adr(
        adr_path, project_path, commit_id, target_versions=target_versions
    )

    if success:
        parsed_out = _parse_adr_output(stdout, stderr)
        branch = parsed_out["branch_name"] or f"feature/{commit_id}_fix_{datetime.now().strftime('%Y%m%d')}"
        commit = parsed_out["commit_hash"] or "unknown"
        pdf = parsed_out["pdf_path"]
        build_time = parsed_out["build_time_seconds"]

        build_time_str = f"{build_time}s" if build_time else "unknown"
        logger.info(f"[ADR Fix] ✅ Build passed ({build_time_str})")
        logger.info(f"[ADR Fix] ✅ Branch: {branch}")
        logger.info(f"[ADR Fix] ✅ Commit: {commit}")
        if pdf:
            logger.info(f"[ADR Fix] ✅ PDF: {pdf}")

        return AdrResult(
            success=True,
            branch_name=branch,
            commit_hash=commit,
            pdf_path=pdf,
            build_time_seconds=build_time,
            error_reason=None,
        )

    else:
        error_reason = _extract_maven_error(stdout, stderr)
        logger.error(f"[ADR Fix] ❌ Build failed — ADR rolled back all changes")
        logger.debug(f"[ADR Fix] Error:\n{error_reason[:500]}")

        return AdrResult(
            success=False,
            branch_name=None,
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
    LangGraph node: adr_fix.

    Reads:  state["_reasoned_groups"]   (or _diff_groups as fallback)
    Writes: state["_adr_results"]       list of AdrResult dicts, one per group
            state["adr_result"]         result of the first group (for routing)
            state["audit_trail"]
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

    for group in groups:
        result = run_adr_fix(group, adr_path, project_path, jira_prefix)
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