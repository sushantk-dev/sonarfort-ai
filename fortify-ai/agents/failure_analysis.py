"""
FortifyAI — Failure Analysis Agent (Iteration 9a)
---------------------------------------------------
Responsibility:
  When ADR returns a non-zero exit code, parse the Maven build error log to:

  1. Identify the failing Java file(s) and exact line number(s)
  2. Cross-reference with the API diff (which methods were removed/changed)
  3. Extract ±50 lines of context around each failure site
  4. Determine whether to retry (attempt AI code fix), advance to the next
     candidate version, or escalate

  Retry budget: max_retries (default 3) attempts per candidate.
  After exhausting attempts on current candidate → advance to next candidate.
  After exhausting all candidates → escalate.

Console output:
  [Failure] spring-context build failed (attempt 1/3)
  [Failure] Failing file: DataBinderService.java:42
  [Failure] Error: cannot find symbol — method setDisallowedFields(String[])
  [Failure] → routing to AI Code Fix
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from loguru import logger

from state import AgentState


# ── Maven error pattern library ───────────────────────────────────────────────

# Patterns that extract (file_path, line_number, message) from Maven output
_ERROR_PATTERNS = [
    # [ERROR] /path/to/File.java:[42,10] error: cannot find symbol
    re.compile(
        r"\[ERROR\]\s+([\w/\\\.\-]+\.java):\[(\d+),\d+\]\s+error:\s*(.+)",
        re.IGNORECASE,
    ),
    # [ERROR] /path/to/File.java:42: error: cannot find symbol
    re.compile(
        r"\[ERROR\]\s+([\w/\\\.\-]+\.java):(\d+):\s+error:\s*(.+)",
        re.IGNORECASE,
    ),
    # COMPILATION ERROR : /abs/path/File.java
    re.compile(
        r"(?:COMPILATION ERROR|ERROR)\s*:?\s*([\w/\\\.\-]+\.java)",
        re.IGNORECASE,
    ),
]

# Patterns that identify a symbol-not-found error referencing an API change
_SYMBOL_PATTERNS = [
    re.compile(r"cannot find symbol.*?(?:method|class|field)\s+([\w\.]+)", re.IGNORECASE | re.DOTALL),
    re.compile(r"symbol:\s+(?:method|class|field)\s+([\w\.<>]+)", re.IGNORECASE),
    re.compile(r"(?:method|field|class)\s+'([\w\.]+)'\s+(?:not found|undefined|cannot be resolved)", re.IGNORECASE),
    re.compile(r"incompatible types.*?([\w\.]+)", re.IGNORECASE),
]


# ── Error parser ──────────────────────────────────────────────────────────────

class FailureSite:
    """One failing location extracted from the Maven error log."""

    def __init__(
        self,
        file_path: str,
        line_number: Optional[int],
        error_message: str,
        missing_symbol: Optional[str] = None,
    ) -> None:
        self.file_path = file_path
        self.line_number = line_number
        self.error_message = error_message
        self.missing_symbol = missing_symbol

    def __repr__(self) -> str:
        loc = f"{Path(self.file_path).name}:{self.line_number}" if self.line_number else Path(self.file_path).name
        return f"FailureSite({loc}: {self.error_message[:60]})"


def parse_maven_errors(error_log: str) -> list[FailureSite]:
    """
    Extract all failing FailureSites from a Maven build error log.
    Deduplicates by (file, line).
    """
    sites: list[FailureSite] = []
    seen: set[tuple] = set()

    for line in error_log.splitlines():
        for pattern in _ERROR_PATTERNS:
            m = pattern.search(line)
            if not m:
                continue

            groups = m.groups()
            file_path = groups[0] if groups else ""
            line_num = int(groups[1]) if len(groups) > 1 and groups[1] and groups[1].isdigit() else None
            error_msg = groups[2] if len(groups) > 2 else line.strip()

            # Extract missing symbol if present
            missing_sym = None
            for sp in _SYMBOL_PATTERNS:
                sm = sp.search(error_log[max(0, error_log.find(line) - 100):error_log.find(line) + 300])
                if sm:
                    missing_sym = sm.group(1).split(".")[-1]  # short name only
                    break

            key = (file_path, line_num)
            if key not in seen:
                seen.add(key)
                sites.append(FailureSite(file_path, line_num, error_msg.strip(), missing_sym))
            break  # stop after first pattern match for this line

    return sites


def extract_code_context(
    project_path: Path,
    file_path: str,
    line_number: Optional[int],
    context: int = 50,
) -> str:
    """
    Return ±context lines around line_number from file_path.
    Falls back to the whole file (first 100 lines) if line_number is None.
    """
    # Resolve absolute path
    candidates = [
        Path(file_path),
        project_path / file_path,
        *list(project_path.rglob(Path(file_path).name)),
    ]

    source_lines: list[str] = []
    for candidate in candidates:
        if candidate.exists():
            try:
                source_lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
                break
            except OSError:
                continue

    if not source_lines:
        return f"(could not read {file_path})"

    if line_number is None:
        snippet = source_lines[:100]
    else:
        start = max(0, line_number - context // 2 - 1)
        end = min(len(source_lines), line_number + context // 2)
        snippet = source_lines[start:end]

    numbered = [
        f"{start + i + 1:4d} | {l}"
        for i, l in enumerate(snippet)
    ]
    return "\n".join(numbered)


# ── Routing decision ──────────────────────────────────────────────────────────

def decide_retry_route(
    state: AgentState,
    max_retries: int = 3,
) -> str:
    """
    Determine next routing step after a build failure.

    Logic:
      retry_count < max_retries  → "retry"     (AI code fix then ADR again)
      retry_count >= max_retries and next candidate exists → "next"
      no more candidates → "escalate"
    """
    retry_count = state.get("retry_count", 0)
    candidate_index = state.get("candidate_index", 0)

    # Pick the first group to inspect (all groups share the same candidate pool)
    groups: list[dict] = (
        state.get("_reasoned_groups")   # type: ignore[attr-defined]
        or state.get("_diff_groups")    # type: ignore[attr-defined]
        or []
    )
    if not groups:
        return "escalate"

    all_candidates: list[str] = (
        groups[0].get("version_candidates", {}).get("candidates", [])
    )
    next_candidate_index = candidate_index + 1

    if retry_count < max_retries:
        return "retry"

    if next_candidate_index < len(all_candidates):
        return "next"

    return "escalate"


# ── LangGraph node ────────────────────────────────────────────────────────────

def failure_analysis_node(state: AgentState, project_path: str, max_retries: int = 3) -> AgentState:
    """
    LangGraph node: failure_analysis.

    Reads:  state["last_build_error"]   — Maven error log from adr_fix_node
            state["retry_count"]
            state["candidate_index"]
    Writes: state["_failure_sites"]     — parsed FailureSite list (as dicts)
            state["_failure_context"]   — code context string for AI Code Fix
            state["retry_count"]        — incremented
            state["audit_trail"]
    """
    error_log = state.get("last_build_error", "") or ""
    retry_count = state.get("retry_count", 0)

    groups: list[dict] = (
        state.get("_reasoned_groups")  # type: ignore[attr-defined]
        or state.get("_diff_groups")   # type: ignore[attr-defined]
        or []
    )
    artifact_id = groups[0]["parsed"]["artifact_id"] if groups else "unknown"
    candidate_index = state.get("candidate_index", 0)
    candidates: list[str] = (
        groups[0].get("version_candidates", {}).get("candidates", []) if groups else []
    )
    current_candidate = candidates[candidate_index] if candidate_index < len(candidates) else "?"

    attempt_num = retry_count + 1
    logger.info(
        f"[Failure] {artifact_id} build failed "
        f"(attempt {attempt_num}/{max_retries})"
    )

    # Parse error log
    sites = parse_maven_errors(error_log)

    if sites:
        for site in sites[:3]:
            loc = f"{Path(site.file_path).name}:{site.line_number}" if site.line_number else Path(site.file_path).name
            logger.info(f"[Failure] Failing file: {loc}")
            logger.info(f"[Failure] Error: {site.error_message[:120]}")
    else:
        logger.warning("[Failure] Could not parse specific error locations from log")

    # Extract code context for AI Code Fix
    proj = Path(project_path)
    context_parts: list[str] = []
    for site in sites[:3]:
        ctx = extract_code_context(proj, site.file_path, site.line_number)
        if ctx:
            context_parts.append(
                f"// {site.file_path}:{site.line_number}\n"
                f"// Error: {site.error_message}\n{ctx}"
            )
    failure_context = "\n\n".join(context_parts) or error_log[:2000]

    # Increment retry counter
    state["retry_count"] = retry_count + 1

    # Determine route
    route = decide_retry_route(state, max_retries)
    logger.info(f"[Failure] → routing to {'AI Code Fix' if route == 'retry' else route.upper()}")

    # Store parsed data for AI Code Fix agent
    state["_failure_sites"] = [  # type: ignore[typeddict-unknown-key]
        {
            "file_path": s.file_path,
            "line_number": s.line_number,
            "error_message": s.error_message,
            "missing_symbol": s.missing_symbol,
        }
        for s in sites
    ]
    state["_failure_context"] = failure_context   # type: ignore[typeddict-unknown-key]
    state["_retry_route"] = route                  # type: ignore[typeddict-unknown-key]

    state["audit_trail"].append({
        "node": "failure_analysis",
        "attempt": attempt_num,
        "sites": len(sites),
        "route": route,
        "candidate": current_candidate,
    })

    return state
