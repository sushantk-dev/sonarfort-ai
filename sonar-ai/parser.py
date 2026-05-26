"""
SonarAI — Sonar Report Parser
Reads sonar-report.json (issues[]) and returns filtered, sorted SonarIssue dicts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from loguru import logger

from state import SonarIssue

# Issues with these statuses are not actionable
_SKIP_STATUSES = {"WONTFIX", "FALSE_POSITIVE", "CLOSED", "RESOLVED"}

# Severity order (lower index = higher priority)
_SEVERITY_ORDER = {
    "BLOCKER": 0,
    "CRITICAL": 1,
    "MAJOR": 2,
    "MINOR": 3,
    "INFO": 4,
}


def parse_sonar_report(report_path: str | Path) -> list[SonarIssue]:
    """
    Parse a sonar-report.json file and return a priority-sorted list of issues.

    Args:
        report_path: Path to the Sonar report JSON file.

    Returns:
        List of SonarIssue dicts, sorted BLOCKER → CRITICAL → MAJOR → MINOR → INFO.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the JSON structure is missing the 'issues' key.
    """
    path = Path(report_path)
    if not path.exists():
        raise FileNotFoundError(f"Sonar report not found: {path}")

    with path.open("r", encoding="utf-8") as fh:
        data: dict[str, Any] = json.load(fh)

    if "issues" not in data:
        raise ValueError(
            f"Sonar report is missing 'issues' key. Found keys: {list(data.keys())}"
        )

    raw_issues: list[dict[str, Any]] = data["issues"]
    logger.info(f"Loaded {len(raw_issues)} total issues from {path.name}")

    parsed: list[SonarIssue] = []
    skipped = 0

    for raw in raw_issues:
        status = raw.get("status", "OPEN").upper()
        if status in _SKIP_STATUSES:
            skipped += 1
            continue

        # component format: "project-key:src/main/java/com/example/Foo.java"
        component = raw.get("component", "")
        line = raw.get("line", 0)

        issue: SonarIssue = {
            "key": raw.get("key", ""),
            "rule_key": raw.get("rule_key", ""),
            "severity": raw.get("severity", "MAJOR").upper(),
            "component": component,
            "line": int(line) if line else 0,
            "message": raw.get("message", ""),
            "status": status,
            "effort": raw.get("effort", ""),
        }
        parsed.append(issue)

    logger.info(
        f"Kept {len(parsed)} actionable issues, skipped {skipped} "
        f"(WONTFIX/FALSE_POSITIVE/CLOSED/RESOLVED)"
    )

    # Sort by severity priority
    parsed.sort(key=lambda i: _SEVERITY_ORDER.get(i["severity"], 99))

    return parsed


def load_rule_kb(kb_path: str | Path | None = None) -> dict[str, Any]:
    """
    Load the rule knowledge base JSON.

    Search order when kb_path is not specified:
    1. data/rule_kb.json relative to this source file's parent  (sonar_ai/../data/)
    2. data/rule_kb.json relative to cwd  (handles flat layouts and Windows path quirks)
    3. rule_kb.json in the same directory as this file (last resort)

    Returns:
        Dict mapping rule_key → rule metadata dict.
    """
    if kb_path is None:
        candidates = [
            Path(__file__).resolve().parent.parent / "data" / "rule_kb.json",
            Path.cwd() / "data" / "rule_kb.json",
            Path(__file__).resolve().parent / "rule_kb.json",
        ]
        for candidate in candidates:
            if candidate.exists():
                kb_path = candidate
                break
        else:
            tried = "\n  ".join(str(c) for c in candidates)
            logger.warning(f"Rule KB not found. Tried:\n  {tried}\nReturning empty KB.")
            return {}

    kb_path = Path(kb_path)
    if not kb_path.exists():
        logger.warning(f"Rule KB not found at {kb_path}, returning empty KB")
        return {}

    with kb_path.open("r", encoding="utf-8") as fh:
        kb: dict[str, Any] = json.load(fh)

    logger.info(f"Loaded rule KB with {len(kb)} entries from {kb_path.name}")
    return kb