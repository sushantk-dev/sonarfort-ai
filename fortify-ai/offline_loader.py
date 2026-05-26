"""
FortifyAI — Offline Report Loader
-----------------------------------
Loads a saved Fortify API JSON response file and returns it as the raw
vulnerability list, bypassing all live API calls.

Supported JSON shapes (auto-detected):
  1. Full API envelope:   {"items": [...], "totalCount": N, ...}
  2. Bare list:           [{"vulnId": ..., "primaryLocation": ...}, ...]
  3. Wrapped list:        {"vulnerabilities": [...]}   (some export tools)

Usage:
  python fortifyai.py --release 0 --report /path/to/report.json

When --report is given:
  - FortifyClient is NOT instantiated (no credentials needed)
  - Vulnerabilities are loaded from the JSON file
  - Version recommendations are synthesised from the data if present,
    otherwise resolved from the Fortify API using only the vuln_ids
    found in the file (requires a token) or stubbed for full offline mode
  - Writeback (post_comment) calls are suppressed — no changes to Fortify
  - All downstream pipeline stages (triage → ADR → PR) run normally

Console output:
  [Offline] Loaded 5 vulnerability/ies from /path/to/report.json
  [Offline] Release ID from file: 1723380  (overrides --release 0)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from loguru import logger


# ── JSON shape detection + normalisation ──────────────────────────────────────

def _normalise(data: object) -> list[dict]:
    """
    Accept any of the three supported JSON shapes and return a flat list
    of vulnerability dicts.

    Raises ValueError if the shape is unrecognised.
    """
    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        # Shape 1 — standard Fortify API envelope
        if "items" in data:
            items = data["items"]
            if isinstance(items, list):
                return items

        # Shape 3 — some export tools wrap under "vulnerabilities"
        for key in ("vulnerabilities", "vulns", "findings"):
            if key in data and isinstance(data[key], list):
                return data[key]

        # Shape 2 — single vulnerability wrapped in a dict (edge case)
        if "vulnId" in data or "primaryLocation" in data:
            return [data]

    raise ValueError(
        f"Unrecognised JSON shape. Expected a list or a dict with an "
        f"'items' / 'vulnerabilities' key. Got: {type(data).__name__}"
    )


def _extract_release_id(data: object) -> Optional[int]:
    """
    Try to extract the releaseId from the JSON envelope or the first item.
    Returns None if not found.
    """
    if isinstance(data, dict):
        if "releaseId" in data:
            return int(data["releaseId"])

    items = _normalise(data) if not isinstance(data, list) else data
    if items and isinstance(items[0], dict):
        rid = items[0].get("releaseId")
        if rid is not None:
            try:
                return int(rid)
            except (ValueError, TypeError):
                pass

    return None


# ── Validation ────────────────────────────────────────────────────────────────

_REQUIRED_FIELDS = {"primaryLocation", "vulnId", "checkId"}
_OPTIONAL_WITH_DEFAULTS = {
    "category":      "Open Source",
    "isSuppressed":  False,
    "auditorStatus": "Fixable OSS",
    "closedStatus":  False,
    "severityString": "High",
    "owasp2021":     "A06:2021 – Vulnerable and Outdated Components",
}


def _validate_and_patch(vuln: dict, index: int) -> dict:
    """
    Validate one vulnerability dict.
    - Warns on missing required fields (but does not drop the record).
    - Fills in optional fields with safe defaults if absent.
    """
    for field in _REQUIRED_FIELDS:
        if not vuln.get(field):
            logger.warning(
                f"[Offline] vuln[{index}] missing required field '{field}' — "
                "triage may skip this record"
            )

    for field, default in _OPTIONAL_WITH_DEFAULTS.items():
        if field not in vuln:
            vuln[field] = default

    return vuln


# ── Public loader ─────────────────────────────────────────────────────────────

def load_report(path: str) -> tuple[list[dict], Optional[int]]:
    """
    Load a Fortify report JSON file and return (vulnerabilities, release_id).

    release_id is extracted from the file if present, else None.
    The caller should fall back to the --release CLI argument when None.

    Raises:
        FileNotFoundError — path does not exist
        json.JSONDecodeError — file is not valid JSON
        ValueError — JSON shape is unrecognised
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Report file not found: {path}")

    raw = p.read_text(encoding="utf-8", errors="replace")
    data = json.loads(raw)

    release_id = _extract_release_id(data)
    vulns = _normalise(data)

    # Validate and patch each record in-place
    vulns = [_validate_and_patch(dict(v), i) for i, v in enumerate(vulns)]

    count = len(vulns)
    release_str = str(release_id) if release_id else "unknown (use --release)"
    logger.info(
        f"[Offline] Loaded {count} vulnerability/ies from {p.name}"
    )
    logger.info(f"[Offline] Release ID from file: {release_str}")

    return vulns, release_id


# ── Offline recommendations stub ──────────────────────────────────────────────

def make_offline_recommendations(vuln_id: str) -> dict:
    """
    Return a minimal recommendations dict for offline mode.
    nextNonVulnerableVersion is set to None — the version resolver will
    flag these for escalation unless --recommendations-file is also supplied.
    """
    return {
        "sonatype": {
            "nextNonVulnerableVersion":     None,
            "greatestNonVulnerableVersion": None,
            "explanation": "(offline mode — recommendations not available)",
            "links": [],
        }
    }


# ── NullFortifyClient — drop-in for offline mode ──────────────────────────────

class NullFortifyClient:
    """
    A no-op FortifyClient used when --report is active.

    - get_vulnerabilities() returns the pre-loaded list from the JSON file.
    - get_recommendations() returns the offline stub.
    - post_comment() logs a dry-run notice instead of making an API call.
    """

    def __init__(self, vulns: list[dict]) -> None:
        self._vulns = vulns

    def get_applications(self) -> list[dict]:
        return []

    def get_releases(self, application_id: int) -> list[dict]:
        return []

    def get_vulnerabilities(self, release_id: int) -> list[dict]:
        return self._vulns

    def get_recommendations(self, release_id: int, vuln_id: str) -> dict:
        logger.debug(
            f"[Offline] get_recommendations({vuln_id[:8]}) — returning stub"
        )
        return make_offline_recommendations(vuln_id)

    def post_comment(self, release_id: int, vuln_id: str, comment: str) -> dict:
        logger.info(
            f"[Offline] [DRY RUN] post_comment({vuln_id[:8]}) suppressed — "
            "no changes written to Fortify"
        )
        return {}

    def print_vulnerability_summary(self, release_id: int) -> list[dict]:
        for v in self._vulns:
            logger.info(
                f"{v.get('checkId', '?'):<20} "
                f"{v.get('primaryLocation', '?')}"
            )
        return self._vulns
