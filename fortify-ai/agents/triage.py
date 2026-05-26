"""
FortifyAI — Triage Agent (Iteration 3)
----------------------------------------
Responsibility:
  1. Filter out findings that should NOT be remediated.
  2. Group the remaining valid findings by dependency (primaryLocation),
     collecting all CVEs per dep so we fix once and close many.

Filter rules (applied in order):
  - isSuppressed == true         → skip
  - category != "Open Source"    → skip
  - auditorStatus != "Fixable OSS" → skip
  - closedStatus == true         → skip

Output (per unique dep kept):
  {
    "primary_location": "org.springframework:spring-context@5.3.31",
    "parsed": { group_id, artifact_id, current_version },
    "cves": ["CVE-2024-38820", "CVE-2025-22233"],
    "vuln_ids": ["uuid-1", "uuid-2"],
    "severity": "High",           ← highest across all CVEs for this dep
    "owasp_2021": "A06:2021 – Vulnerable and Outdated Components",
    "representative_vuln_id": "uuid-1",  ← used for recommendations lookup
  }

Console output (done-when):
  [Triage] spring-context 5.3.31  ✅ 2 CVEs — proceed
  [Triage] spring-core    5.3.31  ✅ 1 CVE  — proceed
  [Triage] jetty-http     12.0.12 ✅ 1 CVE  — proceed
"""

from __future__ import annotations

from typing import Any

from loguru import logger

from fortify_client import parse_primary_location
from state import AgentState

# ── Severity ordering (higher index = higher severity) ────────────────────────
_SEVERITY_RANK: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


# ── Core filter ───────────────────────────────────────────────────────────────

def should_skip(vuln: dict) -> tuple[bool, str]:
    """
    Return (True, reason) if the finding should be skipped,
    or (False, "Valid — proceed") if it should be remediated.
    """
    if vuln.get("isSuppressed", False):
        return True, "Already suppressed"

    if vuln.get("category", "") != "Open Source":
        return True, f"Not an OSS finding (category={vuln.get('category')})"

    if vuln.get("auditorStatus", "") != "Fixable OSS":
        return True, f"Status: {vuln.get('auditorStatus')}"

    if vuln.get("closedStatus", False):
        return True, "Already closed"

    return False, "Valid — proceed"


# ── Grouping ──────────────────────────────────────────────────────────────────

def group_by_dependency(vulns: list[dict]) -> list[dict[str, Any]]:
    """
    Group valid vulnerabilities by primaryLocation.
    Returns one record per unique dep, with all CVEs and vuln_ids collected.
    """
    dep_map: dict[str, dict[str, Any]] = {}

    skipped_count = 0
    kept_count = 0

    for vuln in vulns:
        skip, reason = should_skip(vuln)
        loc = vuln.get("primaryLocation", "")
        cve = vuln.get("checkId", "")
        vuln_id = vuln.get("vulnId", str(vuln.get("id", "")))
        severity_str = vuln.get("severityString", "High").lower()

        if skip:
            skipped_count += 1
            logger.debug(f"[Triage] SKIP {cve or loc}: {reason}")
            continue

        kept_count += 1

        if loc not in dep_map:
            try:
                parsed = parse_primary_location(loc)
            except ValueError:
                parsed = {
                    "group_id": "",
                    "artifact_id": loc,
                    "current_version": "?",
                }
            dep_map[loc] = {
                "primary_location": loc,
                "parsed": parsed,
                "cves": [],
                "vuln_ids": [],
                "severity_rank": 0,
                "severity": "High",  # fallback
                "owasp_2021": vuln.get("owasp2021", ""),
                "representative_vuln_id": vuln_id,
            }

        entry = dep_map[loc]

        # Collect CVEs (dedup)
        if cve and cve not in entry["cves"]:
            entry["cves"].append(cve)

        # Collect vuln IDs (dedup)
        if vuln_id and vuln_id not in entry["vuln_ids"]:
            entry["vuln_ids"].append(vuln_id)

        # Track highest severity across all CVEs for this dep
        rank = _SEVERITY_RANK.get(severity_str, 2)
        if rank > entry["severity_rank"]:
            entry["severity_rank"] = rank
            entry["severity"] = vuln.get("severityString", "High")

    logger.info(
        f"[Triage] {len(vulns)} total findings → "
        f"{kept_count} kept, {skipped_count} skipped"
    )

    groups = list(dep_map.values())

    # Print done-when console output
    for g in groups:
        artifact_id = g["parsed"]["artifact_id"]
        version = g["parsed"]["current_version"]
        cve_count = len(g["cves"])
        cve_word = "CVE" if cve_count == 1 else "CVEs"
        logger.info(
            f"[Triage] {artifact_id:<22} {version:<12} "
            f"✅ {cve_count} {cve_word} — proceed"
        )

    return groups


def apply_max_upgrades(groups: list[dict[str, Any]], max_upgrades: int) -> list[dict[str, Any]]:
    """
    Cap the number of dependencies forwarded for remediation.

    Groups are sorted by severity (Critical → High → Medium → Low) so the
    highest-risk items are always processed first when a limit is in effect.

    Args:
        groups:       Output of group_by_dependency().
        max_upgrades: Maximum number of deps to keep.  0 = no limit.

    Returns:
        Filtered (and severity-sorted) list, length ≤ max_upgrades.
    """
    if not groups:
        return groups

    # Always sort by severity so output order is deterministic even without a cap
    sorted_groups = sorted(
        groups,
        key=lambda g: g.get("severity_rank", 0),
        reverse=True,  # highest severity first
    )

    if max_upgrades <= 0:
        return sorted_groups

    capped = sorted_groups[:max_upgrades]
    dropped = len(sorted_groups) - len(capped)
    if dropped:
        logger.info(
            f"[Triage] ⚠️  max_upgrades={max_upgrades} — "
            f"capping to {len(capped)} dep(s), {dropped} lower-severity dep(s) deferred"
        )
    return capped


# ── LangGraph node ────────────────────────────────────────────────────────────

def triage_node(state: AgentState) -> AgentState:
    """
    LangGraph node: triage.

    Reads:  state["_raw_vulnerabilities"]  (list of raw API dicts, set by
            the fetch step in fortifyai.py before invoking the graph)
    Writes: state["_triaged_groups"]       (list[dict] from group_by_dependency)
            state["status"]                ("skipped" if nothing to process)
            state["audit_trail"]           (appended)
    """
    raw: list[dict] = state.get("_raw_vulnerabilities", [])  # type: ignore[attr-defined]

    if not raw:
        logger.warning("[Triage] No raw vulnerabilities in state — nothing to triage")
        state["status"] = "skipped"
        state["skip_reason"] = "No vulnerabilities returned by Fortify API"
        state["audit_trail"].append({
            "node": "triage",
            "status": "skipped",
            "reason": state["skip_reason"],
        })
        return state

    groups = group_by_dependency(raw)

    if not groups:
        logger.warning("[Triage] All findings filtered out — nothing to remediate")
        state["status"] = "skipped"
        state["skip_reason"] = "All findings suppressed, closed, or non-OSS"
        state["audit_trail"].append({
            "node": "triage",
            "status": "skipped",
            "reason": state["skip_reason"],
            "input_count": len(raw),
        })
        return state

    # Apply optional cap — sorts by severity regardless of whether a limit is set
    max_upgrades: int = state.get("max_upgrades", 0)  # type: ignore[assignment]
    groups = apply_max_upgrades(groups, max_upgrades)

    # Store grouped results back into state for downstream nodes
    state["_triaged_groups"] = groups  # type: ignore[typeddict-unknown-key]
    state["audit_trail"].append({
        "node": "triage",
        "status": "ok",
        "input_count": len(raw),
        "output_groups": len(groups),
        "max_upgrades": max_upgrades or "unlimited",
        "deps": [g["parsed"]["artifact_id"] for g in groups],
    })

    logger.info(
        f"[Triage] ✅ {len(groups)} unique dep(s) queued for remediation"
    )
    return state