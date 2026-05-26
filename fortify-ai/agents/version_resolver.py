"""
FortifyAI — Version Resolution Agent (Iteration 4)
----------------------------------------------------
Responsibility:
  For each triaged dependency group, call the Fortify recommendations endpoint
  to extract:
    - nextNonVulnerableVersion   (minimum safe version — try first)
    - greatestNonVulnerableVersion (latest safe version — try second)

  Build a deduped, ordered candidates list per dep.

Edge cases handled:
  - nextNonVulnerableVersion is null  → no safe version → mark for escalation
  - Multiple CVEs per dep             → take the highest nextNonVulnerableVersion
                                        across all vuln_ids for that dep
  - Candidate dedup                  → [next, greatest] with nulls dropped and
                                        duplicates removed (preserving order)

Console output (done-when):
  [Version] spring-context 5.3.31
            Next safe:     6.1.20
            Greatest safe: 7.0.7
            Candidates:    [6.1.20, 7.0.7]

  [Version] spring-core 5.3.31
            Next safe:     6.1.20
            Greatest safe: 7.0.7
            Candidates:    [6.1.20, 7.0.7]

  [Version] jetty-http 12.0.12
            Next safe:     12.0.15
            Greatest safe: 12.1.3
            Candidates:    [12.0.15, 12.1.3]
"""

from __future__ import annotations

from packaging.version import Version, InvalidVersion
from typing import Optional

from loguru import logger

from fortify_client import FortifyClient
from state import AgentState, VersionCandidates


# ── Version comparison helpers ────────────────────────────────────────────────

def _parse_version(v: Optional[str]) -> Optional[Version]:
    """Return a packaging.Version or None if unparseable / None."""
    if not v:
        return None
    try:
        return Version(v)
    except InvalidVersion:
        return None


def _higher_version(a: Optional[str], b: Optional[str]) -> Optional[str]:
    """Return whichever version string is higher; None if both are None."""
    va, vb = _parse_version(a), _parse_version(b)
    if va is None and vb is None:
        return None
    if va is None:
        return b
    if vb is None:
        return a
    return a if va >= vb else b


def _build_candidates(next_safe: Optional[str], greatest_safe: Optional[str]) -> list[str]:
    """
    Build a deduped ordered candidate list: [next_safe, greatest_safe].
    Nulls are dropped; duplicates removed while preserving order.
    """
    seen: set[str] = set()
    result: list[str] = []
    for v in [next_safe, greatest_safe]:
        if v and v not in seen:
            seen.add(v)
            result.append(v)
    return result


# ── Core resolution function ──────────────────────────────────────────────────

def resolve_safe_version(
    client: FortifyClient,
    release_id: int,
    vuln_id: str,
) -> dict:
    """
    Call the recommendations endpoint for one vuln_id and extract Sonatype data.

    Returns a dict with keys:
      next_safe, greatest_safe, explanation, links, candidates
    """
    rec = client.get_recommendations(release_id, vuln_id)
    sonatype = rec.get("sonatype") or {}

    return {
        "next_safe":     sonatype.get("nextNonVulnerableVersion"),
        "greatest_safe": sonatype.get("greatestNonVulnerableVersion"),
        "explanation":   sonatype.get("explanation", ""),
        "links":         sonatype.get("links") or [],
    }


def resolve_group(
    client: FortifyClient,
    release_id: int,
    group: dict,
) -> VersionCandidates:
    """
    Resolve the safe version for one triaged dependency group.

    When a dep has multiple CVEs (multiple vuln_ids), we query each and
    take the *highest* nextNonVulnerableVersion across all of them — a
    version must be safe against every CVE, not just one.

    Returns a VersionCandidates TypedDict.
    """
    artifact_id = group["parsed"]["artifact_id"]
    current_version = group["parsed"]["current_version"]
    vuln_ids: list[str] = group.get("vuln_ids", [group.get("representative_vuln_id", "")])

    best_next: Optional[str] = None
    best_greatest: Optional[str] = None
    explanation: str = ""
    links: list[str] = []

    for vuln_id in vuln_ids:
        if not vuln_id:
            continue
        try:
            rec = resolve_safe_version(client, release_id, vuln_id)
        except Exception as exc:
            logger.warning(
                f"[Version] Failed to fetch recommendations for {vuln_id}: {exc}"
            )
            continue

        # Take highest next_safe across all CVEs for this dep
        best_next = _higher_version(best_next, rec["next_safe"])
        best_greatest = _higher_version(best_greatest, rec["greatest_safe"])

        # Use the first non-empty explanation + links
        if not explanation and rec["explanation"]:
            explanation = rec["explanation"]
        if not links and rec["links"]:
            links = rec["links"]

    candidates = _build_candidates(best_next, best_greatest)

    # Console output — done-when format
    logger.info(f"[Version] {artifact_id} {current_version}")
    logger.info(f"          Next safe:     {best_next or 'N/A — no safe version found'}")
    logger.info(f"          Greatest safe: {best_greatest or 'N/A'}")
    logger.info(f"          Candidates:    {candidates}")

    return VersionCandidates(
        next_safe=best_next,
        greatest_safe=best_greatest,
        candidates=candidates,
        explanation=explanation,
        links=links,
    )


# ── Batch resolution ──────────────────────────────────────────────────────────

def resolve_all_groups(
    client: FortifyClient,
    release_id: int,
    groups: list[dict],
) -> list[dict]:
    """
    Resolve safe versions for all triaged groups.

    Returns the same groups list with a 'version_candidates' key added to each.
    Groups where no safe version exists have candidates=[] and are flagged
    for escalation via escalate_reason.
    """
    enriched: list[dict] = []

    for group in groups:
        artifact_id = group["parsed"]["artifact_id"]
        candidates_result = resolve_group(client, release_id, group)

        group = dict(group)  # shallow copy — don't mutate caller's list
        group["version_candidates"] = candidates_result

        if not candidates_result["candidates"]:
            group["escalate_reason"] = (
                f"No safe version available for {artifact_id} — "
                "nextNonVulnerableVersion is null in Fortify recommendations"
            )
            logger.warning(
                f"[Version] ⚠️  {artifact_id}: no safe version — "
                "will escalate this dep"
            )
        else:
            group.pop("escalate_reason", None)

        enriched.append(group)

    actionable = [g for g in enriched if g.get("version_candidates", {}).get("candidates")]
    escalated = [g for g in enriched if not g.get("version_candidates", {}).get("candidates")]

    logger.info(
        f"[Version] ✅ {len(actionable)} dep(s) have safe versions, "
        f"{len(escalated)} dep(s) will be escalated"
    )
    return enriched


# ── LangGraph node ────────────────────────────────────────────────────────────

def version_resolver_node(state: AgentState, client: FortifyClient) -> AgentState:
    """
    LangGraph node: version_resolver.

    Reads:  state["_triaged_groups"]   (set by triage node)
            state["release_id"]
    Writes: state["_resolved_groups"]  (triaged groups + version_candidates)
            state["audit_trail"]
    """
    groups: list[dict] = state.get("_triaged_groups", [])  # type: ignore[attr-defined]

    if not groups:
        logger.warning("[Version] No triaged groups in state — nothing to resolve")
        state["status"] = "skipped"
        state["skip_reason"] = "No triaged groups to resolve"
        state["audit_trail"].append({
            "node": "version_resolver",
            "status": "skipped",
        })
        return state

    release_id: int = state["release_id"]
    resolved = resolve_all_groups(client, release_id, groups)

    state["_resolved_groups"] = resolved  # type: ignore[typeddict-unknown-key]
    state["audit_trail"].append({
        "node": "version_resolver",
        "status": "ok",
        "groups_resolved": len(resolved),
        "escalated": [
            g["parsed"]["artifact_id"]
            for g in resolved
            if not g.get("version_candidates", {}).get("candidates")
        ],
    })

    return state
