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
  - max_upgrades cap                 → applied HERE (resolve_until_fixable), not
                                        in triage: deps with no safe version are
                                        set aside for an escalation report and do
                                        NOT use up a slot — the next dep in
                                        severity order is tried instead

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

import re
from packaging.version import Version, InvalidVersion
from typing import Optional

from loguru import logger

from fortify_client import FortifyClient
from state import AgentState, VersionCandidates


# ── Version comparison helpers ────────────────────────────────────────────────
#
# Fortify/Sonatype return Maven-style version strings (e.g. "4.2.18.Final",
# "5.3.31.RELEASE", "12.0.15.jre8"). packaging.version.Version implements
# PEP 440, which rejects these qualifiers outright (InvalidVersion), so a
# naive `Version(v)` call silently loses real, valid safe-version data — the
# dep then gets wrongly escalated as "no safe version" even though Fortify
# supplied one. We normalize known Maven qualifiers before parsing, and fall
# back to a lenient numeric-tuple comparison for anything PEP 440 still
# can't handle, so a value is never dropped just because of its suffix.

# Common Maven "release" qualifiers that carry no version-ordering meaning
# on their own — safe to strip so the numeric core can be parsed.
_MAVEN_QUALIFIER_RE = re.compile(
    r"[.-](?:Final|RELEASE|GA|SEC\d*|SP\d*)$",
    flags=re.IGNORECASE,
)


def _normalize_maven_version(v: str) -> str:
    """Strip trailing Maven release qualifiers (.Final, .RELEASE, .GA, ...)."""
    return _MAVEN_QUALIFIER_RE.sub("", v)


def _numeric_tuple(v: str) -> tuple[int, ...]:
    """Fallback comparable key: pull out leading digit groups, e.g.
    '12.0.15.jre8' -> (12, 0, 15, 8)."""
    return tuple(int(x) for x in re.findall(r"\d+", v))


def _parse_version(v: Optional[str]) -> Optional[Version]:
    """Return a packaging.Version or None if unparseable / None.

    Tries the raw string first, then a Maven-qualifier-stripped version,
    before giving up. Only returns None for genuinely empty/unusable input.
    """
    if not v:
        return None
    try:
        return Version(v)
    except InvalidVersion:
        pass
    try:
        return Version(_normalize_maven_version(v))
    except InvalidVersion:
        return None


def _higher_version(a: Optional[str], b: Optional[str]) -> Optional[str]:
    """Return whichever version string is higher; None if both are None.

    Prefers comparing via packaging.Version (after Maven-qualifier
    normalization). If one or both strings still can't be parsed as a
    Version (e.g. an unusual qualifier), falls back to comparing numeric
    tuples extracted from the raw strings, rather than treating an
    unparseable-but-present value as absent.
    """
    if a is None and b is None:
        return None
    if a is None:
        return b
    if b is None:
        return a

    va, vb = _parse_version(a), _parse_version(b)
    if va is not None and vb is not None:
        return a if va >= vb else b

    # At least one side didn't parse even after normalization — fall back
    # to a lenient numeric comparison instead of silently discarding data.
    ta, tb = _numeric_tuple(a), _numeric_tuple(b)
    if not ta and not tb:
        # Neither string has any digits to compare — keep whichever came
        # first rather than losing both.
        return a
    return a if ta >= tb else b


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
    attempted = 0
    failed = 0

    for vuln_id in vuln_ids:
        if not vuln_id:
            continue
        attempted += 1
        try:
            rec = resolve_safe_version(client, release_id, vuln_id)
        except Exception as exc:
            failed += 1
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

    result = VersionCandidates(
        next_safe=best_next,
        greatest_safe=best_greatest,
        candidates=candidates,
        explanation=explanation,
        links=links,
    )
    # Every recommendations call for this dep errored — that means "we could
    # not find out", NOT "Fortify says there is no safe version". Flagged so
    # resolve_until_fixable() doesn't wrongly escalate it as unfixable.
    if attempted and failed == attempted:
        result["lookup_failed"] = True  # type: ignore[typeddict-unknown-key]
    return result


def _has_safe_version(group: dict) -> bool:
    return bool((group.get("version_candidates") or {}).get("candidates"))


def _resolve_one(client: FortifyClient, release_id: int, group: dict) -> dict:
    """Resolve one group; returns a shallow copy with version_candidates set
    and escalate_reason set (or cleared) to match."""
    artifact_id = group["parsed"]["artifact_id"]
    candidates_result = resolve_group(client, release_id, group)

    group = dict(group)  # shallow copy — don't mutate caller's list
    group["version_candidates"] = candidates_result

    if not candidates_result["candidates"]:
        group["escalate_reason"] = (
            f"No safe version available for {artifact_id} — "
            "nextNonVulnerableVersion is null in Fortify recommendations"
        )
    else:
        group.pop("escalate_reason", None)
    return group


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
        group = _resolve_one(client, release_id, group)
        if not _has_safe_version(group):
            logger.warning(
                f"[Version] ⚠️  {group['parsed']['artifact_id']}: no safe version — "
                "will escalate this dep"
            )
        enriched.append(group)

    actionable = [g for g in enriched if g.get("version_candidates", {}).get("candidates")]
    escalated = [g for g in enriched if not g.get("version_candidates", {}).get("candidates")]

    logger.info(
        f"[Version] ✅ {len(actionable)} dep(s) have safe versions, "
        f"{len(escalated)} dep(s) will be escalated"
    )
    return enriched


# Stop scanning the backlog after this many deps IN A ROW whose recommendations
# lookup failed outright — Fortify is most likely down or the token expired,
# and carrying on would just fire a request for every remaining dep.
_MAX_CONSECUTIVE_LOOKUP_FAILURES = 3


def resolve_until_fixable(
    client: FortifyClient,
    release_id: int,
    groups: list[dict],
    max_upgrades: int,
) -> dict[str, list[dict]]:
    """
    Walk the triaged backlog in severity order (highest first) and resolve
    safe versions until *max_upgrades* deps WITH a safe version are found.

    Deps with no safe version do NOT use up a max_upgrades slot — they are
    set aside (still flagged with escalate_reason, so an escalation report is
    written for them) and the next dep in the backlog is tried instead.

    max_upgrades <= 0 means no cap: every dep in the backlog is resolved.

    Returns a dict of lists:
      "fixable"        — deps with ≥1 safe candidate, len ≤ max_upgrades.
                         These continue through the pipeline.
      "no_safe"        — deps Fortify says have no safe version. Skipped by
                         the fix stages, but still get an escalation report.
      "lookup_failed"  — deps whose recommendations call itself errored. Not
                         escalated (we don't actually know they're unfixable)
                         — simply skipped this run and retried next run.
      "deferred"       — deps never looked at because the cap was already
                         filled. Picked up by a later run.
    """
    ordered = sorted(groups, key=lambda g: g.get("severity_rank", 0), reverse=True)

    fixable: list[dict] = []
    no_safe: list[dict] = []
    lookup_failed: list[dict] = []
    deferred: list[dict] = []
    consecutive_failures = 0

    for i, group in enumerate(ordered):
        if max_upgrades > 0 and len(fixable) >= max_upgrades:
            deferred = ordered[i:]
            break
        if consecutive_failures >= _MAX_CONSECUTIVE_LOOKUP_FAILURES:
            logger.error(
                f"[Version] {consecutive_failures} recommendation lookups failed in a "
                "row — Fortify looks unreachable; stopping the backlog scan here"
            )
            deferred = ordered[i:]
            break

        resolved = _resolve_one(client, release_id, group)
        artifact_id = resolved["parsed"]["artifact_id"]
        version = resolved["parsed"]["current_version"]

        if _has_safe_version(resolved):
            fixable.append(resolved)
            consecutive_failures = 0
        elif (resolved.get("version_candidates") or {}).get("lookup_failed"):
            resolved.pop("escalate_reason", None)
            lookup_failed.append(resolved)
            consecutive_failures += 1
            logger.warning(
                f"[Version] ⚠️  {artifact_id} {version}: recommendations lookup "
                "failed — skipping for this run (not escalated)"
            )
        else:
            resolved["next_node"] = "escalate"
            no_safe.append(resolved)
            consecutive_failures = 0
            logger.warning(
                f"[Version] ⏭️  {artifact_id} {version}: no safe version — "
                "escalation report will be written; moving on to the next dep"
            )

    cap = max_upgrades if max_upgrades > 0 else "unlimited"
    logger.info(
        f"[Version] ✅ {len(fixable)}/{cap} fixable dep(s) selected — "
        f"{len(no_safe)} with no safe version (escalated), "
        f"{len(lookup_failed)} lookup failure(s), "
        f"{len(deferred)} deferred to a later run"
    )
    return {
        "fixable":       fixable,
        "no_safe":       no_safe,
        "lookup_failed": lookup_failed,
        "deferred":      deferred,
    }


def summarize_groups(groups: list[dict]) -> list[dict]:
    """Compact, JSON-friendly view of a list of groups for run results / UI."""
    return [
        {
            "artifact_id":      g.get("parsed", {}).get("artifact_id"),
            "current_version":  g.get("parsed", {}).get("current_version"),
            "primary_location": g.get("primary_location"),
            "severity":         g.get("severity"),
            "cves":             g.get("cves", []),
            "reason":           g.get("escalate_reason"),
        }
        for g in groups
    ]


# ── LangGraph node ────────────────────────────────────────────────────────────

def version_resolver_node(state: AgentState, client: FortifyClient) -> AgentState:
    """
    LangGraph node: version_resolver.

    Reads:  state["_triaged_groups"]   (set by triage node — the full,
                                        severity-sorted backlog, NOT capped)
            state["max_upgrades"]      (0 = unlimited)
            state["release_id"]
    Writes: state["_resolved_groups"]         (fixable deps only, ≤ max_upgrades)
            state["_no_safe_version_groups"]  (escalated — picked up by
                                               fortify_writeback_node so they
                                               still get escalation reports)
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
    max_upgrades: int = state.get("max_upgrades", 0) or 0  # type: ignore[assignment]
    split = resolve_until_fixable(client, release_id, groups, max_upgrades)

    if split["fixable"]:
        state["_resolved_groups"] = split["fixable"]  # type: ignore[typeddict-unknown-key]
        state["_no_safe_version_groups"] = split["no_safe"]  # type: ignore[typeddict-unknown-key]
    else:
        # Nothing fixable at all. graph.py has an unconditional
        # version_resolver → context edge, so keep the old behaviour here:
        # pass the no-safe deps down the normal path, where they are
        # escalated and reported exactly as before this change.
        state["_resolved_groups"] = split["no_safe"]  # type: ignore[typeddict-unknown-key]
        state["_no_safe_version_groups"] = []  # type: ignore[typeddict-unknown-key]

    state["audit_trail"].append({
        "node": "version_resolver",
        "status": "ok",
        "groups_resolved": len(split["fixable"]),
        "max_upgrades": max_upgrades or "unlimited",
        "escalated": [g["parsed"]["artifact_id"] for g in split["no_safe"]],
        "lookup_failed": [g["parsed"]["artifact_id"] for g in split["lookup_failed"]],
        "deferred": len(split["deferred"]),
    })

    return state