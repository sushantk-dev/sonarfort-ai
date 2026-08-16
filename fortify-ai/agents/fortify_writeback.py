"""
FortifyAI — Escalation Report Writer (replaces Fortify Writeback)
------------------------------------------------------------------
Behaviour change:
  - NO comments are posted back to Fortify SSC (writeback removed entirely)
  - Escalated groups are written to a local folder as individual report files
  - Fixed groups are logged to console only

Escalation report file:
  {output_dir}/escalation_{artifact_id}_{timestamp}.txt

File content:
  [FortifyAI] Escalated — manual action required
  Dependency: org.springframework:spring-context 5.3.31
  CVEs:       CVE-2024-38820, CVE-2025-22233
  Reason:     No safe version available from Fortify recommendations
  Tried:      (none)
  ...

Console output:
  [Report] ✅ spring-context fixed — branch: feature/FORTIFY-a4105c54_fix_20260517
  [Report] 📄 Escalation report written: escalation_no-fix-available_20260523_160000.txt
  [Report] ✅ Done — fixed=2, escalated=1
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from loguru import logger

from state import AgentState

try:  # flat layout (token_tracker.py at repo root, next to state.py)
    from token_tracker import token_tracker
except ImportError:  # package layout
    from agents.token_tracker import token_tracker  # type: ignore


# ── LLM-generated next steps ──────────────────────────────────────────────────

_NEXT_STEPS_SYSTEM = """You are a senior Java security engineer writing an escalation report for a
developer who needs to manually fix a vulnerable Maven dependency.

You will be given the full context of what the automated pipeline tried and why
it failed. Write 4-6 concrete, specific, numbered action steps the developer
should take — tailored to THIS failure, not a generic checklist.

Rules:
- Be specific: reference actual class names, methods, versions, CVEs given.
- If the build failed due to a broken API, name the API and suggest an alternative.
- If no safe version exists, say so explicitly and suggest a mitigation path.
- If at-risk call sites are listed, reference them by file name.
- Write plain text only — no markdown, no bullet symbols, just numbered lines.
- Maximum 6 steps. Each step one sentence.
- Start each step with the step number and a period, e.g. "1. ..."
"""

_NEXT_STEPS_USER = """Dependency:        {group_id}:{artifact_id} {current_version}
CVEs:              {cves}
Severity:          {severity}
Escalation reason: {reason}
Versions tried:    {tried}
AI confidence:     {confidence}
At-risk files:     {at_risk}
Breaking changes:  {breaking_count}
Last build error (truncated):
{build_error}
Sonatype explanation:
{explanation}

Write the specific next steps for the developer.
"""


def _generate_next_steps_llm(
    group: dict,
    reason: str,
    build_error: str,
    tried_str: str,
    gcp_project: str,
    gcp_location: str,
) -> Optional[str]:
    """
    Call the LLM to generate specific, tailored next steps for the escalation
    report. Returns an indented numbered-list string, or None if the LLM is
    unavailable or returns an unusable response.

    Reuses _build_llm from ai_reasoning so there is one LLM init path.
    Falls back transparently — callers always get a usable report.
    """
    try:
        from ai_reasoning import _build_llm          # flat layout
    except ImportError:
        try:
            from agents.ai_reasoning import _build_llm  # package layout
        except ImportError:
            logger.debug("[Report] ai_reasoning not importable — skipping LLM next steps")
            return None

    llm = _build_llm(gcp_project, gcp_location, max_output_tokens=512)
    if llm is None:
        return None

    parsed       = group["parsed"]
    ai_reasoning = group.get("ai_reasoning", {})
    api_diff     = group.get("api_diff", {})
    explanation  = (group.get("version_candidates") or {}).get("explanation", "(not available)")

    at_risk     = ai_reasoning.get("at_risk_lines", [])
    at_risk_str = ", ".join(at_risk[:5]) if at_risk else "(none identified)"

    prompt = _NEXT_STEPS_USER.format(
        group_id        = parsed["group_id"],
        artifact_id     = parsed["artifact_id"],
        current_version = parsed["current_version"],
        cves            = ", ".join(group.get("cves", [])) or "(see Fortify finding)",
        severity        = group.get("severity", "Unknown"),
        reason          = reason[:500],
        tried           = tried_str,
        confidence      = ai_reasoning.get("confidence", "unknown"),
        at_risk         = at_risk_str,
        breaking_count  = api_diff.get("breaking_count", 0),
        build_error     = build_error[:800] if build_error
                          else "(no build error — escalated before build)",
        explanation     = explanation[:600],
    )

    try:
        from langchain_core.messages import HumanMessage, SystemMessage  # type: ignore
        messages = [
            SystemMessage(content=_NEXT_STEPS_SYSTEM),
            HumanMessage(content=prompt),
        ]
        t0       = time.time()
        response = llm.invoke(messages)
        latency  = time.time() - t0
        token_tracker.record(
            "fortify-writeback", response, model=getattr(llm, "model_name", None),
        )
        text     = response.content if hasattr(response, "content") else str(response)
        logger.debug(f"[Report] LLM next steps generated ({latency:.1f}s, {len(text)} chars)")

        # Validate — must start at least one numbered line
        if not re.search(r"^\d+\.", text.strip(), re.MULTILINE):
            logger.debug("[Report] LLM response lacked numbered steps — using fallback")
            return None

        # Indent each line for report formatting
        return "\n".join(f"  {line}" for line in text.strip().splitlines())

    except Exception as exc:
        logger.debug(f"[Report] LLM next steps call failed: {exc} — using fallback")
        return None


# ── Report content builders ───────────────────────────────────────────────────

def _fixed_summary(
    group: dict,
    adr_result: dict,
    pr_result: dict,
) -> str:
    """One-line console summary for a successfully fixed dependency."""
    parsed      = group["parsed"]
    artifact_id = parsed["artifact_id"]
    current_ver = parsed["current_version"]
    candidate   = group.get("current_candidate") or (
        group.get("version_candidates", {}).get("candidates", ["?"])[0]
    )
    branch      = adr_result.get("branch_name", "unknown")
    pr_url      = pr_result.get("pr_url", "")
    pr_part     = f" | PR: {pr_url}" if pr_url else ""
    return (
        f"{artifact_id} {current_ver} → {candidate} "
        f"| branch: {branch}{pr_part}"
    )


def _escalation_report(
    group: dict,
    escalation_reason: Optional[str],
    adr_results: list[dict],
    gcp_project: str = "",
    gcp_location: str = "us-central1",
    is_jdk_mismatch: bool = False,
    required_jdk: Optional[str] = None,
    ai_code_fix_reason: Optional[str] = None,
) -> str:
    """
    Build the full escalation report text for one dependency group.
    Written to disk as a plain-text file.

    When gcp_project is supplied the Next Steps section is generated by the
    LLM and tailored to the specific failure. Falls back to the generic
    hardcoded steps when Vertex AI is unavailable or gcp_project is empty.
    """
    parsed      = group["parsed"]
    group_id    = parsed["group_id"]
    artifact_id = parsed["artifact_id"]
    current_ver = parsed["current_version"]
    cves        = group.get("cves", [])
    candidates  = group.get("version_candidates", {}).get("candidates", [])
    tried_str   = ", ".join(candidates) if candidates else "(none)"
    reason      = (
        escalation_reason
        or group.get("escalate_reason")
        or "Automated fix was not possible"
    )
    # ai_code_fix_reason may arrive as an explicit param (graph.py's single
    # state-per-run flow) or live on the group dict itself (api_server.py's
    # REST flow mutates the same group object across stages) — either works.
    effective_ai_code_fix_reason = ai_code_fix_reason or group.get("ai_code_fix_reason")

    # Gather retry attempts from adr_results if available
    adr = next(
        (r["result"] for r in adr_results
         if r["artifact_id"] == artifact_id),
        {}
    )
    build_error = adr.get("error_reason", "")

    ai_reasoning = group.get("ai_reasoning", {})
    confidence   = ai_reasoning.get("confidence", "")
    at_risk      = ai_reasoning.get("at_risk_lines", [])

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "=" * 60,
        "[FortifyAI] Escalated — manual action required",
        "=" * 60,
        "",
        f"Dependency:  {group_id}:{artifact_id}",
        f"Version:     {current_ver}",
        f"CVEs:        {', '.join(cves) or '(see Fortify finding)'}",
        f"OWASP:       {group.get('owasp_2021', 'A06:2021')}",
        f"Severity:    {group.get('severity', 'Unknown')}",
        "",
        "── Escalation Reason ──────────────────────────────────",
        reason,
        "",
        "── What Was Tried ─────────────────────────────────────",
        f"Candidates:  {tried_str}",
    ]

    if confidence:
        lines += [f"AI confidence: {confidence}"]
    if at_risk:
        lines += [f"At-risk lines: {', '.join(at_risk[:5])}"]

    if is_jdk_mismatch:
        lines += [
            "",
            "── Detected Cause ─────────────────────────────────────",
            "JDK / toolchain version mismatch — the build environment used a "
            "different Java version than this project requires. This is an "
            "environment problem, not a code problem: FortifyAI's AI Code Fix "
            "was skipped because no source patch can resolve it.",
        ]
        if required_jdk:
            lines += [f"Project requires JDK: {required_jdk}"]

    # AI Code Fix is only relevant for code-level failures — a JDK mismatch
    # is an environment problem and AI Code Fix is skipped for it entirely
    # (already covered by the "Detected Cause" section above), so only show
    # this section for the code-patch-attempted path.
    if effective_ai_code_fix_reason and not is_jdk_mismatch:
        lines += [
            "",
            "── AI Code Fix ─────────────────────────────────────────",
            "FortifyAI attempted to generate and apply an AI source patch to "
            "fix the build, but could not produce a working fix:",
            effective_ai_code_fix_reason,
        ]

    if build_error:
        lines += [
            "",
            "── Cause of Build Failure ──────────────────────────────",
            build_error[:2000],
        ]

    # ── Next Steps: LLM-generated (specific) or hardcoded (generic fallback) ──
    lines += ["", "── Next Steps ─────────────────────────────────────────"]

    llm_steps = None
    if gcp_project:
        llm_steps = _generate_next_steps_llm(
            group, reason, build_error, tried_str, gcp_project, gcp_location
        )

    if llm_steps:
        lines += [
            llm_steps,
            "  (steps generated by FortifyAI based on this specific failure)",
        ]
    elif is_jdk_mismatch:
        lines += [
            f"  1. Install/select JDK {required_jdk} for this project"
            if required_jdk else
            "  1. Determine the JDK version this project's pom.xml expects "
            "(maven.compiler.release/source/target or java.version)",
            "  2. Point JAVA_HOME / the build agent's toolchain at that JDK version",
            "  3. Re-run the build locally with mvn -v to confirm the active JDK matches",
            "  4. Re-trigger FortifyAI once the correct JDK is available in this "
            "environment — no dependency or source change is needed",
        ]
    else:
        lines += [
            "  1. Review the Sonatype recommendation in Fortify SSC",
            "  2. Check whether a patched version exists on Maven Central",
            "  3. Consider a mitigating control if no safe version is available",
            "  4. Contact the dependency maintainer if the CVE is unpatched",
            "  5. Manually update the pom.xml and run mvn clean verify",
        ]

    lines += [
        "",
        f"Timestamp:   {ts}",
        "=" * 60,
    ]

    return "\n".join(lines)


# ── File writer ────────────────────────────────────────────────────────────────

import os as _os

_GCS_BUCKET         = _os.environ.get("GCS_BUCKET", "").strip()
_GCS_ESC_PREFIX     = _os.environ.get("GCS_ESCALATION_PREFIX", "escalations/").rstrip("/") + "/"

# Reused across calls — constructing google.cloud.storage.Client() does an
# auth/credential handshake, so building a fresh one per write is wasteful.
_gcs_client_singleton = None


def _get_gcs_client():
    global _gcs_client_singleton
    if _gcs_client_singleton is None:
        from google.cloud import storage
        _gcs_client_singleton = storage.Client()
    return _gcs_client_singleton


def _get_gcs_bucket():
    """
    Return (bucket, bucket_name) when GCS_BUCKET env var is set, else (None, None).
    Uses Workload Identity on GKE — no key file needed.
    Refreshes env var on every call so hot-updates via os.environ work, but
    reuses a single cached storage.Client() instance.
    """
    name = _os.environ.get("GCS_BUCKET", "").strip()
    if not name:
        return None, None
    try:
        client = _get_gcs_client()
        return client.bucket(name), name
    except Exception as exc:
        logger.warning(f"[Report] GCS unavailable ({exc}) — falling back to local filesystem")
        return None, None


def write_escalation_report(
    group: dict,
    escalation_reason: Optional[str],
    adr_results: list[dict],
    output_dir: str,
    gcp_project: str = "",
    gcp_location: str = "us-central1",
    pipeline_id: str | None = None,
    is_jdk_mismatch: bool = False,
    required_jdk: Optional[str] = None,
    ai_code_fix_reason: Optional[str] = None,
) -> Optional[str]:
    """
    Write the escalation report.

    GCS mode (GCS_BUCKET set — required in production / multi-pod):
        gs://{GCS_BUCKET}/{GCS_ESCALATION_PREFIX}escalation_{artifact_id}_{ts}.txt
        On upload failure the report is NOT written locally — a local file
        would be invisible to other pods and to the GCS-backed /escalations
        endpoints, silently reintroducing per-pod state. The failure is
        surfaced (returns None → counted as failed in the run summary).

    Local mode (GCS_BUCKET unset — single-pod development only):
        {output_dir}/escalation_{artifact_id}_{ts}.txt

    Idempotency: when *pipeline_id* is supplied (the api_server pipeline
    runner always passes it), the filename is deterministic —
    escalation_{artifact_id}_{pipeline_id}.txt — instead of timestamp-based,
    and an existing report for that (artifact_id, pipeline_id) pair is
    reused rather than regenerated. This matters because fortify-writeback
    runs last and is NOT checkpoint-skippable the way earlier stages are:
    if a resume re-enters the pipeline at fortify-writeback (or a caller
    retries the same pipeline_id), the previous timestamp-based filename
    scheme would silently write a second escalation report for the same
    finding. Individual /stages/fortify-writeback calls (no pipeline_id)
    keep the original timestamp-based filename for backward compatibility.

    Returns the GCS URI or local file path on success, None on failure.
    """
    artifact_id = group["parsed"]["artifact_id"]
    if pipeline_id:
        filename = f"escalation_{artifact_id}_{pipeline_id}.txt"
    else:
        ts       = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"escalation_{artifact_id}_{ts}.txt"
    text        = _escalation_report(
        group, escalation_reason, adr_results, gcp_project, gcp_location,
        is_jdk_mismatch=is_jdk_mismatch, required_jdk=required_jdk,
        ai_code_fix_reason=ai_code_fix_reason,
    )

    # Fields the /escalations list endpoint needs — stashed as blob metadata
    # so listing can read them straight off list_blobs() without a separate
    # download_as_bytes() round-trip per file.
    cves       = group.get("cves", [])
    candidates = group.get("version_candidates", {}).get("candidates", [])
    reason     = (
        escalation_reason
        or group.get("escalate_reason")
        or "Automated fix was not possible"
    )
    esc_metadata = {
        "artifact_id": artifact_id,
        "cves":        ",".join(cves),
        "reason":      reason[:1500],  # metadata values have a size limit
        "tried":       ",".join(candidates),
        "severity":    str(group.get("severity", "Unknown")),
        "ai_code_fix_reason": (ai_code_fix_reason or group.get("ai_code_fix_reason") or "")[:1500],
    }

    # ── GCS mode (sole path when a bucket is configured) ─────────────────────
    if _os.environ.get("GCS_BUCKET", "").strip():
        bucket, bucket_name = _get_gcs_bucket()
        if bucket is None:
            logger.error(
                "[Report] GCS_BUCKET is set but the bucket is unreachable — "
                "escalation report NOT written (no local fallback in GCS mode)"
            )
            return None
        prefix    = _os.environ.get("GCS_ESCALATION_PREFIX", "escalations/").rstrip("/") + "/"
        blob_name = prefix + filename
        if pipeline_id:
            existing = bucket.blob(blob_name)
            try:
                if existing.exists():
                    uri = f"gs://{bucket_name}/{blob_name}"
                    logger.info(
                        f"[Report] ↩️  Escalation report already exists for this "
                        f"pipeline run — reusing {uri} instead of regenerating"
                    )
                    return uri
            except Exception as exc:
                logger.debug(f"[Report] Existence check failed for {blob_name}: {exc} — proceeding to write")
        try:
            blob = bucket.blob(blob_name)
            blob.metadata = esc_metadata
            blob.upload_from_string(text.encode("utf-8"), content_type="text/plain")
            uri = f"gs://{bucket_name}/{blob_name}"
            logger.info(f"[Report] 📄 Escalation report uploaded: {uri}")
            return uri
        except Exception as exc:
            logger.error(
                f"[Report] GCS upload failed ({exc}) — escalation report NOT "
                f"written (no local fallback in GCS mode)"
            )
            return None

    # ── Local mode (single-pod / local dev only) ─────────────────────────────
    out_dir = Path(output_dir)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.error(f"[Report] Cannot create output dir {output_dir}: {exc}")
        return None

    file_path = out_dir / filename
    if pipeline_id and file_path.exists():
        logger.info(
            f"[Report] ↩️  Escalation report already exists for this "
            f"pipeline run — reusing {file_path} instead of regenerating"
        )
        return str(file_path)
    try:
        file_path.write_text(text, encoding="utf-8")
        logger.info(f"[Report] 📄 Escalation report written (local): {file_path}")
        return str(file_path)
    except OSError as exc:
        logger.error(f"[Report] Failed to write {file_path}: {exc}")
        return None


# ── Main dispatch ─────────────────────────────────────────────────────────────

def run_all_reports(
    groups: list[dict],
    adr_results: list[dict],
    pr_results: list[dict],
    output_dir: str,
    escalation_reason: Optional[str] = None,
    gcp_project: str = "",
    gcp_location: str = "us-central1",
    pipeline_id: str | None = None,
    is_jdk_mismatch: bool = False,
    required_jdk: Optional[str] = None,
    ai_code_fix_reason: Optional[str] = None,
) -> dict:
    """
    For each group:
      - Fixed   → log to console
      - Escalated → write report file to output_dir

    Returns summary dict: total_fixed, total_escalated, total_failed,
                          escalation_files (list of written paths)
    """
    adr_by_artifact = {r["artifact_id"]: r["result"] for r in adr_results}

    pr_by_artifact: dict[str, dict] = {}
    pr_idx = 0
    for g in groups:
        art = g["parsed"]["artifact_id"]
        if adr_by_artifact.get(art, {}).get("success") and pr_idx < len(pr_results):
            pr_by_artifact[art] = pr_results[pr_idx]
            pr_idx += 1

    total_fixed      = 0
    total_escalated  = 0
    total_failed     = 0
    escalation_files: list[str] = []

    for group in groups:
        art        = group["parsed"]["artifact_id"]
        adr_result = adr_by_artifact.get(art, {})
        pr_result  = pr_by_artifact.get(art, {})

        if adr_result.get("success"):
            summary = _fixed_summary(group, adr_result, pr_result)
            logger.info(f"[Report] ✅ {summary}")
            total_fixed += 1
        else:
            reason = (
                group.get("escalate_reason")
                or escalation_reason
                or adr_result.get("error_reason")
                or "Automated fix was not possible"
            )
            path = write_escalation_report(
                group, reason, adr_results, output_dir, gcp_project, gcp_location,
                pipeline_id=pipeline_id,
                is_jdk_mismatch=is_jdk_mismatch, required_jdk=required_jdk,
                # Explicit param (single-state pipeline run) OR per-group
                # field (REST flow, set directly on the group dict) — either
                # way write_escalation_report/_escalation_report fall back
                # to group.get("ai_code_fix_reason") if this is None.
                ai_code_fix_reason=ai_code_fix_reason,
            )
            if path:
                total_escalated += 1
                escalation_files.append(path)
            else:
                total_failed += 1

    logger.info(
        f"[Report] ✅ Done — "
        f"fixed={total_fixed}, "
        f"escalated={total_escalated}, "
        f"failed={total_failed}"
    )
    if escalation_files:
        logger.info(f"[Report] Escalation reports in: {output_dir}")

    return {
        "total_fixed":       total_fixed,
        "total_escalated":   total_escalated,
        "total_failed":      total_failed,
        "escalation_files":  escalation_files,
    }


# ── LangGraph node ────────────────────────────────────────────────────────────

def fortify_writeback_node(
    state: AgentState,
    output_dir: str,
    gcp_project: str = "",
    gcp_location: str = "us-central1",
) -> AgentState:
    """
    LangGraph node: fortify_writeback (now an escalation report writer).

    Reads:  state["_reasoned_groups"]
            state["_adr_results"]
            state["_all_pr_results"]
            state["escalation_reason"]
            state["ai_code_fix_failure_reason"]  (optional — surfaced as its
                                                    own report section)
            state["_gcp_project"]      (optional — enables LLM next steps)
            state["_gcp_location"]     (optional)
    Writes: state["status"]            → "fixed" or "escalated"
            state["_escalation_files"] → list of written report paths
            state["audit_trail"]
    """
    groups: list[dict] = (
        state.get("_reasoned_groups")  # type: ignore[attr-defined]
        or state.get("_diff_groups")   # type: ignore[attr-defined]
        or []
    )
    adr_results: list[dict] = state.get("_adr_results", [])    # type: ignore[attr-defined]
    pr_results:  list[dict] = state.get("_all_pr_results", []) # type: ignore[attr-defined]
    escalation_reason       = state.get("escalation_reason")
    is_jdk_mismatch         = bool(state.get("is_jdk_mismatch"))   # type: ignore[attr-defined]
    required_jdk            = state.get("required_jdk")            # type: ignore[attr-defined]
    ai_code_fix_reason      = state.get("ai_code_fix_failure_reason")  # type: ignore[attr-defined]

    # Pick up GCP config from state if not injected as arg directly.
    # graph.py stores these on state the same way it does for ai_reasoning_node.
    effective_gcp_project  = gcp_project  or state.get("_gcp_project", "")            # type: ignore[attr-defined]
    effective_gcp_location = gcp_location or state.get("_gcp_location", "us-central1") # type: ignore[attr-defined]

    if not groups:
        logger.warning("[Report] No groups in state — nothing to report")
        state["audit_trail"].append({"node": "fortify_writeback", "status": "skipped"})
        return state

    summary = run_all_reports(
        groups=groups,
        adr_results=adr_results,
        pr_results=pr_results,
        output_dir=output_dir,
        escalation_reason=escalation_reason,
        gcp_project=effective_gcp_project,
        gcp_location=effective_gcp_location,
        is_jdk_mismatch=is_jdk_mismatch,
        required_jdk=required_jdk,
        ai_code_fix_reason=ai_code_fix_reason,
    )

    if summary["total_fixed"] > 0:
        state["status"] = "fixed"
    if summary["total_escalated"] > 0:
        state["status"] = "escalated"

    state["_escalation_files"] = summary["escalation_files"]  # type: ignore[typeddict-unknown-key]
    state["audit_trail"].append({
        "node": "fortify_writeback",
        "status": "ok",
        **{k: v for k, v in summary.items() if k != "escalation_files"},
        "escalation_files": summary["escalation_files"],
    })

    return state