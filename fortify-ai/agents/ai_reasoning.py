"""
FortifyAI — AI Reasoning Agent (Iteration 7)
----------------------------------------------
Responsibility:
  Judge whether a proposed version upgrade is safe for THIS specific codebase
  given the API diff results and the actual calling code.

  Uses ChatVertexAI (claude-sonnet-4-5 on Vertex AI Model Garden, with
  gemini-1.5-pro-002 as fallback) and LangChain's JsonOutputParser.

Routing output:
  High confidence + safe    → ADR Fix directly (Iteration 8)
  Medium / Low confidence   → AI Code Fix first (Iteration 9)
  Unsafe                    → try next candidate, or escalate

Output schema (JSON):
  {
    "safe":                 true | false,
    "confidence":           "high" | "medium" | "low",
    "at_risk_lines":        ["Service.java:42", "Config.java:88"],
    "reason":               "Brief human-readable explanation",
    "pre_fix_required":     true | false,
    "recommended_candidate": "6.1.20"
  }

Console output:
  [AI Reasoning] spring-context 5.3.31 → 6.1.20
                 Safe: true   Confidence: medium
                 Reason: Major version jump — DataBinder API changed
                 At risk: Service.java:42, Config.java:88
                 Pre-fix required: true
"""

from __future__ import annotations

import json
import re
import time
from typing import Optional

from loguru import logger

from state import AgentState, AiReasoningResult

# ── Prompt template ───────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are a senior Java security engineer specialising in dependency upgrade safety.
You are given:
  - A vulnerable Maven dependency and the proposed safe upgrade version
  - The CVEs being fixed and Sonatype's explanation of the vulnerability
  - The japicmp API diff output (breaking changes between old and new JAR)
  - The actual Java calling code from the codebase that uses this dependency

Your job is to assess whether the upgrade is safe for THIS specific codebase.

You MUST respond with a single valid JSON object — no preamble, no markdown fences,
no trailing text. The JSON must have exactly these fields:

{
  "safe":                  <boolean — true if upgrade can proceed>,
  "confidence":            <"high" | "medium" | "low">,
  "at_risk_lines":         <list of "FileName.java:lineNumber" strings, or []>,
  "reason":                <1-2 sentence explanation>,
  "pre_fix_required":      <boolean — true if calling code needs patching first>,
  "recommended_candidate": <the version string you recommend trying, e.g. "6.1.20">
}

Confidence rules:
  high   — no breaking changes touch this codebase's calling code; upgrade is drop-in
  medium — breaking changes exist but the calling code can be adapted; needs review
  low    — significant risk; unclear if calling code can be adapted without deep changes

If japicmp output says "unavailable", assume safe=true with confidence=medium and
note in the reason that the diff could not be run.
"""

_USER_PROMPT_TEMPLATE = """\
Vulnerable dependency: {group_id}:{artifact_id} {current_version} → {candidate}

CVEs being fixed:
{cve_list}

Sonatype explanation:
{explanation}

japicmp API diff ({breaking_count} breaking change(s)):
{api_diff}

Calling code from this codebase:
{calling_code}

Assess the upgrade safety and respond in JSON only.
"""


# ── LLM initialisation ────────────────────────────────────────────────────────

def _build_llm(gcp_project: str, gcp_location: str, max_output_tokens: int = 1024):
    """
    Build a ChatVertexAI instance.
    Tries claude-sonnet-4-5 first, falls back to gemini-1.5-pro-002.
    Returns the LLM object or None if Vertex AI is unavailable.

    max_output_tokens:
      1024  — default, sufficient for AI Reasoning JSON verdict (~6 fields)
      4096  — use for AI Code Fix, which may return multi-patch JSON responses
               that silently truncate and fail json.loads() at 1024 tokens
    """
    try:
        import vertexai  # type: ignore
        from langchain_google_vertexai import ChatVertexAI  # type: ignore

        vertexai.init(project=gcp_project, location=gcp_location)

        try:
            llm = ChatVertexAI(
                model_name="claude-sonnet-4-5@20251001",
                max_output_tokens=max_output_tokens,
                temperature=0.1,          # low temp for deterministic JSON
            )
            logger.debug("[AI Reasoning] Using claude-sonnet-4-5 on Vertex AI")
            return llm
        except Exception as exc:
            logger.warning(
                f"[AI Reasoning] claude-sonnet-4-5 unavailable ({exc}) — "
                "falling back to gemini-1.5-pro-002"
            )
            llm = ChatVertexAI(
                model_name="gemini-1.5-pro-002",
                max_output_tokens=max_output_tokens,
                temperature=0.1,
            )
            logger.debug("[AI Reasoning] Using gemini-1.5-pro-002 on Vertex AI")
            return llm

    except ImportError:
        logger.warning(
            "[AI Reasoning] langchain-google-vertexai not installed — "
            "will use heuristic fallback"
        )
        return None
    except Exception as exc:
        logger.warning(f"[AI Reasoning] Vertex AI init failed: {exc}")
        return None


# ── JSON extraction ───────────────────────────────────────────────────────────

def _extract_json(text: str) -> Optional[dict]:
    """
    Extract the first JSON object from an LLM response.
    Handles markdown fences, leading/trailing text.
    """
    # Strip markdown fences
    text = re.sub(r"```(?:json)?", "", text).strip()

    # Find the outermost { ... }
    start = text.find("{")
    end = text.rfind("}") + 1
    if start == -1 or end == 0:
        return None

    candidate = text[start:end]
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        return None


def _validate_result(data: dict, recommended_candidate: str) -> AiReasoningResult:
    """
    Validate and normalise the LLM JSON output into AiReasoningResult.
    Fills in safe defaults for missing or invalid fields.
    """
    safe = bool(data.get("safe", True))
    confidence = str(data.get("confidence", "medium")).lower()
    if confidence not in ("high", "medium", "low"):
        confidence = "medium"

    at_risk = data.get("at_risk_lines", [])
    if not isinstance(at_risk, list):
        at_risk = []
    at_risk = [str(l) for l in at_risk]

    reason = str(data.get("reason", "No reason provided"))[:500]
    pre_fix = bool(data.get("pre_fix_required", False))
    rec = str(data.get("recommended_candidate", recommended_candidate))

    return AiReasoningResult(
        safe=safe,
        confidence=confidence,
        at_risk_lines=at_risk,
        reason=reason,
        pre_fix_required=pre_fix,
        recommended_candidate=rec,
    )


# ── Heuristic fallback ────────────────────────────────────────────────────────

def _heuristic_reasoning(
    group: dict,
    candidate: str,
) -> AiReasoningResult:
    """
    Pure-logic fallback when Vertex AI is unavailable.

    Rules:
    - No breaking changes → safe=True, confidence=high
    - Breaking changes but no affected_lines → safe=True, confidence=medium
    - Breaking changes + affected_lines → safe=True, confidence=medium, pre_fix=True
    """
    api_diff = group.get("api_diff", {})
    has_breaking = api_diff.get("has_breaking_changes", False)
    affected = api_diff.get("affected_lines", [])

    if not has_breaking:
        return AiReasoningResult(
            safe=True,
            confidence="high",
            at_risk_lines=[],
            reason=(
                "No breaking API changes detected by japicmp. "
                "Upgrade is likely drop-in compatible."
            ),
            pre_fix_required=False,
            recommended_candidate=candidate,
        )

    if affected:
        return AiReasoningResult(
            safe=True,
            confidence="medium",
            at_risk_lines=affected,
            reason=(
                f"Breaking API changes detected and {len(affected)} call site(s) "
                "in the codebase reference changed APIs. Review required before merging."
            ),
            pre_fix_required=True,
            recommended_candidate=candidate,
        )

    return AiReasoningResult(
        safe=True,
        confidence="medium",
        at_risk_lines=[],
        reason=(
            "Breaking API changes detected but none cross-referenced to calling code. "
            "Upgrade is likely safe but manual review recommended."
        ),
        pre_fix_required=False,
        recommended_candidate=candidate,
    )


# ── Main reasoning function ───────────────────────────────────────────────────

def reason_about_upgrade(
    group: dict,
    candidate: str,
    llm,
) -> AiReasoningResult:
    """
    Run AI reasoning for one dep + candidate pair.

    If llm is None, falls back to heuristic logic.
    Returns AiReasoningResult.
    """
    parsed = group["parsed"]
    group_id = parsed["group_id"]
    artifact_id = parsed["artifact_id"]
    current_version = parsed["current_version"]

    api_diff = group.get("api_diff", {})
    breaking_count = api_diff.get("breaking_count", 0)
    raw_diff = api_diff.get("raw_output", "japicmp unavailable")[:3000]
    affected_lines = api_diff.get("affected_lines", [])

    cve_list = "\n".join(f"  - {c}" for c in group.get("cves", []))
    explanation = (group.get("version_candidates") or {}).get("explanation", "")[:1000]
    calling_code = group.get("_calling_code_snippet", "")[:2000] or "(no calling code found)"

    # ── Heuristic path (no LLM) ───────────────────────────────────────────────
    if llm is None:
        logger.info(
            f"[AI Reasoning] {artifact_id}: using heuristic fallback (Vertex AI unavailable)"
        )
        result = _heuristic_reasoning(group, candidate)
        _log_result(artifact_id, current_version, candidate, result)
        return result

    # ── LLM path ──────────────────────────────────────────────────────────────
    user_prompt = _USER_PROMPT_TEMPLATE.format(
        group_id=group_id,
        artifact_id=artifact_id,
        current_version=current_version,
        candidate=candidate,
        cve_list=cve_list or "  (none listed)",
        explanation=explanation or "(not available)",
        breaking_count=breaking_count,
        api_diff=raw_diff,
        calling_code=calling_code,
    )

    from langchain_core.messages import HumanMessage, SystemMessage  # type: ignore

    messages = [
        SystemMessage(content=_SYSTEM_PROMPT),
        HumanMessage(content=user_prompt),
    ]

    t0 = time.time()
    try:
        response = llm.invoke(messages)
        latency = time.time() - t0
        raw_text = response.content if hasattr(response, "content") else str(response)
        logger.info(
            f"[AI Reasoning] LLM call complete "
            f"({latency:.1f}s, {len(raw_text)} chars)"
        )
    except Exception as exc:
        logger.warning(
            f"[AI Reasoning] LLM call failed: {exc} — using heuristic fallback"
        )
        result = _heuristic_reasoning(group, candidate)
        _log_result(artifact_id, current_version, candidate, result)
        return result

    # Parse JSON
    data = _extract_json(raw_text)
    if data is None:
        logger.warning(
            "[AI Reasoning] Could not parse LLM JSON response — "
            "using heuristic fallback"
        )
        logger.debug(f"[AI Reasoning] Raw LLM output: {raw_text[:500]}")
        result = _heuristic_reasoning(group, candidate)
        _log_result(artifact_id, current_version, candidate, result)
        return result

    result = _validate_result(data, candidate)
    _log_result(artifact_id, current_version, candidate, result)
    return result


def _log_result(
    artifact_id: str,
    current_version: str,
    candidate: str,
    result: AiReasoningResult,
) -> None:
    """Emit the done-when console output lines."""
    safe_icon = "✅" if result["safe"] else "❌"
    conf_icon = {"high": "🟢", "medium": "🟡", "low": "🔴"}.get(
        result["confidence"], "🟡"
    )
    logger.info(
        f"[AI Reasoning] {artifact_id} {current_version} → {candidate}"
    )
    logger.info(
        f"               Safe: {result['safe']}  {safe_icon}   "
        f"Confidence: {result['confidence']} {conf_icon}"
    )
    logger.info(f"               Reason: {result['reason']}")
    if result["at_risk_lines"]:
        logger.info(
            f"               At risk: {', '.join(result['at_risk_lines'][:5])}"
        )
    logger.info(f"               Pre-fix required: {result['pre_fix_required']}")


# ── Routing helper ────────────────────────────────────────────────────────────

def route_from_reasoning(result: AiReasoningResult) -> str:
    """
    Return the next pipeline node name based on the AI reasoning result.

    Returns one of: "adr_fix" | "ai_code_fix" | "escalate"
    """
    if not result["safe"]:
        return "escalate"
    if result["confidence"] == "high" and not result["pre_fix_required"]:
        return "adr_fix"
    return "ai_code_fix"


# ── Batch reasoning ───────────────────────────────────────────────────────────

def reason_all_groups(
    groups: list[dict],
    gcp_project: str,
    gcp_location: str,
) -> list[dict]:
    """
    Run AI reasoning for every group against its current candidate.
    Builds the LLM once and reuses it across all groups.
    Enriches each group dict with 'ai_reasoning' and 'next_node'.
    """
    llm = _build_llm(gcp_project, gcp_location)

    enriched: list[dict] = []

    for group in groups:
        candidates: list[str] = (
            group.get("version_candidates", {}).get("candidates", [])
        )
        if not candidates:
            logger.warning(
                f"[AI Reasoning] {group['parsed']['artifact_id']}: "
                "no candidates — skipping reasoning, will escalate"
            )
            group = dict(group)
            group["ai_reasoning"] = AiReasoningResult(
                safe=False,
                confidence="low",
                at_risk_lines=[],
                reason="No safe version candidates available",
                pre_fix_required=False,
                recommended_candidate="",
            )
            group["next_node"] = "escalate"
            enriched.append(group)
            continue

        candidate = candidates[0]   # always reason about next_safe first
        result = reason_about_upgrade(group, candidate, llm)

        group = dict(group)
        group["ai_reasoning"] = result
        group["next_node"] = route_from_reasoning(result)
        group["current_candidate"] = candidate
        enriched.append(group)

    # Summary
    routes = [g["next_node"] for g in enriched]
    logger.info(
        f"[AI Reasoning] ✅ Routing: "
        f"adr_fix={routes.count('adr_fix')}, "
        f"ai_code_fix={routes.count('ai_code_fix')}, "
        f"escalate={routes.count('escalate')}"
    )
    return enriched


# ── LangGraph node ────────────────────────────────────────────────────────────

def ai_reasoning_node(
    state: AgentState,
    gcp_project: str,
    gcp_location: str,
) -> AgentState:
    """
    LangGraph node: ai_reasoning.

    Reads:  state["_diff_groups"]
    Writes: state["_reasoned_groups"]  (groups + ai_reasoning + next_node)
            state["audit_trail"]
    """
    groups: list[dict] = state.get("_diff_groups", [])  # type: ignore[attr-defined]

    if not groups:
        logger.warning("[AI Reasoning] No diff groups in state — skipping")
        state["status"] = "skipped"
        state["skip_reason"] = "No diff groups for AI reasoning"
        state["audit_trail"].append({"node": "ai_reasoning", "status": "skipped"})
        return state

    enriched = reason_all_groups(groups, gcp_project, gcp_location)

    state["_reasoned_groups"] = enriched  # type: ignore[typeddict-unknown-key]
    state["audit_trail"].append({
        "node": "ai_reasoning",
        "status": "ok",
        "groups": len(enriched),
        "routes": {
            g["parsed"]["artifact_id"]: g["next_node"] for g in enriched
        },
    })
    return state