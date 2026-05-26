"""
SonarAI — LLM Agent Nodes  (Iteration 2)
Three LangGraph node functions wired into the state graph:
  plan_fix      → LLM·1 Planner  → PlannerOutput
  generate_fix  → LLM·2 Generator → GeneratorOutput
  critique_fix  → LLM·3 Critic   → CriticOutput

Iteration 2 changes:
  - plan_fix now passes rag_context (prior fix examples) to the Planner prompt.
  - retrieve_rag_context() is exposed as a standalone node for the graph to call
    before plan_fix, enabling pre-fetch of ChromaDB results.

Resilience additions:
  - All three LLM chain.invoke() calls are wrapped by _invoke_with_retry(), which
    uses tenacity exponential backoff to survive transient Vertex AI 429/503 errors.
    Retry budget: up to LLM_MAX_ATTEMPTS attempts, starting at LLM_RETRY_WAIT_MIN
    seconds, doubling each time up to LLM_RETRY_WAIT_MAX seconds.
    Non-retryable errors (auth, 400 bad request) are re-raised immediately.
  - Fallback model support: if the primary model (vertex_model) exhausts all
    retries due to model-level unavailability (404 Not Found, prolonged 503), or
    if it is outright absent from the Model Garden, _invoke_with_retry
    transparently rebuilds the chain against vertex_fallback_model and makes one
    final attempt before giving up. The three node functions (plan_fix,
    generate_fix, critique_fix) are unaware of this — they pass the prompt
    template and prompt_vars; the helper owns the model selection.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from langchain_google_vertexai import ChatVertexAI
from loguru import logger
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
    before_sleep_log,
    RetryError,
)
import logging as _logging

from config import settings
from prompts import planner_prompt, generator_prompt, critic_prompt, format_rag_context
from state import AgentState, PlannerOutput, GeneratorOutput, CriticOutput, RAGContext, SonarRuleDetail

# ── Retry configuration ───────────────────────────────────────────────────────
# Transient Vertex AI failures (rate limits, service unavailability) should be
# retried automatically. Non-retryable errors (auth, malformed request) are
# re-raised immediately so the node can fail fast and record a proper error.
LLM_MAX_ATTEMPTS = 3
LLM_RETRY_WAIT_MIN = 2    # seconds before first retry
LLM_RETRY_WAIT_MAX = 30   # cap for exponential backoff


# ── LLM factory ──────────────────────────────────────────────────────────────

def _make_llm(temperature: float = 0.2, model_name: str | None = None) -> ChatVertexAI:
    """
    Return a ChatVertexAI instance.

    Args:
        temperature: Sampling temperature passed to the model.
        model_name:  Override the model name. Defaults to settings.vertex_model.
                     Pass settings.vertex_fallback_model explicitly to build
                     the fallback — keeps callsites readable.
    """
    return ChatVertexAI(
        model_name=model_name or settings.vertex_model,
        project=settings.gcp_project,
        location=settings.gcp_location,
        max_output_tokens=settings.max_tokens,
        temperature=temperature,
    )


# ── Error classification helpers ──────────────────────────────────────────────

def _is_retryable(exc: BaseException) -> bool:
    """
    Return True for transient Vertex AI / gRPC errors that are safe to retry
    against the *same* model:
      - HTTP 429  Too Many Requests  (quota exhaustion)
      - HTTP 500  Internal Server Error
      - HTTP 503  Service Unavailable  (transient blip, not a full outage)
      - gRPC RESOURCE_EXHAUSTED / UNAVAILABLE status codes
      - DeadlineExceeded (request timeout)

    Return False for permanent errors where retrying the same model is pointless:
      - HTTP 400  Bad Request  (malformed prompt / invalid parameter)
      - HTTP 401 / 403  Authentication / Permission denied
      - HTTP 404  Model not found  (→ triggers fallback instead)

    The google-cloud-aiplatform SDK raises google.api_core.exceptions.*
    which all inherit from GoogleAPICallError.
    """
    try:
        from google.api_core import exceptions as _gae
        if isinstance(exc, _gae.ResourceExhausted):   # 429
            return True
        if isinstance(exc, _gae.ServiceUnavailable):  # 503 transient
            return True
        if isinstance(exc, _gae.InternalServerError): # 500
            return True
        if isinstance(exc, _gae.DeadlineExceeded):    # timeout
            return True
        # NotFound (404) and all other GoogleAPICallErrors → not retryable here
        if isinstance(exc, _gae.GoogleAPICallError):
            return False
    except ImportError:
        pass

    msg = str(exc).lower()
    fatal_patterns = ("401", "403", "404", "permission", "unauthenticated",
                      "invalid argument", "not found")
    transient_patterns = ("429", "503", "500", "rate limit", "quota",
                          "unavailable", "deadline")
    if any(p in msg for p in fatal_patterns):
        return False
    if any(p in msg for p in transient_patterns):
        return True
    # Unknown errors: retry (a wasted attempt is cheaper than aborting the issue)
    return True


def _is_model_unavailable(exc: BaseException) -> bool:
    """
    Return True when the error indicates the *model itself* is unavailable or
    unknown — meaning retrying the same model will never succeed and we should
    switch to the fallback model instead.

    Triggers on:
      - google.api_core.exceptions.NotFound       (404 — model not in garden)
      - google.api_core.exceptions.ServiceUnavailable whose message mentions
        the model name, a region, or "not deployed" (sustained outage, not a blip)
      - String-match fallbacks for when the SDK is not importable.

    Intentionally conservative: a plain 503 without a model-name mention is
    treated as a transient blip (_is_retryable=True) rather than a model outage.
    """
    try:
        from google.api_core import exceptions as _gae
        if isinstance(exc, _gae.NotFound):            # 404 — model absent
            return True
        if isinstance(exc, _gae.ServiceUnavailable):
            msg = str(exc).lower()
            # "not deployed", "no healthy upstream", region mentions → sustained
            model_hints = ("not deployed", "no healthy upstream", "us-central1",
                           "model", settings.vertex_model.lower())
            if any(h in msg for h in model_hints):
                return True
    except ImportError:
        pass

    msg = str(exc).lower()
    return any(p in msg for p in ("not found", "404", "not deployed",
                                   "no healthy upstream", "model unavailable"))


# ── Retry / backoff + fallback helper ────────────────────────────────────────

def _invoke_with_retry(
    prompt: Any,
    prompt_vars: dict[str, Any],
    node_name: str,
    temperature: float = 0.2,
) -> Any:
    """
    Invoke a LangChain prompt template against the configured LLM with
    exponential backoff retry and automatic fallback to the secondary model.

    Two-phase execution
    ───────────────────
    Phase 1 — Primary model (settings.vertex_model):
      Up to LLM_MAX_ATTEMPTS attempts with exponential backoff.
      Retryable errors (429, 500, 503 blips, timeouts) are retried.
      Non-retryable errors (auth, bad request) raise immediately — no fallback.
      Model-unavailability errors (404, sustained 503) skip remaining retries
      and drop straight to Phase 2.

    Phase 2 — Fallback model (settings.vertex_fallback_model):
      A single attempt with no further retry.  If this also fails the
      exception propagates to the calling node, which records an error result.
      Phase 2 is skipped entirely if vertex_fallback_model is not configured
      or is identical to vertex_model.

    Args:
        prompt:      A LangChain prompt template (e.g. planner_prompt).
                     The chain (prompt | llm) is built internally so the model
                     can be swapped for the fallback without changing callsites.
        prompt_vars: Variables forwarded to chain.invoke().
        node_name:   Label for log messages ("Planner", "Generator", "Critic").
        temperature: Sampling temperature for the LLM.

    Returns:
        Raw response object from chain.invoke().

    Raises:
        The last exception when both phases are exhausted or on non-retryable
        primary errors.
    """
    fallback_model = settings.vertex_fallback_model
    has_fallback = bool(fallback_model and fallback_model != settings.vertex_model)

    # ── Phase 1: primary model with tenacity backoff ──────────────────────────
    primary_llm = _make_llm(temperature=temperature)
    primary_chain = prompt | primary_llm

    attempt = 0
    model_unavailable = False  # set True to break out to Phase 2

    @retry(
        retry=retry_if_exception(_is_retryable),
        stop=stop_after_attempt(LLM_MAX_ATTEMPTS),
        wait=wait_exponential(multiplier=1, min=LLM_RETRY_WAIT_MIN, max=LLM_RETRY_WAIT_MAX),
        before_sleep=before_sleep_log(_logging.getLogger("tenacity"), _logging.WARNING),
        reraise=True,
    )
    def _primary_attempt() -> Any:
        nonlocal attempt, model_unavailable
        attempt += 1
        if attempt > 1:
            logger.warning(
                f"[{node_name}] Primary model retry {attempt}/{LLM_MAX_ATTEMPTS} "
                f"(model={settings.vertex_model})"
            )
        try:
            return primary_chain.invoke(prompt_vars)
        except Exception as exc:
            if _is_model_unavailable(exc):
                # Signal Phase 2 and stop retrying this model
                model_unavailable = True
                logger.error(
                    f"[{node_name}] Primary model '{settings.vertex_model}' is "
                    f"unavailable ({type(exc).__name__}: {exc}). "
                    + ("Falling back to fallback model." if has_fallback
                       else "No fallback configured — aborting.")
                )
                raise  # tenacity sees this as non-retryable (not in _is_retryable)
            raise

    primary_exc: Exception | None = None
    try:
        return _primary_attempt()
    except RetryError as exc:
        primary_exc = exc.last_attempt.exception()
        logger.error(
            f"[{node_name}] Primary model exhausted all {LLM_MAX_ATTEMPTS} attempts. "
            f"Last error: {primary_exc}"
        )
    except Exception as exc:
        primary_exc = exc
        # Non-retryable primary error (auth, bad request, model unavailable)
        if not model_unavailable:
            # Auth / bad request — fallback won't help
            raise

    # ── Phase 2: fallback model (single attempt) ──────────────────────────────
    if not has_fallback:
        assert primary_exc is not None
        raise primary_exc

    logger.warning(
        f"[{node_name}] Switching to fallback model '{fallback_model}' "
        f"(primary: {settings.vertex_model})"
    )
    fallback_llm = _make_llm(temperature=temperature, model_name=fallback_model)
    fallback_chain = prompt | fallback_llm

    try:
        response = fallback_chain.invoke(prompt_vars)
        logger.info(
            f"[{node_name}] Fallback model '{fallback_model}' succeeded — "
            "consider updating vertex_model in settings if this keeps happening."
        )
        return response
    except Exception as exc:
        logger.error(
            f"[{node_name}] Fallback model '{fallback_model}' also failed: {exc}"
        )
        raise


# ── JSON parsing helper ───────────────────────────────────────────────────────

def _parse_json_response(raw: str, node_name: str) -> dict[str, Any]:
    """
    Parse a JSON response from an LLM.  Handles common LLM habits like:
    - Wrapping JSON in ```json ... ``` fences
    - Leading/trailing whitespace
    """
    cleaned = re.sub(r"^```(?:json)?\s*", "", raw.strip(), flags=re.MULTILINE)
    cleaned = re.sub(r"\s*```$", "", cleaned.strip(), flags=re.MULTILINE)
    cleaned = cleaned.strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as exc:
        logger.error(f"[{node_name}] JSON parse failed: {exc}\nRaw output:\n{raw[:500]}")
        raise


def _clean_patch_hunks(patch: str) -> str:
    """
    Strip markdown code fences that the LLM embeds INSIDE the patch_hunks JSON value.
    """
    if not patch:
        return patch

    patch = patch.replace("\\r\\n", "\n").replace("\\n", "\n")
    patch = re.sub(r"^```[a-zA-Z]*\s*\n?", "", patch.lstrip(), flags=re.MULTILINE)
    patch = re.sub(r"\n?^```\s*$", "", patch.rstrip(), flags=re.MULTILINE)

    return patch.strip()


# ── Node helpers ──────────────────────────────────────────────────────────────

def _rule_kb_entry_text(state: AgentState) -> str:
    """Format the Rule KB entry for the current issue, or a generic note if missing.

    Merges two sources (live data takes precedence over static KB):
      1. state['sonar_rule_detail'] — fetched live from /api/rules/show
      2. state['rule_kb']           — local static JSON knowledge base

    Supports both legacy schema (name/short/severity/description/fix_strategy/examples)
    and the extended FindBugs-compatible schema that adds type, tags, and impacts.
    """
    rule_kb: dict = state.get("rule_kb", {})
    issue = state.get("current_issue", {})
    rule_key = issue.get("rule_key", "")

    # ── 1. Live rule detail from SonarQube API ─────────────────────────────────
    live: SonarRuleDetail = state.get("sonar_rule_detail", {}) or {}
    live_lines: list[str] = []

    if live.get("name"):
        live_lines.append(f"[LIVE] Name: {live['name']}")
    if live.get("type"):
        live_lines.append(f"[LIVE] Type: {live['type']}")
    if live.get("severity"):
        live_lines.append(f"[LIVE] Severity: {live['severity']}")
    if live.get("lang_name"):
        live_lines.append(f"[LIVE] Language: {live['lang_name']}")
    if live.get("rem_fn_type"):
        live_lines.append(f"[LIVE] Remediation: {live['rem_fn_type']} ({live.get('rem_fn_base_effort', '')})")
    tags = list(live.get("tags", []) or []) + list(live.get("sys_tags", []) or [])
    if tags:
        live_lines.append(f"[LIVE] Tags: {', '.join(tags)}")
    if live.get("fix_summary"):
        live_lines.append(f"[LIVE] Fix Guidance:\n{live['fix_summary']}")

    # ── 2. Static KB entry ─────────────────────────────────────────────────────
    entry = rule_kb.get(rule_key)
    static_lines: list[str] = []

    if entry:
        static_lines = [
            f"Name: {entry.get('name', '')}",
            f"Description: {entry.get('description', '')}",
            f"Fix Strategy: {entry.get('fix_strategy', '')}",
            f"Example Before: {entry.get('example_before', '')}",
            f"Example After: {entry.get('example_after', '')}",
        ]
        rule_type = entry.get("type")
        if rule_type:
            static_lines.append(f"Type: {rule_type}")
        tags_kb = entry.get("tags")
        if tags_kb:
            static_lines.append(f"Tags: {', '.join(tags_kb)}")
        impacts = entry.get("impacts")
        if impacts:
            impact_strs = [
                f"{imp.get('softwareQuality', '')} ({imp.get('severity', '')})"
                for imp in impacts
            ]
            static_lines.append(f"Impacts: {'; '.join(impact_strs)}")

    # ── Combine: live first, then static KB ────────────────────────────────────
    if not live_lines and not static_lines:
        return f"No KB entry or live rule data for rule {rule_key}. Apply generic best-practice remediation."

    parts: list[str] = []
    if live_lines:
        parts.append("## Live Rule Data (from SonarQube API)")
        parts.extend(live_lines)
    if static_lines:
        parts.append("## Static KB Entry")
        parts.extend(static_lines)

    return "\n".join(parts)


# ── RAG node ─────────────────────────────────────────────────────────────────

def retrieve_rag_context(state: AgentState) -> AgentState:
    """
    LangGraph node — retrieve similar prior fixes from ChromaDB.
    Populates state['rag_context'].
    Silently no-ops (empty context) if RAG is disabled or unavailable.
    """
    if not settings.enable_rag:
        empty: RAGContext = {"rule_key": "", "similar_fixes": [], "retrieved_count": 0}
        return {**state, "rag_context": empty}

    issue = state.get("current_issue", {})
    rule_key = issue.get("rule_key", "")
    message = issue.get("message", "")
    method_context = state.get("method_context", "")

    logger.info(f"[RAG] Retrieving prior fixes for rule={rule_key}")

    try:
        from rag_store import retrieve_similar_fixes
        similar_fixes = retrieve_similar_fixes(
            rule_key=rule_key,
            method_context=method_context,
            message=message,
            top_k=settings.rag_top_k,
        )
    except Exception as exc:
        logger.warning(f"[RAG] Retrieval failed (non-fatal): {exc}")
        similar_fixes = []

    rag_ctx: RAGContext = {
        "rule_key": rule_key,
        "similar_fixes": similar_fixes,
        "retrieved_count": len(similar_fixes),
    }

    if similar_fixes:
        logger.info(f"[RAG] Found {len(similar_fixes)} similar fix(es) to use as context")
    else:
        logger.info("[RAG] No similar prior fixes found")

    return {**state, "rag_context": rag_ctx}


# ── Sonar Rule Fetch node ─────────────────────────────────────────────────────

def fetch_sonar_rule(state: AgentState) -> AgentState:
    """
    LangGraph node — fetch live rule details from the SonarQube /api/rules/show
    endpoint for the current issue's rule_key.

    Populates state['sonar_rule_detail'] with:
      - name, html_desc, severity, type, status, lang, tags, sys_tags
      - rem_fn_type, rem_fn_base_effort
      - fix_summary  (plain-text guidance distilled from htmlDesc)

    Silently no-ops if SONAR_TOKEN or SONAR_HOST_URL are not configured,
    or if the rule is not found (graceful degradation).
    """
    issue = state.get("current_issue", {})
    rule_key = issue.get("rule_key", "")

    empty_detail: SonarRuleDetail = {
        "rule_key": rule_key,
        "name": "",
        "html_desc": "",
        "severity": issue.get("severity", ""),
        "type": "",
        "status": "",
        "lang": "",
        "lang_name": "",
        "tags": [],
        "sys_tags": [],
        "rem_fn_type": "",
        "rem_fn_base_effort": "",
        "fix_summary": "",
    }

    if not settings.sonar_token or not settings.sonar_host_url:
        logger.info(
            f"[RuleFetch] SONAR_TOKEN/HOST not configured — skipping rule fetch for {rule_key}"
        )
        return {**state, "sonar_rule_detail": empty_detail}

    logger.info(f"[RuleFetch] Fetching rule details for {rule_key}")

    try:
        import requests as _req
        import html as _html
        import re as _re

        base_url = settings.sonar_host_url.rstrip("/")
        resp = _req.get(
            f"{base_url}/api/rules/show",
            auth=(settings.sonar_token, ""),
            params={"key": rule_key},
            timeout=15,
        )

        if resp.status_code == 404:
            logger.warning(f"[RuleFetch] Rule {rule_key} not found in SonarQube (404)")
            return {**state, "sonar_rule_detail": empty_detail}

        if resp.status_code != 200:
            logger.warning(
                f"[RuleFetch] SonarQube returned HTTP {resp.status_code} for rule {rule_key}"
            )
            return {**state, "sonar_rule_detail": empty_detail}

        body = resp.json()
        rule = body.get("rule", {})

        # Extract HTML description — prefer mdDesc if present, fall back to htmlDesc
        html_desc = rule.get("htmlDesc", "") or rule.get("mdDesc", "")

        # Distil a plain-text fix summary by stripping HTML tags
        plain_desc = _html.unescape(_re.sub(r"<[^>]+>", " ", html_desc))
        plain_desc = _re.sub(r"\s{2,}", " ", plain_desc).strip()

        # Try to pull just the "Compliant Solution" or "How to fix" section
        fix_summary = _extract_fix_section(plain_desc, html_desc)

        detail: SonarRuleDetail = {
            "rule_key":           rule_key,
            "name":               rule.get("name", ""),
            "html_desc":          html_desc,
            "severity":           rule.get("severity", issue.get("severity", "")),
            "type":               rule.get("type", ""),
            "status":             rule.get("status", ""),
            "lang":               rule.get("lang", ""),
            "lang_name":          rule.get("langName", ""),
            "tags":               rule.get("tags", []),
            "sys_tags":           rule.get("sysTags", []),
            "rem_fn_type":        rule.get("remFnType", ""),
            "rem_fn_base_effort": rule.get("remFnBaseEffort", ""),
            "fix_summary":        fix_summary,
        }

        logger.info(
            f"[RuleFetch] ✅ Fetched rule '{detail['name']}' "
            f"(type={detail['type']}, effort={detail['rem_fn_base_effort']})"
        )
        return {**state, "sonar_rule_detail": detail}

    except Exception as exc:
        logger.warning(f"[RuleFetch] Non-fatal error fetching rule {rule_key}: {exc}")
        return {**state, "sonar_rule_detail": empty_detail}


def _extract_fix_section(plain_text: str, html: str) -> str:
    """
    Extract the most relevant fix guidance from a SonarQube rule description.
    Looks for 'Compliant Solution', 'How to fix', or 'Recommended' sections.
    Falls back to the first 600 chars of plain text if no section is found.
    """
    import re as _re

    # Try to find a compliant/fix section in the HTML (between headings)
    section_patterns = [
        r"(?:Compliant[^<]*Solution|How to[^<]*[Ff]ix|Recommended[^<]*Practice)(.*?)(?=<h\d|$)",
        r"(?:Non-?compliant Code|Noncompliant Code)(.*?)(?:Compliant|$)",
    ]
    for pat in section_patterns:
        m = _re.search(pat, html, _re.DOTALL | _re.IGNORECASE)
        if m:
            snippet = _re.sub(r"<[^>]+>", " ", m.group(0))
            snippet = _re.sub(r"\s{2,}", " ", snippet).strip()
            if len(snippet) > 30:
                return snippet[:800]

    # Fall back to first 600 chars of plain description
    return plain_text[:600] if plain_text else ""

# ── Confidence calibration helpers ───────────────────────────────────────────

# Rules where even a correct fix carries elevated risk and should be capped.
_HIGH_RISK_RULES: frozenset[str] = frozenset({
    "java:S2068",  # hardcoded credentials
    "java:S5547",  # weak cipher algorithm
    "java:S3649",  # SQL injection
    "java:S2076",  # OS command injection
    "java:S2631",  # regex injection
    "java:S5131",  # XSS
})

# Weights for the five planner sub-scores → must sum to 1.0
_CONFIDENCE_WEIGHTS: dict[str, float] = {
    "rule_understood":   0.25,
    "fix_is_mechanical": 0.30,
    "context_sufficient": 0.20,
    "side_effects_risk": 0.15,
    "rag_match_quality": 0.10,
}


def _aggregate_confidence(factors: dict[str, float]) -> float:
    """
    Weighted average of planner sub-scores into a calibrated confidence float.

    Each factor is clamped to [0, 1] before weighting so a misbehaving LLM
    cannot push the aggregate out of range.  Missing factors default to 0.5
    (neutral) so callers never get a KeyError.
    """
    score = sum(
        min(max(float(factors.get(k, 0.5)), 0.0), 1.0) * w
        for k, w in _CONFIDENCE_WEIGHTS.items()
    )
    return round(score, 3)


def _calibrate_confidence(raw_score: float, state: AgentState) -> float:
    """
    Apply rule-based, signal-driven adjustments to the planner's aggregated
    confidence score.  Uses only information that is deterministically
    observable at plan time — no LLM calls.

    Adjustments (applied in order, cumulative):
      +0.10  RAG found a fix with similarity ≥ 0.85  (strong prior evidence)
      +0.05  RAG found a fix with similarity ≥ 0.70  (moderate prior evidence)
      −0.15  Rule is in the high-risk security/injection category
      −0.05  Code context was truncated ("lines omitted" marker present)
      −0.10  No rule KB entry AND no live SonarQube rule detail available
      cap 0.75  Issue severity is BLOCKER (always warrants human review)

    The result is clamped to [0.0, 1.0].
    """
    score = raw_score
    issue = state.get("current_issue", {})
    rag_ctx = state.get("rag_context", {}) or {}

    # ── RAG boost ────────────────────────────────────────────────────────────
    similar = rag_ctx.get("similar_fixes", [])
    top_similarity = similar[0].get("similarity", 0.0) if similar else 0.0
    if top_similarity >= 0.85:
        score = min(1.0, score + 0.10)
        logger.debug(f"[Planner] calibration: +0.10 RAG strong match (sim={top_similarity:.2f})")
    elif top_similarity >= 0.70:
        score = min(1.0, score + 0.05)
        logger.debug(f"[Planner] calibration: +0.05 RAG moderate match (sim={top_similarity:.2f})")

    # ── High-risk rule penalty ────────────────────────────────────────────────
    rule_key = issue.get("rule_key", "")
    if rule_key in _HIGH_RISK_RULES:
        score = max(0.0, score - 0.15)
        logger.debug(f"[Planner] calibration: −0.15 high-risk rule ({rule_key})")

    # ── Truncated context penalty ─────────────────────────────────────────────
    if "lines omitted" in state.get("method_context", ""):
        score = max(0.0, score - 0.05)
        logger.debug("[Planner] calibration: −0.05 truncated method context")

    # ── Missing rule knowledge penalty ───────────────────────────────────────
    rule_detail = state.get("sonar_rule_detail", {}) or {}
    rule_kb = state.get("rule_kb", {}) or {}
    has_live_guidance = bool(rule_detail.get("fix_summary"))
    has_kb_entry = bool(rule_kb.get(rule_key))
    if not has_live_guidance and not has_kb_entry:
        score = max(0.0, score - 0.10)
        logger.debug("[Planner] calibration: −0.10 no rule KB or live rule detail")

    # ── BLOCKER cap ───────────────────────────────────────────────────────────
    if issue.get("severity") == "BLOCKER":
        if score > 0.75:
            logger.debug(f"[Planner] calibration: capping BLOCKER score {score:.3f} → 0.75")
            score = 0.75

    return round(min(max(score, 0.0), 1.0), 3)


def plan_fix(state: AgentState) -> AgentState:
    """
    Analyse the current Sonar issue with chain-of-thought reasoning.
    Populates state['planner_output'].

    Iteration 3 changes:
      - Requests structured `confidence_factors` (5 sub-scores) from the LLM
        instead of a single opaque float.
      - Aggregates sub-scores via _aggregate_confidence() with fixed weights.
      - Applies signal-driven calibration via _calibrate_confidence() using
        observable pipeline facts (RAG similarity, severity, rule risk, context
        completeness, KB coverage).
      - Stores both raw factors and the final calibrated score in planner_output.
    """
    issue = state["current_issue"]
    logger.info(
        f"[Planner] rule={issue['rule_key']} severity={issue['severity']} "
        f"line={issue['line']}"
    )

    # Build RAG few-shot block
    rag_ctx = state.get("rag_context", {})
    similar_fixes = rag_ctx.get("similar_fixes", []) if rag_ctx else []
    rag_block = format_rag_context(similar_fixes)
    if similar_fixes:
        logger.info(f"[Planner] Including {len(similar_fixes)} RAG example(s) in prompt")

    prompt_vars = {
        "rule_key": issue["rule_key"],
        "severity": issue["severity"],
        "message": issue["message"],
        "file_path": state.get("file_path", "unknown"),
        "flagged_line": issue["line"],
        "rule_kb_entry": _rule_kb_entry_text(state),
        "method_context": state.get("method_context", ""),
        "rag_context": rag_block,
    }

    t0 = time.time()
    response = _invoke_with_retry(
        planner_prompt, prompt_vars, "Planner",
        temperature=settings.planner_temperature,
    )
    elapsed = time.time() - t0

    raw = response.content if hasattr(response, "content") else str(response)
    logger.info(f"[Planner] LLM call completed in {elapsed:.2f}s")

    parsed: PlannerOutput = _parse_json_response(raw, "Planner")  # type: ignore[assignment]

    parsed.setdefault("reasoning", "")
    parsed.setdefault("strategy", "")

    # ── Confidence: aggregate sub-scores → calibrate with signals ─────────────
    factors: dict[str, float] = parsed.pop("confidence_factors", {})
    # Graceful fallback: if the LLM returned a bare `confidence` float instead
    # of the new schema (e.g. during a model rollout), use it as a neutral seed.
    if not factors and "confidence" in parsed:
        legacy = float(parsed["confidence"])
        factors = {k: legacy for k in _CONFIDENCE_WEIGHTS}
        logger.warning(
            f"[Planner] LLM returned legacy `confidence` float ({legacy:.2f}) "
            "instead of confidence_factors — using as uniform seed."
        )

    raw_aggregated = _aggregate_confidence(factors)
    calibrated = _calibrate_confidence(raw_aggregated, state)

    parsed["confidence_factors"] = factors        # keep for PR body / audit
    parsed["confidence"] = calibrated             # this drives HIGH/MEDIUM/LOW routing

    logger.info(
        f"[Planner] factors={factors} "
        f"raw_agg={raw_aggregated:.3f} "
        f"calibrated={calibrated:.3f} "
        f"strategy_preview={parsed['strategy'][:80]!r}"
    )

    return {**state, "planner_output": parsed}


# ── LLM·2  Generator ─────────────────────────────────────────────────────────

def _extract_failing_hunk(patch: str, error: str) -> str:
    """
    Return the hunk from a unified diff that is closest to the line number
    mentioned in a compiler or git-apply error message.
    Used to give the Generator precise feedback on which hunk to fix.
    """
    if not patch or not error:
        return ""
    import re as _re
    line_match = _re.search(r":(\d+):", error)
    if not line_match:
        return ""
    error_line = int(line_match.group(1))
    best_hunk = ""
    best_dist = 9999
    for m in _re.finditer(r"(@@ -(\d+).*?@@[^\n]*\n(?:[ +\-\\][^\n]*\n?)*)", patch):
        hunk_start_match = _re.search(r"-(\d+)", m.group(1))
        if not hunk_start_match:
            continue
        hunk_line = int(hunk_start_match.group(1))
        dist = abs(hunk_line - error_line)
        if dist < best_dist:
            best_dist = dist
            best_hunk = m.group(0)
    # Only return if reasonably close (within 50 lines)
    return best_hunk[:600] if best_dist < 50 else ""


def generate_fix(state: AgentState) -> AgentState:
    """
    Generate a minimal unified diff fixing the Sonar issue.
    Populates state['generator_output'].
    Appends critic feedback to the prompt on retry iterations.

    Retry loop improvements (Iteration 3):
    - retry_count is incremented in the router BEFORE this node runs, so
      retry_count=0 means first attempt, retry_count=1 means second, etc.
    - Temperature decays by 0.1 per retry making the model progressively more
      deterministic — critical for accurate '-' line reproduction.
    - On retries, feedback now includes the specific failing hunk (extracted
      from the previous patch) so the LLM knows exactly which part to fix.
    """
    issue = state["current_issue"]
    retry_count = state.get("retry_count", 0)
    planner_out = state.get("planner_output", {})

    logger.info(f"[Generator] retry={retry_count} rule={issue['rule_key']}")

    # ── Retry feedback block ──────────────────────────────────────────────────
    retry_feedback = ""
    if retry_count > 0:
        critic_out = state.get("critic_output", {})
        concerns = critic_out.get("concerns", [])
        concern_text = "\n".join(f"  - {c}" for c in concerns)
        validation = state.get("validation", {})

        compiler_error = validation.get("compiler_error", "")
        test_error = validation.get("test_error", "")

        retry_feedback = (
            f"## ⚠ Attempt {retry_count} Was Rejected — Fix These Issues\n"
            f"Critic concerns:\n{concern_text}\n"
        )

        if compiler_error:
            # Extract the specific failing hunk for precise feedback
            prev_patch = state.get("generator_output", {}).get("patch_hunks", "")
            failing_hunk = _extract_failing_hunk(prev_patch, compiler_error)
            if failing_hunk:
                retry_feedback += (
                    f"\nThe following hunk caused the failure — DO NOT reuse it:\n"
                    f"```diff\n{failing_hunk}\n```\n"
                    "Produce a corrected version of this hunk only.\n"
                )
            retry_feedback += f"\nCompiler error:\n```\n{compiler_error[:800]}\n```\n"

        if test_error:
            retry_feedback += f"\nTest failure:\n```\n{test_error[:800]}\n```\n"

        retry_feedback += (
            "\nCRITICAL: Copy ALL '-' lines CHARACTER-FOR-CHARACTER from the file "
            "listing below. Do not paraphrase, truncate, or alter removed lines.\n"
        )

    # ── Temperature decay: more deterministic on each retry ───────────────────
    # retry 0 → settings.generator_temperature (e.g. 0.3)
    # retry 1 → 0.2,  retry 2 → 0.1,  retry 3+ → 0.0
    effective_temp = max(0.0, settings.generator_temperature - (0.1 * retry_count))
    if retry_count > 0:
        logger.info(
            f"[Generator] Temperature decayed to {effective_temp:.1f} "
            f"(base={settings.generator_temperature}, retry={retry_count})"
        )

    repo_root = state.get("repo_local_path", "")
    abs_path = state.get("file_path", "")
    try:
        rel_path = Path(abs_path).relative_to(repo_root).as_posix() if repo_root else abs_path
    except ValueError:
        rel_path = Path(abs_path).name

    full_file_context = _numbered_file(abs_path, flagged_line=issue.get("line", 0))
    context_for_prompt = full_file_context or state.get("method_context", "")

    # Extract the first 1-based line number visible in the numbered context so
    # the Generator prompt can anchor @@ offsets precisely.
    # _numbered_file() prefixes every code line with "NNNN  " — grab the first one.
    method_start_line: int = state.get("method_start_line", 0)
    if not method_start_line and context_for_prompt:
        _ln_match = re.search(r"^\s*(\d+)\s{2}", context_for_prompt, re.MULTILINE)
        if _ln_match:
            method_start_line = int(_ln_match.group(1))

    prompt_vars = {
        "rule_key": issue["rule_key"],
        "severity": issue["severity"],
        "message": issue["message"],
        "file_path": rel_path,
        "flagged_line": issue["line"],
        "method_start_line": method_start_line,
        "strategy": planner_out.get("strategy", ""),
        "method_context": context_for_prompt,
        "retry_feedback": retry_feedback,
    }

    t0 = time.time()
    response = _invoke_with_retry(
        generator_prompt, prompt_vars, "Generator",
        temperature=effective_temp,
    )
    elapsed = time.time() - t0

    raw = response.content if hasattr(response, "content") else str(response)
    logger.info(f"[Generator] LLM call completed in {elapsed:.2f}s")

    parsed: GeneratorOutput = _parse_json_response(raw, "Generator")  # type: ignore[assignment]
    parsed.setdefault("patch_hunks", "")
    parsed.setdefault("changed_methods", [])

    raw_patch = parsed["patch_hunks"]
    cleaned_patch = _clean_patch_hunks(raw_patch)
    if cleaned_patch != raw_patch:
        logger.info(
            f"[Generator] Stripped markdown fences from patch_hunks "
            f"(was {len(raw_patch)} chars, now {len(cleaned_patch)} chars)"
        )
    parsed["patch_hunks"] = cleaned_patch

    logger.info(
        f"[Generator] patch_lines={len(parsed['patch_hunks'].splitlines())} "
        f"changed_methods={parsed['changed_methods']}"
    )

    return {**state, "generator_output": parsed}


# ── LLM·3  Critic ─────────────────────────────────────────────────────────────

def _check_patch_touches_flagged_line(
    patch_hunks: str,
    flagged_line: int,
    tolerance: int = 3,
) -> tuple[bool, str]:
    """
    Deterministic pre-check: parse the unified diff and verify that at least
    one REMOVED ('-') line falls within `tolerance` lines of `flagged_line`.

    Returns:
        (True,  "")       — patch is correctly targeted
        (False, reason)   — patch does not touch the flagged line

    This check runs BEFORE the LLM Critic call so obviously mis-targeted
    patches are rejected instantly without spending an LLM token.

    Algorithm:
      For each @@ hunk header, advance an old-file line counter through the
      hunk body:
        '-' lines  → candidate removed line; advance counter
        ' ' lines  → context; advance counter
        '+' lines  → new lines only; do NOT advance old-file counter
      A hit is recorded when abs(current_old_line - flagged_line) <= tolerance.
    """
    if not patch_hunks or not patch_hunks.strip():
        return False, "Patch is empty."

    if flagged_line <= 0:
        # No line number to check against — let the LLM decide.
        return True, ""

    hunk_re = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", re.MULTILINE)
    matches = list(hunk_re.finditer(patch_hunks))

    if not matches:
        return False, "Patch contains no valid @@ hunk headers."

    for m in matches:
        old_start = int(m.group(1))
        # old_count = int(m.group(2) or 1)  # not used directly

        # Slice out this hunk's body (up to the next hunk header or EOF)
        body_start = m.end()
        next_m = hunk_re.search(patch_hunks, body_start)
        body = patch_hunks[body_start: next_m.start() if next_m else None]

        current_old_line = old_start
        for line in body.splitlines():
            if not line:
                current_old_line += 1
                continue
            prefix = line[0]
            if prefix == "-":
                if abs(current_old_line - flagged_line) <= tolerance:
                    return True, ""
                current_old_line += 1
            elif prefix == "+":
                pass  # '+' lines don't exist in the old file
            else:
                # context line (space) or other — advance old-file pointer
                current_old_line += 1

    return False, (
        f"No removed line within ±{tolerance} lines of flagged line {flagged_line}. "
        "The patch appears to target the wrong location."
    )


def critique_fix(state: AgentState) -> AgentState:
    """
    Adversarially review the generated patch.
    Populates state['critic_output'].

    Iteration 3 changes:
      - After recording the Critic verdict, adjusts planner_output['confidence']
        based on the outcome so the score used in deliver.py reflects the full
        pipeline rather than just the Planner's pre-generation guess:
          approved + no concerns  → +0.05  (clean approval, small boost)
          approved + concerns     →  0     (approved with notes, unchanged)
          rejected                → −0.15  (meaningful penalty)
        The adjusted value is clamped to [0, 1] and stored back in planner_output.

    Iteration 4 changes:
      - Deterministic pre-check (_check_patch_touches_flagged_line) runs BEFORE
        the LLM call. Patches that don't touch within ±3 lines of the flagged
        line are auto-rejected instantly, saving an LLM call.
      - LLM prompt now requests `flagged_line_found_in_hunk` as an explicit
        boolean field. If the LLM reports False, approved is forced to False
        regardless of the LLM's own `approved` value, closing a loophole where
        the LLM could silently approve a mis-targeted patch.
    """
    issue = state["current_issue"]
    generator_out = state.get("generator_output", {})
    patch_hunks = generator_out.get("patch_hunks", "")
    flagged_line: int = issue.get("line", 0)

    logger.info(f"[Critic] reviewing patch for rule={issue['rule_key']}")

    # ── Deterministic gate ────────────────────────────────────────────────────
    # Run BEFORE the LLM call — reject immediately if the patch obviously misses
    # the flagged line. This is cheap (pure regex) and catches the most common
    # failure mode: a plausible-looking diff that touches the wrong method/line.
    det_ok, det_reason = _check_patch_touches_flagged_line(patch_hunks, flagged_line)
    if not det_ok:
        logger.warning(f"[Critic] Deterministic gate FAILED: {det_reason}")
        parsed: CriticOutput = {
            "approved": False,
            "flagged_line_found_in_hunk": False,
            "concerns": [f"[auto-rejected by deterministic check] {det_reason}"],
        }
        # Skip LLM call — still apply confidence penalty below.
        approved = False
        concern_count = len(parsed["concerns"])
        planner_out = dict(state.get("planner_output", {}))
        current_conf: float = float(planner_out.get("confidence", 0.5))
        delta = -0.15
        adjusted_conf = round(min(max(current_conf + delta, 0.0), 1.0), 3)
        planner_out["confidence"] = adjusted_conf
        logger.info(
            f"[Critic] confidence adjusted: {current_conf:.3f} → {adjusted_conf:.3f} "
            f"(delta={delta:+.2f}, auto-rejected, concerns={concern_count})"
        )
        return {**state, "critic_output": parsed, "planner_output": planner_out}

    # ── LLM review ───────────────────────────────────────────────────────────
    changed_methods = generator_out.get("changed_methods", [])

    prompt_vars = {
        "rule_key": issue["rule_key"],
        "severity": issue["severity"],
        "message": issue["message"],
        "file_path": state.get("file_path", "unknown"),
        "flagged_line": flagged_line,
        "method_context": state.get("method_context", ""),
        "patch_hunks": patch_hunks,
        "changed_methods": ", ".join(changed_methods) if changed_methods else "unknown",
    }

    t0 = time.time()
    response = _invoke_with_retry(
        critic_prompt, prompt_vars, "Critic",
        temperature=settings.planner_temperature,
    )
    elapsed = time.time() - t0

    raw = response.content if hasattr(response, "content") else str(response)
    logger.info(f"[Critic] LLM call completed in {elapsed:.2f}s")

    parsed: CriticOutput = _parse_json_response(raw, "Critic")  # type: ignore[assignment]
    parsed.setdefault("approved", False)
    parsed.setdefault("concerns", [])
    parsed.setdefault("flagged_line_found_in_hunk", True)   # safe default for old responses

    # ── Safety override: if LLM says it didn't find the flagged line, force rejection ──
    if not parsed.get("flagged_line_found_in_hunk", True):
        if parsed.get("approved"):
            logger.warning(
                "[Critic] LLM reported flagged_line_found_in_hunk=false but approved=true "
                "— overriding to rejected (line-targeting failure takes precedence)."
            )
            parsed["approved"] = False
        if not any("flagged line" in c.lower() or "wrong location" in c.lower()
                   for c in parsed["concerns"]):
            parsed["concerns"].insert(
                0,
                f"Patch does not modify flagged line {flagged_line} "
                "(flagged_line_found_in_hunk=false reported by LLM).",
            )

    logger.info(
        f"[Critic] approved={parsed['approved']} "
        f"flagged_line_found_in_hunk={parsed.get('flagged_line_found_in_hunk')} "
        f"concerns={len(parsed['concerns'])}"
    )
    if not parsed["approved"]:
        for concern in parsed["concerns"]:
            logger.warning(f"[Critic] concern: {concern}")

    # ── Confidence adjustment based on Critic verdict ─────────────────────────
    planner_out = dict(state.get("planner_output", {}))
    current_conf: float = float(planner_out.get("confidence", 0.5))
    approved: bool = parsed["approved"]
    concern_count: int = len(parsed["concerns"])

    if approved and concern_count == 0:
        delta = +0.05   # clean approval → small boost
    elif approved:
        delta = 0.0     # approved with minor notes → no change
    else:
        delta = -0.15   # rejected → meaningful penalty

    adjusted_conf = round(min(max(current_conf + delta, 0.0), 1.0), 3)
    planner_out["confidence"] = adjusted_conf

    if delta != 0.0:
        logger.info(
            f"[Critic] confidence adjusted: {current_conf:.3f} → {adjusted_conf:.3f} "
            f"(delta={delta:+.2f}, approved={approved}, concerns={concern_count})"
        )

    return {**state, "critic_output": parsed, "planner_output": planner_out}


# ── File helpers ──────────────────────────────────────────────────────────────

def _numbered_file(file_path: str, max_lines: int = 300, flagged_line: int = 0) -> str:
    """
    Return file content with 1-based line numbers prepended, capped at max_lines.

    Truncation strategy (when file exceeds max_lines):
      The flagged line is ALWAYS included in the output. The budget is split into
      three regions so the LLM always sees the code it needs to modify:

        1. HEAD   — up to 40 lines from the top of the file (imports, class declaration)
        2. WINDOW — ±context_radius lines centred on the flagged line (the fix target)
        3. TAIL   — up to 20 lines from the bottom (closing braces, useful for structure)

      Regions are de-duplicated and presented in file order with gap markers so the
      LLM knows lines were omitted and doesn't confuse omitted line numbers.

      If flagged_line is 0 or not provided, falls back to the old head+tail strategy
      (safe for callers that don't have a line number, e.g. Critic node).

    Previous bug: head=150 + tail=50 always omitted the middle of large files.
    A 600-line file with a flagged line at line 300 would never show that line.
    """
    if not file_path:
        return ""
    try:
        lines = Path(file_path).read_text(encoding="utf-8", errors="replace").splitlines()
        total = len(lines)
        header = f"// {Path(file_path).name} — {total} lines total\n"

        if total <= max_lines:
            # File fits entirely — number and return everything
            numbered = "\n".join(f"{i+1:4d}  {l}" for i, l in enumerate(lines))
            return header + numbered

        # ── Truncation: build three regions centred on the flagged line ────────
        if flagged_line > 0:
            # Budget allocation out of max_lines:
            head_budget   = 40                        # imports + class declaration
            tail_budget   = 20                        # closing structure
            window_budget = max_lines - head_budget - tail_budget  # ~240 for default 300

            context_radius = window_budget // 2      # lines before AND after flagged line

            # Region 1: head (0-based indices)
            head_end = min(head_budget, total)        # exclusive

            # Region 2: window centred on flagged line (convert to 0-based)
            fl0 = flagged_line - 1                    # 0-based flagged line index
            win_start = max(0, fl0 - context_radius)
            win_end   = min(total, fl0 + context_radius + 1)

            # Expand window if we have budget left (flagged line near top/bottom)
            used = (win_end - win_start)
            spare = window_budget - used
            if spare > 0:
                # Grow toward whichever end has more room
                extra_before = min(spare // 2, win_start)
                extra_after  = min(spare - extra_before, total - win_end)
                win_start -= extra_before
                win_end   += extra_after

            # Region 3: tail
            tail_start = max(total - tail_budget, 0)  # 0-based

            # Merge overlapping / adjacent regions in file order
            # Each region is (start_0based, end_0based_exclusive)
            regions = _merge_regions([
                (0,          head_end),
                (win_start,  win_end),
                (tail_start, total),
            ], total)

            # Render with gap markers between non-contiguous regions
            parts: list[str] = []
            prev_end = 0
            for r_start, r_end in regions:
                if r_start > prev_end:
                    omitted = r_start - prev_end
                    parts.append(f"     ... ({omitted} lines omitted) ...")
                parts.append(
                    "\n".join(f"{r_start + i + 1:4d}  {lines[r_start + i]}"
                               for i in range(r_end - r_start))
                )
                prev_end = r_end

            if prev_end < total:
                parts.append(f"     ... ({total - prev_end} lines omitted) ...")

            numbered = "\n".join(parts)

        else:
            # No flagged_line provided — simple head + tail (safe fallback)
            head_n = max_lines - 50
            head   = lines[:head_n]
            tail   = lines[-50:]
            gap    = total - head_n - 50
            numbered = (
                "\n".join(f"{i+1:4d}  {l}" for i, l in enumerate(head))
                + f"\n     ... ({gap} lines omitted) ...\n"
                + "\n".join(f"{total - 49 + i:4d}  {l}" for i, l in enumerate(tail))
            )

        return header + numbered

    except OSError:
        return ""


def _merge_regions(
    regions: list[tuple[int, int]], total_lines: int
) -> list[tuple[int, int]]:
    """
    Merge a list of (start, end) 0-based half-open intervals into a sorted,
    non-overlapping list. Adjacent regions (gap == 0 or 1) are merged so we
    don't emit a "1 line omitted" gap marker for a single omitted blank line.
    """
    # Clamp to valid range
    clamped = [(max(0, s), min(total_lines, e)) for s, e in regions if s < e]
    sorted_regions = sorted(clamped, key=lambda r: r[0])

    merged: list[tuple[int, int]] = []
    for start, end in sorted_regions:
        if merged and start <= merged[-1][1] + 1:   # overlapping or adjacent
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))

    return merged