"""
FortifyAI — AI Code Fix Agent (Iteration 9b)
----------------------------------------------
Responsibility:
  When failure_analysis identifies broken call sites, call the LLM to
  generate a targeted Java source patch and apply it to the files before
  re-running ADR.

  Used in two positions in the pipeline:
    PRE-PATCH  (Iteration 7 routes medium/low confidence → here → ADR)
    POST-PATCH (Iteration 9 routes build failure → failure_analysis → here → ADR)

  LLM prompt: send the failing code context + API diff + error message →
  receive a unified diff or line-by-line replacement.

  Apply strategy:
    1. Try git apply --check (dry-run) to validate the patch
    2. Apply via pathlib str_replace if diff format; or write full file replacement
    3. If application fails → log and pass through (ADR will detect failure again)

Console output:
  [AI Code Fix] spring-context: generating fix for DataBinderService.java:42
  [AI Code Fix] ✅ Patch applied to DataBinderService.java
  [AI Code Fix] → re-running ADR
"""

from __future__ import annotations

import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

from loguru import logger

from state import AgentState

try:  # flat layout (token_tracker.py at repo root, next to state.py)
    from token_tracker import token_tracker
except ImportError:  # package layout
    from agents.token_tracker import token_tracker  # type: ignore


# ── Prompt templates ──────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are a senior Java engineer. Your task is to fix a Maven build failure
caused by a dependency version upgrade.

You will be given:
  - The dependency being upgraded (groupId:artifactId old → new)
  - The API changes (removed/changed methods from japicmp)
  - The failing Java code with line numbers and the exact compiler error
  - The Maven build error message

Your response MUST be a single JSON object with exactly these fields:
{
  "explanation":  "<1-2 sentences describing what changed and why>",
  "patches": [
    {
      "file":    "<relative path to the Java file>",
      "line":    <integer line number where the fix applies>,
      "old":     "<exact current line content (no leading whitespace trimmed)>",
      "new":     "<replacement line content>"
    }
  ]
}

Rules:
- Only patch what is broken; do not refactor unrelated code.
- The "old" string must match EXACTLY (same whitespace) what is in the file.
- If a method was removed, replace its call with the closest available equivalent.
- If a class was removed, update the import and usage.
- If there is no safe fix, return an empty patches list and explain why.
- Respond with JSON only — no preamble, no markdown fences.
"""

_USER_PROMPT_TEMPLATE = """\
Dependency upgrade:
  {group_id}:{artifact_id} {current_version} → {candidate}

API changes (japicmp):
{api_diff}

Maven build error:
{build_error}

Failing code (with line numbers):
{failure_context}

Generate the minimal patch to fix the compilation error. JSON only.
"""


# ── LLM call ──────────────────────────────────────────────────────────────────

def _call_llm(prompt_vars: dict, llm) -> tuple[Optional[dict], Optional[str]]:
    """
    Call the LLM and return (parsed JSON, failure_reason).

    failure_reason is None on success, otherwise a short human-readable
    string explaining why no usable patch JSON came back — this is
    surfaced all the way through to the escalation report, so it should
    stay specific enough to be useful to a developer reading it later.
    """
    import json as _json

    user_prompt = _USER_PROMPT_TEMPLATE.format(**prompt_vars)

    try:
        from langchain_core.messages import HumanMessage, SystemMessage  # type: ignore
        messages = [
            SystemMessage(content=_SYSTEM_PROMPT),
            HumanMessage(content=user_prompt),
        ]
        t0 = time.time()
        response = llm.invoke(messages)
        latency = time.time() - t0
        usage = token_tracker.record(
            "ai-code-fix", response, model=getattr(llm, "model_name", None),
        )
        raw = response.content if hasattr(response, "content") else str(response)
        logger.debug(
            f"[AI Code Fix] LLM responded in {latency:.1f}s "
            f"({usage['input_tokens']}→{usage['output_tokens']} tokens)"
        )

        # Strip markdown fences
        raw = re.sub(r"```(?:json)?", "", raw).strip()
        start = raw.find("{")
        end = raw.rfind("}") + 1
        if start == -1:
            reason = "LLM response contained no JSON object"
            logger.warning(f"[AI Code Fix] {reason}")
            return None, reason

        try:
            return _json.loads(raw[start:end]), None
        except _json.JSONDecodeError as exc:
            reason = f"LLM response was not valid JSON ({exc})"
            logger.warning(f"[AI Code Fix] {reason}")
            return None, reason

    except Exception as exc:
        reason = f"LLM call failed: {exc}"
        logger.warning(f"[AI Code Fix] {reason}")
        return None, reason


# ── Patch application ─────────────────────────────────────────────────────────

def _apply_patch(project_path: Path, patch: dict) -> tuple[bool, Optional[str]]:
    """
    Apply one line-level patch using exact string replacement.

    patch = {"file": "...", "line": 42, "old": "...", "new": "..."}
    Returns (success, failure_reason). failure_reason is None on success.
    """
    rel_file = patch.get("file", "")
    old_text = patch.get("old", "")
    new_text = patch.get("new", "")

    if not rel_file or not old_text:
        return False, "patch was missing a file path or 'old' text"

    # Locate the file
    candidates = [
        project_path / rel_file,
        *list(project_path.rglob(Path(rel_file).name)),
    ]
    target: Optional[Path] = None
    for c in candidates:
        if c.exists():
            target = c
            break

    if target is None:
        reason = f"{rel_file}: file not found in project"
        logger.warning(f"[AI Code Fix] File not found: {rel_file}")
        return False, reason

    try:
        content = target.read_text(encoding="utf-8")
    except OSError as exc:
        reason = f"{target.name}: could not read file ({exc})"
        logger.warning(f"[AI Code Fix] Cannot read {target}: {exc}")
        return False, reason

    if old_text not in content:
        reason = f"{target.name}: patch text did not match the file verbatim"
        logger.warning(
            f"[AI Code Fix] 'old' text not found verbatim in {target.name} — "
            "patch cannot be applied"
        )
        return False, reason

    # Apply replacement (first occurrence only — safer than global)
    new_content = content.replace(old_text, new_text, 1)

    # Backup before writing
    backup = target.with_suffix(target.suffix + ".fortifyai_bak")
    backup.write_text(content, encoding="utf-8")

    try:
        target.write_text(new_content, encoding="utf-8")
        logger.info(f"[AI Code Fix] ✅ Patch applied to {target.name}")
        return True, None
    except OSError as exc:
        # Restore backup
        backup.write_text(content, encoding="utf-8")
        reason = f"{target.name}: could not write file ({exc})"
        logger.error(f"[AI Code Fix] Failed to write {target}: {exc}")
        return False, reason


def apply_all_patches(project_path: Path, patches: list[dict]) -> tuple[int, list[str]]:
    """
    Apply all patches.
    Returns (count of successful applications, list of failure reasons for
    the patches that could not be applied).
    """
    success_count = 0
    failure_reasons: list[str] = []
    for patch in patches:
        applied, reason = _apply_patch(project_path, patch)
        if applied:
            success_count += 1
        elif reason:
            failure_reasons.append(reason)
    return success_count, failure_reasons


# ── Heuristic fallback ────────────────────────────────────────────────────────

def _heuristic_patch(
    failure_sites: list[dict],
    api_diff: dict,
) -> list[dict]:
    """
    When no LLM is available, attempt a best-effort heuristic patch.
    Currently returns an empty list — without an LLM we cannot safely
    generate Java source changes.  The retry loop will exhaust attempts
    and advance to the next candidate version instead.
    """
    logger.info(
        "[AI Code Fix] No LLM available — cannot generate heuristic patch. "
        "Retry loop will advance to next candidate."
    )
    return []


# ── Main fix function ─────────────────────────────────────────────────────────

def generate_and_apply_fix(
    group: dict,
    failure_context: str,
    failure_sites: list[dict],
    project_path: Path,
    llm,
) -> tuple[bool, Optional[str]]:
    """
    Generate a code fix via LLM and apply it to the project files.

    Returns (applied, failure_reason):
      - applied=True, failure_reason=None            → at least one patch applied
      - applied=False, failure_reason="<explanation>" → nothing applied, and why

    As a side effect, also stashes the outcome on ``group["ai_code_fix_reason"]``
    (cleared on success) — several callers (the REST pipeline in
    api_server.py in particular) pass the same group dict through multiple
    stages by reference, and read it back there rather than threading a
    return value through every intermediate call.
    """
    parsed = group["parsed"]
    artifact_id = parsed["artifact_id"]
    current_version = parsed["current_version"]
    candidate = group.get("current_candidate") or (
        group.get("version_candidates", {}).get("candidates", ["?"])[0]
    )

    for site in failure_sites[:3]:
        loc = f"{Path(site.get('file_path', '')).name}:{site.get('line_number', '?')}"
        logger.info(f"[AI Code Fix] {artifact_id}: generating fix for {loc}")

    api_diff = group.get("api_diff", {})
    raw_diff = api_diff.get("raw_output", "unavailable")[:2000]
    build_error = "\n".join(
        f"{s.get('file_path', '')}:{s.get('line_number', '?')}: {s.get('error_message', '')}"
        for s in failure_sites[:5]
    )

    # No LLM → heuristic (empty)
    llm_call_reason: Optional[str] = None
    explanation: Optional[str] = None
    if llm is None:
        patches = _heuristic_patch(failure_sites, api_diff)
        llm_call_reason = "no LLM configured — cannot generate a source patch"
    else:
        prompt_vars = {
            "group_id": parsed["group_id"],
            "artifact_id": artifact_id,
            "current_version": current_version,
            "candidate": candidate,
            "api_diff": raw_diff,
            "build_error": build_error,
            "failure_context": failure_context[:3000],
        }
        result, llm_call_reason = _call_llm(prompt_vars, llm)
        patches = result.get("patches", []) if result else []
        explanation = result.get("explanation") if result else None

        if explanation:
            logger.info(f"[AI Code Fix] LLM: {explanation[:200]}")

    if not patches:
        if llm_call_reason:
            reason = llm_call_reason
        elif explanation:
            reason = f"LLM returned no patches — {explanation}"
        else:
            reason = "LLM returned no patches and gave no explanation"
        logger.warning(f"[AI Code Fix] No patches generated — {reason}")
        group["ai_code_fix_reason"] = reason
        return False, reason

    applied, apply_failure_reasons = apply_all_patches(project_path, patches)
    logger.info(f"[AI Code Fix] {applied}/{len(patches)} patch(es) applied")

    if applied > 0:
        group["ai_code_fix_reason"] = None
        return True, None

    reason = (
        f"LLM proposed {len(patches)} patch(es) but none could be applied — "
        + "; ".join(apply_failure_reasons)
    ) if apply_failure_reasons else (
        f"LLM proposed {len(patches)} patch(es) but none could be applied"
    )
    group["ai_code_fix_reason"] = reason
    return False, reason


# ── LangGraph node ────────────────────────────────────────────────────────────

def ai_code_fix_node(
    state: AgentState,
    project_path: str,
    gcp_project: str,
    gcp_location: str,
    vertex_model: str = "gemini-2.5-flash",
    max_tokens: int = 8192,
) -> AgentState:
    """
    LangGraph node: ai_code_fix.

    Reads:  state["_failure_context"]   from failure_analysis_node
            state["_failure_sites"]
            state["_reasoned_groups"]   (or _diff_groups)
    Writes: state["ai_code_fix_applied"]
            state["audit_trail"]

    vertex_model: model name from VERTEX_MODEL config
    max_tokens:   max output tokens from MAX_TOKENS config (use \u22654096 for
                  multi-patch JSON responses to avoid silent truncation)
    """
    groups: list[dict] = (
        state.get("_reasoned_groups")  # type: ignore[attr-defined]
        or state.get("_diff_groups")   # type: ignore[attr-defined]
        or []
    )
    failure_context: str = state.get("_failure_context", "")  # type: ignore[attr-defined]
    failure_sites: list[dict] = state.get("_failure_sites", [])  # type: ignore[attr-defined]

    if not groups:
        logger.warning("[AI Code Fix] No groups in state — skipping")
        state["ai_code_fix_applied"] = False
        return state

    if state.get("is_jdk_mismatch"):
        logger.info(
            "[AI Code Fix] Skipping — last failure was a JDK/toolchain mismatch, "
            "not a code error. No source patch can fix this."
        )
        state["ai_code_fix_applied"] = False
        state["ai_code_fix_failure_reason"] = (  # type: ignore[typeddict-unknown-key]
            "Skipped — the build failure was a JDK/toolchain mismatch, not a "
            "code-level error, so no source patch could apply here"
        )
        state["audit_trail"].append({
            "node": "ai_code_fix",
            "status": "skipped",
            "reason": "jdk_mismatch",
        })
        return state

    # Build LLM using the configured model and token limit.
    # max_tokens should be \u22654096 for this agent — multi-patch JSON responses
    # silently truncate at lower limits, causing json.loads() to fail and all
    # patches to be dropped.
    from agents.ai_reasoning import _build_llm
    llm = _build_llm(gcp_project, gcp_location, model_name=vertex_model, max_output_tokens=max_tokens)

    proj = Path(project_path)
    any_applied = False
    failure_reasons: list[str] = []

    for group in groups:
        artifact_id = group["parsed"]["artifact_id"]
        applied, reason = generate_and_apply_fix(
            group, failure_context, failure_sites, proj, llm
        )
        if applied:
            any_applied = True
        elif reason:
            failure_reasons.append(f"{artifact_id}: {reason}")

    state["ai_code_fix_applied"] = any_applied
    combined_reason = "; ".join(failure_reasons) if failure_reasons else None
    if combined_reason:
        # Only overwrite state on failure — a later successful attempt should
        # not be masked by a stale reason from an earlier retry.
        state["ai_code_fix_failure_reason"] = combined_reason  # type: ignore[typeddict-unknown-key]
    elif any_applied:
        state["ai_code_fix_failure_reason"] = None  # type: ignore[typeddict-unknown-key]

    state["audit_trail"].append({
        "node": "ai_code_fix",
        "status": "ok" if any_applied else "no_patch",
        "patches_applied": any_applied,
        "failure_reason": combined_reason,
    })

    return state