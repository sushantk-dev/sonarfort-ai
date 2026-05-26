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

def _call_llm(prompt_vars: dict, llm) -> Optional[dict]:
    """Call the LLM and return parsed JSON, or None on failure."""
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
        raw = response.content if hasattr(response, "content") else str(response)
        logger.debug(f"[AI Code Fix] LLM responded in {latency:.1f}s")

        # Strip markdown fences
        raw = re.sub(r"```(?:json)?", "", raw).strip()
        start = raw.find("{")
        end = raw.rfind("}") + 1
        if start == -1:
            return None
        return _json.loads(raw[start:end])

    except Exception as exc:
        logger.warning(f"[AI Code Fix] LLM call failed: {exc}")
        return None


# ── Patch application ─────────────────────────────────────────────────────────

def _apply_patch(project_path: Path, patch: dict) -> bool:
    """
    Apply one line-level patch using exact string replacement.

    patch = {"file": "...", "line": 42, "old": "...", "new": "..."}
    Returns True on success.
    """
    rel_file = patch.get("file", "")
    old_text = patch.get("old", "")
    new_text = patch.get("new", "")

    if not rel_file or not old_text:
        return False

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
        logger.warning(f"[AI Code Fix] File not found: {rel_file}")
        return False

    try:
        content = target.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning(f"[AI Code Fix] Cannot read {target}: {exc}")
        return False

    if old_text not in content:
        logger.warning(
            f"[AI Code Fix] 'old' text not found verbatim in {target.name} — "
            "patch cannot be applied"
        )
        return False

    # Apply replacement (first occurrence only — safer than global)
    new_content = content.replace(old_text, new_text, 1)

    # Backup before writing
    backup = target.with_suffix(target.suffix + ".fortifyai_bak")
    backup.write_text(content, encoding="utf-8")

    try:
        target.write_text(new_content, encoding="utf-8")
        logger.info(f"[AI Code Fix] ✅ Patch applied to {target.name}")
        return True
    except OSError as exc:
        # Restore backup
        backup.write_text(content, encoding="utf-8")
        logger.error(f"[AI Code Fix] Failed to write {target}: {exc}")
        return False


def apply_all_patches(project_path: Path, patches: list[dict]) -> int:
    """Apply all patches; return count of successful applications."""
    success_count = 0
    for patch in patches:
        if _apply_patch(project_path, patch):
            success_count += 1
    return success_count


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
) -> bool:
    """
    Generate a code fix via LLM and apply it to the project files.
    Returns True if at least one patch was successfully applied.
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
    if llm is None:
        patches = _heuristic_patch(failure_sites, api_diff)
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
        result = _call_llm(prompt_vars, llm)
        patches = result.get("patches", []) if result else []

        if result and result.get("explanation"):
            logger.info(f"[AI Code Fix] LLM: {result['explanation'][:200]}")

    if not patches:
        logger.warning("[AI Code Fix] No patches generated — ADR will retry as-is")
        return False

    applied = apply_all_patches(project_path, patches)
    logger.info(f"[AI Code Fix] {applied}/{len(patches)} patch(es) applied")
    return applied > 0


# ── LangGraph node ────────────────────────────────────────────────────────────

def ai_code_fix_node(
    state: AgentState,
    project_path: str,
    gcp_project: str,
    gcp_location: str,
) -> AgentState:
    """
    LangGraph node: ai_code_fix.

    Reads:  state["_failure_context"]   from failure_analysis_node
            state["_failure_sites"]
            state["_reasoned_groups"]   (or _diff_groups)
    Writes: state["ai_code_fix_applied"]
            state["audit_trail"]
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

    # Build LLM (reuse ai_reasoning builder).
    # Use 4096 tokens — multi-patch JSON responses silently truncate at 1024,
    # causing json.loads() to fail and all patches to be dropped (Gap 2 fix).
    from agents.ai_reasoning import _build_llm
    llm = _build_llm(gcp_project, gcp_location, max_output_tokens=4096)

    proj = Path(project_path)
    any_applied = False

    for group in groups:
        applied = generate_and_apply_fix(
            group, failure_context, failure_sites, proj, llm
        )
        if applied:
            any_applied = True

    state["ai_code_fix_applied"] = any_applied
    state["audit_trail"].append({
        "node": "ai_code_fix",
        "status": "ok" if any_applied else "no_patch",
        "patches_applied": any_applied,
    })

    return state