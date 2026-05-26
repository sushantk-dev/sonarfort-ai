"""
SonarAI — LLM Prompt Templates  (Iteration 3)

Changes from Iteration 2:
  - Planner prompt now requests structured `confidence_factors` (5 sub-scores)
    instead of a single opaque confidence float, forcing the LLM to reason
    about each dimension before committing to a number.
  - Aggregation and calibration of sub-scores is handled in agents.py.

NOTE: All { } in system message strings that are NOT template variables must be
escaped as {{ }} — LangChain's ChatPromptTemplate treats any single { } as a
variable placeholder and raises KeyError if the variable is not supplied.
"""

from __future__ import annotations

from langchain_core.prompts import (
    ChatPromptTemplate,
    SystemMessagePromptTemplate,
    HumanMessagePromptTemplate,
)

# ── Shared system persona ─────────────────────────────────────────────────────

_EXPERT_JAVA_ENGINEER = (
    "You are an expert Java engineer specialising in code quality, security hardening, "
    "and static analysis remediation. You always produce minimal, correct, production-safe "
    "patches and explain your reasoning concisely. You NEVER hallucinate method names, "
    "line numbers, or imports that are not present in the provided context."
)

# ── LLM·1  Planner ────────────────────────────────────────────────────────────

PLANNER_SYSTEM = _EXPERT_JAVA_ENGINEER + (
    "\n\nYour job is to ANALYSE a SonarQube issue and produce a structured remediation plan. "
    "Think step-by-step before committing to a strategy. "
    "If prior fix examples are provided, use them to inform your approach — prefer patterns "
    "that have worked before for the same rule. "
    "Respond ONLY with a JSON object — no markdown fences, no extra text — matching this schema:\n"
    "{{\n"
    '  "reasoning": "<chain-of-thought explanation, up to 300 words>",\n'
    '  "strategy": "<concise 1-3 sentence description of the exact code change required>",\n'
    '  "confidence_factors": {{\n'
    '    "rule_understood": <float 0.0-1.0  how clearly you understand what this rule requires and why it fires here>,\n'
    '    "fix_is_mechanical": <float 0.0-1.0  1.0 = simple textual substitution with no logic change; 0.0 = requires deep architectural change>,\n'
    '    "context_sufficient": <float 0.0-1.0  how complete the provided code context is for making the change safely>,\n'
    '    "side_effects_risk": <float 0.0-1.0  1.0 = no realistic risk of regressions or new bugs; 0.0 = high risk>,\n'
    '    "rag_match_quality": <float 0.0-1.0  how closely the prior fix examples match this case; use 0.5 if none were provided>\n'
    "  }}\n"
    "}}\n\n"
    "Score each factor independently and honestly. "
    "Do NOT anchor all factors to the same value. "
    "A BLOCKER security rule with incomplete context should score low on context_sufficient and side_effects_risk "
    "even if rule_understood is high."
)

PLANNER_HUMAN = """\
## SonarQube Issue
- Rule:     {rule_key}
- Severity: {severity}
- Message:  {message}
- File:     {file_path}
- Line:     {flagged_line}

## Rule Knowledge Base Entry
{rule_kb_entry}

## Java Method Context (line numbers shown)
```java
{method_context}
```
{rag_context}
Analyse the issue and produce your remediation plan JSON.
"""

planner_prompt = ChatPromptTemplate.from_messages([
    SystemMessagePromptTemplate.from_template(PLANNER_SYSTEM),
    HumanMessagePromptTemplate.from_template(PLANNER_HUMAN),
])


# ── LLM·2  Generator ─────────────────────────────────────────────────────────

GENERATOR_SYSTEM = _EXPERT_JAVA_ENGINEER + (
    "\n\nYour job is to produce a MINIMAL UNIFIED DIFF that fixes the SonarQube issue. "
    "Rules:\n"
    "1. Output ONLY a JSON object — no markdown fences, no extra text.\n"
    "2. The diff MUST be a valid unified diff with correct @@ line offsets.\n"
    "   - Use the line numbers shown in the file listing to compute @@ offsets exactly.\n"
    "   - @@ format: -<old_start>,<old_count> +<new_start>,<new_count> @@\n"
    "   - old_start = the 1-based line number of the FIRST line in the hunk (from the listing).\n"
    "   - Include 3 lines of unchanged context before and after each change.\n"
    "3. The --- header must be:  --- a/<relative/path/to/File.java>\n"
    "   The +++ header must be:  +++ b/<relative/path/to/File.java>\n"
    "   Always use forward slashes, never backslashes.\n"
    "4. Change ONLY what is necessary to fix the reported issue.\n"
    "5. Preserve original indentation and style exactly.\n"
    "   CRITICAL: Every line you mark with '-' (remove) MUST be copied CHARACTER-FOR-CHARACTER\n"
    "   from the file listing above. Do NOT paraphrase, truncate, or alter the content of\n"
    "   removed lines in any way — even comments or log messages must be exact.\n"
    "6. Add required imports at the top of the file if the fix needs new classes.\n"
    "7. Do NOT change method signatures unless strictly required.\n"
    "8. Every context line inside a hunk MUST start with a single space character.\n\n"
    "ONE-SHOT EXAMPLE — study this before writing your diff:\n"
    "  Suppose 'Context starts at line: 42' and the listing shows:\n"
    "    42  public void processOrder(Order order) {{\n"
    "    43      validateOrder(order);\n"
    "    44      String id = order.getId();\n"
    "    45      logger.log(Level.FINE, \"Processing: \" + id);\n"
    "    46      fulfillOrder(order);\n"
    "    47  }}\n"
    "  Correct hunk (old_start=42, the line-number prefix of the FIRST hunk line):\n"
    "\n"
    "  @@ -42,6 +42,6 @@\n"
    "   public void processOrder(Order order) {{\n"
    "       validateOrder(order);\n"
    "       String id = order.getId();\n"
    "-      logger.log(Level.FINE, \"Processing: \" + id);\n"
    "+      logger.log(Level.FINE, \"Processing: {{}}\", id);\n"
    "       fulfillOrder(order);\n"
    "   }}\n"
    "\n"
    "  Key rules illustrated:\n"
    "  - @@ old_start (42) equals the 'Context starts at line' anchor from the prompt.\n"
    "  - Every unchanged context line starts with a single SPACE (not a digit).\n"
    "  - The '-' line is copied CHARACTER-FOR-CHARACTER from the listing.\n\n"
    "Response schema:\n"
    "{{\n"
    '  "patch_hunks": "<complete unified diff as a single string, use \\n for newlines>",\n'
    '  "changed_methods": ["<MethodName>", ...]\n'
    "}}"
)

GENERATOR_HUMAN = """\
## SonarQube Issue
- Rule:     {rule_key}
- Severity: {severity}
- Message:  {message}
- File:     {file_path}  ← use this exact path in --- / +++ headers (forward slashes)
- Flagged line: {flagged_line}

## Fix Strategy (from Planner)
{strategy}

## Complete File Listing (line numbers are exact — use them for @@ offsets)
- Context starts at line: {method_start_line}  ← your first @@ old_start must be ≥ this value
```java
{method_context}
```

{retry_feedback}
Produce the unified diff JSON now. Double-check that your @@ start line numbers
match the line numbers shown in the listing above.
"""

generator_prompt = ChatPromptTemplate.from_messages([
    SystemMessagePromptTemplate.from_template(GENERATOR_SYSTEM),
    HumanMessagePromptTemplate.from_template(GENERATOR_HUMAN),
])


# ── LLM·3  Critic ─────────────────────────────────────────────────────────────

CRITIC_SYSTEM = _EXPERT_JAVA_ENGINEER + (
    "\n\nYour job is to ADVERSARIALLY REVIEW a proposed code patch for a SonarQube issue. "
    "Work through the following steps IN ORDER before writing your verdict.\n\n"

    "STEP 1 — LINE TARGETING (most important check)\n"
    "  a. Note the flagged line number from the issue.\n"
    "  b. Parse every @@ hunk header in the diff to find which old-file line numbers "
    "     each hunk covers. A hunk starting at @@ -N,C @@ covers old lines N through N+C-1.\n"
    "  c. Walk the hunk body line by line, tracking the current old-file line number: "
    "     '-' lines and context lines advance the old-file counter; '+' lines do not.\n"
    "  d. Set flagged_line_found_in_hunk=true ONLY if at least one '-' (removed) line "
    "     falls within 3 lines of the flagged line number.\n"
    "  e. If flagged_line_found_in_hunk=false, set approved=false and add the concern: "
    "     'Patch does not modify the flagged line (line N) — wrong location targeted.'\n\n"

    "STEP 2 — RULE SATISFACTION\n"
    "  Confirm the removed '-' line(s) contain the exact pattern that triggers the rule "
    "  (e.g. System.out.println for S106, string concatenation in logger for S2629). "
    "  Confirm the added '+' line(s) eliminate that pattern without reintroducing it. "
    "  If the rule still fires after the patch, set approved=false.\n\n"

    "STEP 3 — COMPLETENESS\n"
    "  Scan the full method context for OTHER occurrences of the same anti-pattern. "
    "  If any exist and are not patched, add a concern (but this alone does not require "
    "  approved=false unless the fix is clearly incomplete).\n\n"

    "STEP 4 — SAFETY\n"
    "  Would the change introduce a NullPointerException, resource leak, changed "
    "  exception behaviour, or any regression in a non-error path? If so, add a concern "
    "  and set approved=false.\n\n"

    "STEP 5 — DIFF VALIDITY\n"
    "  Verify the @@ offsets are consistent with the line numbers in the method context. "
    "  Verify every '-' line matches the original source character-for-character. "
    "  If either check fails, set approved=false.\n\n"

    "STEP 6 — STYLE\n"
    "  Does the patch preserve original indentation, brace style, and import ordering? "
    "  Add a minor concern if not, but this alone does not require approved=false.\n\n"

    "Respond ONLY with a JSON object — no markdown fences, no extra text:\n"
    "{{\n"
    '  "approved": <true|false>,\n'
    '  "flagged_line_found_in_hunk": <true|false>,\n'
    '  "concerns": ["<specific concern 1>", ...]\n'
    "}}\n"
    "approved=false if ANY of steps 1, 2, 4, or 5 fail. "
    "If approved=true, concerns may be empty or list minor notes. "
    "If approved=false, every concern MUST be specific — name the exact line or pattern."
)

CRITIC_HUMAN = """\
## SonarQube Issue
- Rule:     {rule_key}
- Severity: {severity}
- Message:  {message}
- File:     {file_path}
- Flagged line: {flagged_line}  ← the patch MUST modify within ±3 lines of this

## Original Method Context (line numbers are exact)
```java
{method_context}
```

## Proposed Patch
```diff
{patch_hunks}
```

## Changed Methods Claimed
{changed_methods}

Work through Steps 1–6 in order. Confirm whether the diff touches line {flagged_line}.
Respond with your JSON verdict.
"""

critic_prompt = ChatPromptTemplate.from_messages([
    SystemMessagePromptTemplate.from_template(CRITIC_SYSTEM),
    HumanMessagePromptTemplate.from_template(CRITIC_HUMAN),
])


# ── RAG context formatter ─────────────────────────────────────────────────────

def format_rag_context(similar_fixes: list[dict]) -> str:
    """
    Format retrieved RAG examples into a human-readable block for the Planner prompt.
    Returns an empty string if no examples are provided.
    """
    if not similar_fixes:
        return ""

    lines = ["\n## Prior Fix Examples (from vector store — use as reference)"]
    for i, fix in enumerate(similar_fixes, 1):
        sim = fix.get("similarity", 0)
        rule = fix.get("rule_key", "")
        fname = fix.get("file_name", "")
        reasoning = fix.get("reasoning", "")
        patch_preview = fix.get("patch_hunks", "")[:300]

        lines.append(f"\n### Example {i} (rule={rule}, file={fname}, similarity={sim:.2f})")
        if reasoning:
            lines.append(f"**Reasoning:** {reasoning}")
        if patch_preview:
            lines.append(f"```diff\n{patch_preview}\n```")

    lines.append("")
    return "\n".join(lines)