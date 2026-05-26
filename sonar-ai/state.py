"""
SonarAI — Shared Agent State  (Iteration 3)
Passed through every node of the LangGraph state graph.
All fields are optional to allow partial population at different stages.

Iteration 2 additions:
  - rag_context        : similar prior fixes retrieved from ChromaDB
  - pipeline_results   : list of per-issue outcome dicts (for summary report)
  - sonar_rescan_ok    : result of post-fix Sonar API rescan
  - langsmith_run_id   : LangSmith trace ID for this pipeline run

Iteration 3 additions:
  - method_start_line  : 1-based line number of the first line in method_context,
                         used as an anchor in the Generator prompt so the LLM can
                         compute correct @@ offsets without guessing.

Iteration 4 additions:
  - severities         : comma-separated severity filter passed from the UI
                         e.g. "BLOCKER,CRITICAL" — applied in node_ingest
"""

from __future__ import annotations

from typing import Any, Optional
from typing_extensions import TypedDict


class SonarIssue(TypedDict):
    """A single parsed issue from sonar-report.json."""
    key: str               # Sonar issue key / UUID
    rule_key: str          # e.g. "java:S2259"
    severity: str          # BLOCKER | CRITICAL | MAJOR | MINOR | INFO
    component: str         # e.g. "my-project:src/main/java/Foo.java"
    line: int              # Flagged line number
    message: str           # Human-readable issue message
    status: str            # OPEN | CONFIRMED | etc.
    effort: str            # Remediation effort string


class PlannerOutput(TypedDict):
    """Output from LLM·1 (Planner)."""
    reasoning: str
    strategy: str
    confidence: float      # 0.0 – 1.0


class GeneratorOutput(TypedDict):
    """Output from LLM·2 (Generator)."""
    patch_hunks: str       # Unified diff text
    changed_methods: list[str]


class CriticOutput(TypedDict):
    """Output from LLM·3 (Critic)."""
    approved: bool
    concerns: list[str]
    flagged_line_found_in_hunk: bool   # True if the patch modifies the flagged line


class ValidationResult(TypedDict):
    diff_ok: bool
    compile_ok: bool
    tests_ok: bool
    compiler_error: str
    test_error: str


class RAGContext(TypedDict):
    """Prior fix examples retrieved from ChromaDB."""
    rule_key: str
    similar_fixes: list[dict[str, Any]]   # [{patch, reasoning, confidence, file}]
    retrieved_count: int


class SonarRuleDetail(TypedDict, total=False):
    """
    Live rule metadata fetched from the SonarQube /api/rules/show endpoint.
    Populated by the fetch_sonar_rule agent node.
    """
    rule_key: str
    name: str                # Human-readable rule name
    html_desc: str           # Full HTML description of the rule
    severity: str            # Default severity from the rule definition
    type: str                # BUG | CODE_SMELL | VULNERABILITY | SECURITY_HOTSPOT
    status: str              # READY | DEPRECATED | etc.
    lang: str                # e.g. "java"
    lang_name: str           # e.g. "Java"
    tags: list[str]          # e.g. ["unused", "java8"]
    sys_tags: list[str]
    rem_fn_type: str         # CONSTANT_ISSUE | LINEAR | etc.
    rem_fn_base_effort: str  # e.g. "1min"
    fix_summary: str         # Extracted plain-text fix guidance (Claude-distilled)


class IssueResult(TypedDict):
    """Per-issue outcome stored in pipeline_results list."""
    issue_key: str
    rule_key: str
    severity: str
    file_path: str
    line: int
    outcome: str           # "pr_opened" | "draft_pr" | "escalated" | "skipped" | "error"
    pr_url: Optional[str]
    escalation_path: Optional[str]
    confidence: float
    sonar_rescan_ok: Optional[bool]
    error: Optional[str]


class AgentState(TypedDict, total=False):
    # ── Input ─────────────────────────────────────────────────────────────────
    sonar_report_path: str          # Path to sonar-report.json
    repo_url: str                   # GitHub clone URL
    commit_sha: str                 # Exact commit SHA from Sonar scan

    # ── Severity filter (Iteration 4) ────────────────────────────────────────
    severities: str                 # Comma-separated e.g. "BLOCKER,CRITICAL,MAJOR"
                                    # Applied in node_ingest before any processing

    # ── Parsed issues ─────────────────────────────────────────────────────────
    issues: list[SonarIssue]        # All parsed, filtered, sorted issues
    current_issue_index: int        # Pointer into issues[]
    current_issue: SonarIssue       # Convenience alias

    # ── Repo state ────────────────────────────────────────────────────────────
    repo_local_path: str            # Absolute path to cloned repo
    fix_branch: str                 # Git branch name for this fix
    file_path: str                  # Absolute path to the .java file
    method_context: str             # Extracted method source (or ±50 line slice)
    method_start_line: int          # 1-based line number of the first line in method_context

    # ── Rule KB ───────────────────────────────────────────────────────────────
    rule_kb: dict[str, Any]         # rule_key → rule metadata dict

    # ── RAG (Iteration 2) ─────────────────────────────────────────────────────
    rag_context: RAGContext         # Similar prior fixes from ChromaDB

    # ── Live Sonar Rule Detail (Iteration 3) ──────────────────────────────────
    sonar_rule_detail: SonarRuleDetail   # Fetched from /api/rules/show

    # ── LLM outputs ───────────────────────────────────────────────────────────
    planner_output: PlannerOutput
    generator_output: GeneratorOutput
    critic_output: CriticOutput
    retry_count: int                # How many critic→generator retries so far

    # ── Validation ────────────────────────────────────────────────────────────
    validation: ValidationResult

    # ── Sonar Rescan (Iteration 2) ────────────────────────────────────────────
    sonar_rescan_ok: Optional[bool]         # True if rule no longer fires after fix
    sonar_rescan_message: str               # Human-readable rescan result

    # ── Delivery ──────────────────────────────────────────────────────────────
    pr_url: Optional[str]           # PR URL if opened
    escalation_path: Optional[str]  # Path to escalation .md if not PRed

    # ── Pipeline metadata ─────────────────────────────────────────────────────
    errors: list[str]               # Accumulated non-fatal errors / warnings
    done: bool                      # Signals terminal state to the graph

    # ── Multi-issue tracking (Iteration 2) ────────────────────────────────────
    pipeline_results: list[IssueResult]   # Accumulated results across all issues
    max_issues: int                       # Cap on how many issues to process
    langsmith_run_id: Optional[str]       # LangSmith trace ID