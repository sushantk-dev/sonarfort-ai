"""
SonarAI — LangGraph State Graph  (Iteration 2)

Sequential pipeline (default):
  ingest → [for each issue] → load_repo → rag_retrieve → plan →
           generate → critique → validate → deliver → [next issue]

Parallel pipeline (parallel_issues=True):
  ingest → fan_out → [Send per issue] → per_issue_subgraph → collect_results

New in Iteration 2:
  - rag_retrieve node (ChromaDB prior fix lookup)
  - Multi-issue sequential processing loop
  - Parallel fan-out via LangGraph Send API
  - Pipeline summary report printed at end
  - LangSmith tracing bootstrap
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal, Annotated
import operator

from loguru import logger
from langgraph.graph import StateGraph, END
from langgraph.types import Send

from state import AgentState, SonarIssue, IssueResult
from config import settings, configure_langsmith
from parser import parse_sonar_report, load_rule_kb
from repo_loader import clone_repo, create_fix_branch, resolve_java_file, extract_method_context
from agents import plan_fix, generate_fix, critique_fix, retrieve_rag_context, fetch_sonar_rule
from validator import validate
from deliver import deliver


# ── Node: ingest ──────────────────────────────────────────────────────────────

def node_ingest(state: AgentState) -> AgentState:
    """Parse the Sonar report, load the Rule KB, set up the issue queue."""
    logger.info("[Ingest] Parsing Sonar report...")
    issues = parse_sonar_report(state["sonar_report_path"])
    rule_kb = load_rule_kb()

    # ── Apply severity filter ─────────────────────────────────────────────────
    # state["severities"] is guaranteed to exist because run_pipeline always
    # sets it in initial_state. AgentState now declares it as a typed field.
    sev_filter = state.get("severities", "").strip()
    if sev_filter:
        allowed_sevs = {s.strip().upper() for s in sev_filter.split(",") if s.strip()}
        before_count = len(issues)
        issues = [i for i in issues if i.get("severity", "").upper() in allowed_sevs]
        logger.info(
            f"[Ingest] Severity filter '{sev_filter}': "
            f"{before_count} → {len(issues)} issues remaining"
        )
    # ─────────────────────────────────────────────────────────────────────────

    # Apply max_issues cap (applied after severity filter)
    max_issues = state.get("max_issues", settings.max_issues)
    if max_issues and max_issues > 0 and len(issues) > max_issues:
        logger.info(f"[Ingest] Capping at {max_issues} issues (from {len(issues)} total)")
        issues = issues[:max_issues]

    if not issues:
        logger.warning("[Ingest] No actionable issues found — pipeline will exit")
        return {
            **state,
            "issues": [],
            "rule_kb": rule_kb,
            "current_issue_index": 0,
            "errors": [],
            "pipeline_results": [],
            "done": True,
        }

    logger.info(
        f"[Ingest] {len(issues)} issues queued. First: {issues[0]['rule_key']} "
        f"(line {issues[0]['line']}) in {issues[0]['component']}"
    )

    return {
        **state,
        "issues": issues,
        "rule_kb": rule_kb,
        "current_issue_index": 0,
        "current_issue": issues[0],
        "errors": state.get("errors", []),
        "pipeline_results": state.get("pipeline_results", []),
        "done": False,
    }


# ── Node: load_repo ───────────────────────────────────────────────────────────

def node_load_repo(state: AgentState) -> AgentState:
    """Clone the repo, checkout commit SHA, resolve file path, extract method context."""
    issue = state["current_issue"]
    logger.info(f"[LoadRepo] Loading repo for issue {issue['rule_key']}")

    repo = clone_repo(
        repo_url=state["repo_url"],
        clone_base_dir=settings.clone_dir,
        github_token=settings.github_token,
        commit_sha=state["commit_sha"],
    )

    repo_local_path = str(repo.working_dir)
    fix_branch = create_fix_branch(repo, issue["rule_key"], issue["key"])

    file_path = resolve_java_file(repo_local_path, issue["component"])
    if not file_path:
        error_msg = f"Cannot resolve file for component: {issue['component']}"
        logger.error(f"[LoadRepo] {error_msg}")
        errors = state.get("errors", []) + [error_msg]
        # Record a skipped result and move to next issue
        from deliver import _make_issue_result, _append_result
        result = _make_issue_result(
            issue, {**state, "file_path": ""},
            "error", 0.0, error=error_msg
        )
        return {**state, "errors": errors, "done": False, **_append_result(state, result)}

    method_context = extract_method_context(file_path, issue["line"])
    logger.info(f"[LoadRepo] Ready. file={Path(file_path).name} branch={fix_branch}")

    return {
        **state,
        "repo_local_path": repo_local_path,
        "fix_branch": fix_branch,
        "file_path": file_path,
        "method_context": method_context,
        "retry_count": 0,
        # Clear per-issue LLM outputs
        "planner_output": {},
        "generator_output": {},
        "critic_output": {},
        "validation": {},
        "rag_context": {},
        "pr_url": None,
        "escalation_path": None,
        "sonar_rescan_ok": None,
    }


# ── Node: rag_retrieve ────────────────────────────────────────────────────────

def node_rag_retrieve(state: AgentState) -> AgentState:
    """Retrieve similar prior fixes from ChromaDB (Iteration 2)."""
    return retrieve_rag_context(state)


# ── Node: fetch_rule ──────────────────────────────────────────────────────────

def node_fetch_rule(state: AgentState) -> AgentState:
    """Fetch live rule details from SonarQube /api/rules/show (Iteration 3)."""
    return fetch_sonar_rule(state)


# ── Node: plan ────────────────────────────────────────────────────────────────

def node_plan(state: AgentState) -> AgentState:
    """LLM·1 Planner — analyse issue and produce fix strategy."""
    return plan_fix(state)


# ── Node: generate ────────────────────────────────────────────────────────────

# node_generate is defined alongside route_after_critique above (handles retry_count increment)


# ── Node: critique ────────────────────────────────────────────────────────────

def node_critique(state: AgentState) -> AgentState:
    """LLM·3 Critic — review the generated patch."""
    return critique_fix(state)


# ── Node: validate ────────────────────────────────────────────────────────────

def node_validate(state: AgentState) -> AgentState:
    """Apply diff and run mvn compile + test."""
    return validate(state)


# ── Node: deliver ─────────────────────────────────────────────────────────────

def node_deliver(state: AgentState) -> AgentState:
    """Commit, push, open PR or write escalation. Store fix in RAG."""
    return deliver(state)


# ── Node: advance_issue ───────────────────────────────────────────────────────

def node_advance_issue(state: AgentState) -> AgentState:
    """
    Move the pointer to the next issue in the queue.
    Resets per-issue state fields and sets current_issue.
    """
    issues = state.get("issues", [])
    idx = state.get("current_issue_index", 0) + 1

    if idx >= len(issues):
        logger.info(f"[Pipeline] All {len(issues)} issue(s) processed")
        return {**state, "current_issue_index": idx, "done": True}

    next_issue: SonarIssue = issues[idx]
    logger.info(
        f"[Pipeline] Advancing to issue {idx + 1}/{len(issues)}: "
        f"{next_issue['rule_key']} in {next_issue['component']}"
    )

    return {
        **state,
        "current_issue_index": idx,
        "current_issue": next_issue,
        "done": False,
        # Reset per-issue fields
        "fix_branch": "",
        "file_path": "",
        "method_context": "",
        "retry_count": 0,
        "planner_output": {},
        "generator_output": {},
        "critic_output": {},
        "validation": {},
        "rag_context": {},
        "pr_url": None,
        "escalation_path": None,
        "sonar_rescan_ok": None,
    }


# ── Conditional edges ─────────────────────────────────────────────────────────

def route_after_critique(state: AgentState) -> Literal["validate", "generate"]:
    critic_out = state.get("critic_output", {})
    approved = critic_out.get("approved", False)
    retry_count = state.get("retry_count", 0)

    if approved:
        logger.info("[Router] Critic approved — proceeding to validate")
        return "validate"

    if retry_count < settings.max_critic_retries:
        logger.info(
            f"[Router] Critic rejected — retry {retry_count + 1}/{settings.max_critic_retries}"
        )
        # NOTE: retry_count is incremented inside node_generate (not here)
        # to avoid mutating shared state inside a pure routing function.
        return "generate"

    logger.warning("[Router] Critic rejected and retries exhausted — proceeding to validate")
    return "validate"


def node_generate(state: AgentState) -> AgentState:
    """
    LLM·2 Generator — produce unified diff patch.
    Increments retry_count when the critic has previously rejected the patch,
    so generate_fix() sees the correct count and decays temperature accordingly.
    """
    critic_out = state.get("critic_output", {})
    # If the critic has run and rejected, this is a retry — increment before calling generate
    if critic_out and not critic_out.get("approved", True):
        state = {**state, "retry_count": state.get("retry_count", 0) + 1}
    return generate_fix(state)


def route_after_ingest(state: AgentState) -> Literal["load_repo", END]:
    if state.get("done") or not state.get("issues"):
        return END
    return "load_repo"


def route_after_load_repo(state: AgentState) -> Literal["rag_retrieve", "advance_issue"]:
    """Skip to next issue if file resolution failed (no file_path set)."""
    if not state.get("file_path"):
        return "advance_issue"
    return "rag_retrieve"


def route_after_validate(state: AgentState) -> Literal["deliver", "generate"]:
    """
    If the diff failed to apply AND we still have retries left, route back to
    generate so the LLM can produce a corrected patch.
    This covers the case where the Critic approved the patch but it was still
    structurally corrupt (wrong offsets, hallucinated context lines, etc.).
    """
    validation = state.get("validation", {})
    retry_count = state.get("retry_count", 0)

    if not validation.get("diff_ok") and retry_count < settings.max_critic_retries:
        logger.info(
            f"[Router] Diff apply failed — routing back to generator "
            f"(retry {retry_count + 1}/{settings.max_critic_retries})"
        )
        return "generate"

    return "deliver"


def route_after_deliver(state: AgentState) -> Literal["advance_issue", END]:
    """After delivering one issue, advance to the next (or end if all done)."""
    issues = state.get("issues", [])
    idx = state.get("current_issue_index", 0)
    if idx + 1 >= len(issues):
        return END
    return "advance_issue"


def route_after_advance(state: AgentState) -> Literal["load_repo", END]:
    if state.get("done") or not state.get("issues"):
        return END
    return "load_repo"


# ── Sequential graph ──────────────────────────────────────────────────────────

def build_sequential_graph() -> StateGraph:
    """
    Assemble the sequential multi-issue SonarAI LangGraph.

    Flow: ingest → load_repo → rag_retrieve → plan → generate → critique
          → validate → deliver → [advance_issue → load_repo → ...] → END
    """
    graph = StateGraph(AgentState)

    graph.add_node("ingest", node_ingest)
    graph.add_node("load_repo", node_load_repo)
    graph.add_node("rag_retrieve", node_rag_retrieve)
    graph.add_node("fetch_rule", node_fetch_rule)
    graph.add_node("plan", node_plan)
    graph.add_node("generate", node_generate)
    graph.add_node("critique", node_critique)
    graph.add_node("validate", node_validate)
    graph.add_node("deliver", node_deliver)
    graph.add_node("advance_issue", node_advance_issue)

    graph.set_entry_point("ingest")

    graph.add_conditional_edges(
        "ingest", route_after_ingest, {"load_repo": "load_repo", END: END}
    )
    graph.add_conditional_edges(
        "load_repo", route_after_load_repo,
        {"rag_retrieve": "rag_retrieve", "advance_issue": "advance_issue"}
    )
    graph.add_edge("rag_retrieve", "fetch_rule")
    graph.add_edge("fetch_rule", "plan")
    graph.add_edge("plan", "generate")
    graph.add_edge("generate", "critique")
    graph.add_conditional_edges(
        "critique", route_after_critique,
        {"validate": "validate", "generate": "generate"},
    )
    graph.add_conditional_edges(
        "validate", route_after_validate,
        {"deliver": "deliver", "generate": "generate"}
    )
    graph.add_conditional_edges(
        "deliver", route_after_deliver,
        {"advance_issue": "advance_issue", END: END}
    )
    graph.add_conditional_edges(
        "advance_issue", route_after_advance,
        {"load_repo": "load_repo", END: END}
    )

    return graph.compile()


# ── Parallel graph ────────────────────────────────────────────────────────────

class ParallelPipelineState(AgentState, total=False):
    """Extended state for parallel fan-out — aggregates per-issue results."""
    # Using Annotated with operator.add so LangGraph can merge lists from parallel branches
    pipeline_results: Annotated[list[IssueResult], operator.add]  # type: ignore[assignment]


def node_fan_out(state: AgentState) -> list[Send]:
    """
    Emit one Send per issue to run them in parallel via LangGraph's Send API.
    Caps concurrency via max_parallel_workers by batching if needed.
    """
    issues = state.get("issues", [])
    base_state = {k: v for k, v in state.items() if k != "issues"}

    sends = []
    for i, issue in enumerate(issues):
        issue_state = {
            **base_state,
            "current_issue": issue,
            "current_issue_index": i,
            "retry_count": 0,
            "pipeline_results": [],
        }
        sends.append(Send("process_single_issue", issue_state))

    logger.info(f"[FanOut] Dispatching {len(sends)} parallel issue pipeline(s)")
    return sends


def _build_single_issue_subgraph() -> StateGraph:
    """Build the per-issue subgraph: load_repo → rag → plan → gen → critique → validate → deliver."""
    sg = StateGraph(AgentState)

    sg.add_node("load_repo", node_load_repo)
    sg.add_node("rag_retrieve", node_rag_retrieve)
    sg.add_node("fetch_rule", node_fetch_rule)
    sg.add_node("plan", node_plan)
    sg.add_node("generate", node_generate)
    sg.add_node("critique", node_critique)
    sg.add_node("validate", node_validate)
    sg.add_node("deliver", node_deliver)

    sg.set_entry_point("load_repo")

    sg.add_conditional_edges(
        "load_repo", route_after_load_repo,
        {"rag_retrieve": "rag_retrieve", "advance_issue": END}
    )
    sg.add_edge("rag_retrieve", "fetch_rule")
    sg.add_edge("fetch_rule", "plan")
    sg.add_edge("plan", "generate")
    sg.add_edge("generate", "critique")
    sg.add_conditional_edges(
        "critique", route_after_critique,
        {"validate": "validate", "generate": "generate"},
    )
    sg.add_conditional_edges(
        "validate", route_after_validate,
        {"deliver": "deliver", "generate": "generate"}
    )
    sg.add_edge("deliver", END)

    return sg.compile()


def build_parallel_graph() -> StateGraph:
    """
    Assemble the parallel fan-out SonarAI LangGraph.
    ingest → fan_out → [Send per issue → process_single_issue] → collect
    """
    graph = StateGraph(ParallelPipelineState)

    graph.add_node("ingest", node_ingest)
    graph.add_node("process_single_issue", _build_single_issue_subgraph())

    graph.set_entry_point("ingest")

    # Conditional entry: if no issues, skip to END; else fan out
    graph.add_conditional_edges(
        "ingest",
        lambda s: "fan_out" if (s.get("issues") and not s.get("done")) else END,
        {"fan_out": "process_single_issue", END: END},
    )

    # Fan-out: ingest → Send(process_single_issue) for each issue
    # LangGraph calls the conditional edge function and if it returns a list of Send,
    # it dispatches them all in parallel.
    graph.add_conditional_edges(
        "ingest",
        node_fan_out,
        {"process_single_issue": "process_single_issue"},
    )

    graph.add_edge("process_single_issue", END)

    return graph.compile()


# ── Public runner ─────────────────────────────────────────────────────────────

def build_graph():
    """Return the appropriate graph based on settings."""
    if settings.parallel_issues:
        logger.info("[Graph] Using PARALLEL fan-out graph")
        return build_parallel_graph()
    logger.info("[Graph] Using SEQUENTIAL multi-issue graph")
    return build_sequential_graph()


def run_pipeline(
    sonar_report_path: str,
    repo_url: str,
    commit_sha: str,
    max_issues: int = 0,
    severities: str = "BLOCKER,CRITICAL,MAJOR,MINOR,INFO",   # ← NEW
) -> AgentState:
    """
    Run the full SonarAI pipeline for all issues in the report.

    Args:
        sonar_report_path: Path to sonar-report.json
        repo_url:          GitHub HTTPS clone URL
        commit_sha:        Exact commit SHA used during the Sonar scan
        max_issues:        Cap on issues to process (0 = no limit)
        severities:        Comma-separated severities to fix,
                           e.g. "BLOCKER,CRITICAL" — defaults to all five

    Returns:
        Final AgentState after the pipeline completes.
    """
    # Bootstrap LangSmith tracing (Iteration 2)
    configure_langsmith()

    app = build_graph()

    initial_state: AgentState = {
        "sonar_report_path": sonar_report_path,
        "repo_url": repo_url,
        "commit_sha": commit_sha,
        "max_issues": max_issues or settings.max_issues,
        "severities": severities or "BLOCKER,CRITICAL,MAJOR,MINOR,INFO",   # ← NEW
        "pipeline_results": [],
        "errors": [],
    }

    logger.info("=" * 60)
    logger.info("SonarAI pipeline starting (Iteration 2)")
    logger.info(f"  report     : {sonar_report_path}")
    logger.info(f"  repo       : {repo_url}")
    logger.info(f"  commit     : {commit_sha}")
    logger.info(f"  severities : {severities}")              # ← NEW
    logger.info(f"  parallel   : {settings.parallel_issues}")
    logger.info(f"  rag        : {settings.enable_rag}")
    logger.info(f"  rescan     : {settings.enable_sonar_rescan}")
    logger.info("=" * 60)

    try:
        final_state = app.invoke(initial_state)
    except KeyboardInterrupt:
        logger.warning("[Pipeline] Interrupted by user (KeyboardInterrupt)")
        final_state = {
            **initial_state,
            "errors": ["Pipeline interrupted by user"],
            "pipeline_results": initial_state.get("pipeline_results", []),
            "done": True,
        }
    except Exception as exc:
        # Any exception that escapes all node-level try/catch blocks lands here.
        # We log the full traceback, build a minimal final state so _print_summary
        # can still run, and re-raise so the caller knows the pipeline failed.
        import traceback
        logger.error("[Pipeline] FATAL — unhandled exception escaped the graph:")
        logger.error(traceback.format_exc())

        # Attempt to salvage any results that were recorded before the crash
        partial_results = initial_state.get("pipeline_results", [])
        final_state = {
            **initial_state,
            "errors": [f"Fatal pipeline error: {type(exc).__name__}: {exc}"],
            "pipeline_results": partial_results,
            "done": True,
        }
        _print_summary(final_state)
        raise  # re-raise so CI / calling code sees a non-zero exit

    _print_summary(final_state)

    return final_state


# ── Summary report ────────────────────────────────────────────────────────────

def _print_summary(final_state: AgentState) -> None:
    """Print a human-readable pipeline summary with outcome per issue. Never raises."""
    try:
        _print_summary_inner(final_state)
    except Exception as exc:
        logger.warning(f"[Pipeline] Summary rendering failed (non-fatal): {exc}")


def _print_summary_inner(final_state: AgentState) -> None:
    """Inner summary logic — called by _print_summary inside a safety try/except."""
    results: list[IssueResult] = final_state.get("pipeline_results", [])
    errors: list[str] = final_state.get("errors", [])

    logger.info("=" * 60)
    logger.info("SonarAI Pipeline Summary")
    logger.info("=" * 60)

    if not results:
        logger.info("No issues processed")
        logger.info("=" * 60)
        return

    counts = {"pr_opened": 0, "draft_pr": 0, "escalated": 0, "skipped": 0, "error": 0}

    for r in results:
        outcome = r.get("outcome", "unknown")
        counts[outcome] = counts.get(outcome, 0) + 1

        icon = {
            "pr_opened": "✅",
            "draft_pr": "📝",
            "escalated": "⚠️ ",
            "skipped":   "⏭️ ",
            "error":     "❌",
        }.get(outcome, "❓")

        rule = r.get("rule_key", "")
        severity = r.get("severity", "")
        conf = r.get("confidence", 0.0)
        file_name = Path(r.get("file_path", "unknown")).name
        line = r.get("line", 0)

        detail = r.get("pr_url") or r.get("escalation_path") or r.get("error") or ""
        rescan = ""
        if r.get("sonar_rescan_ok") is True:
            rescan = " [rescan: ✅]"
        elif r.get("sonar_rescan_ok") is False:
            rescan = " [rescan: ❌]"

        logger.info(
            f"  {icon} {rule} ({severity}) in {file_name}:{line} "
            f"— conf={conf:.0%} → {outcome}{rescan}"
        )
        if detail:
            logger.info(f"     └─ {detail}")

    logger.info("-" * 60)
    logger.info(
        f"  Total: {len(results)} | "
        f"PR: {counts['pr_opened']} | "
        f"Draft: {counts['draft_pr']} | "
        f"Escalated: {counts['escalated']} | "
        f"Errors: {counts['error']}"
    )

    if errors:
        logger.warning(f"  Non-fatal errors: {len(errors)}")
        for e in errors[:5]:
            logger.warning(f"    • {e}")

    # Write JSON summary file
    _write_summary_json(results)

    logger.info("=" * 60)


def _write_summary_json(results: list[IssueResult]) -> None:
    """Write a machine-readable JSON summary to pipeline_summary.json."""
    summary_path = Path("pipeline_summary.json")
    try:
        summary = {
            "total": len(results),
            "results": [
                {
                    "issue_key": r.get("issue_key", ""),
                    "rule_key": r.get("rule_key", ""),
                    "severity": r.get("severity", ""),
                    "file": Path(r.get("file_path", "")).name,
                    "line": r.get("line", 0),
                    "outcome": r.get("outcome", ""),
                    "confidence": r.get("confidence", 0.0),
                    "pr_url": r.get("pr_url"),
                    "escalation_path": r.get("escalation_path"),
                    "sonar_rescan_ok": r.get("sonar_rescan_ok"),
                }
                for r in results
            ],
        }
        summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        logger.info(f"[Summary] Written to {summary_path}")
    except Exception as exc:
        logger.warning(f"[Summary] Could not write JSON summary: {exc}")