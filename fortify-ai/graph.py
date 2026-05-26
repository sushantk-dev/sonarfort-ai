"""
FortifyAI LangGraph Pipeline
-----------------------------
All pipeline nodes are registered here. In Iteration 1 every node is a
stub that logs its name and passes state through unchanged.
Real logic is wired in subsequent iterations.

Node execution order (happy path):
  triage → version_resolver → context → api_diff
         → ai_reasoning → adr_fix → pr_agent → fortify_writeback → END

Conditional edges (retry / escalate) are declared as stubs now and will
be filled in during Iterations 8 & 9.
"""

from __future__ import annotations

from typing import Literal

from langgraph.graph import END, StateGraph
from loguru import logger

from agents.triage import triage_node
from agents.version_resolver import version_resolver_node
from agents.context import context_node
from agents.api_diff import api_diff_node
from agents.ai_reasoning import ai_reasoning_node, route_from_reasoning
from agents.adr_fix import adr_fix_node
from agents.failure_analysis import failure_analysis_node, decide_retry_route
from agents.ai_code_fix import ai_code_fix_node
from agents.pr_agent import pr_agent_node
from agents.fortify_writeback import fortify_writeback_node
from state import AgentState


# ── Stub node helpers ─────────────────────────────────────────────────────────

def _stub(name: str, state: AgentState) -> AgentState:
    """Generic stub: log the node name and return state unchanged."""
    logger.info(f"[{name}] node reached (stub — not yet implemented)")
    state["audit_trail"].append({"node": name, "status": "stub"})
    return state


# ── Node definitions (stubs) ──────────────────────────────────────────────────

def triage(state: AgentState) -> AgentState:
    """
    Iteration 3: Filter findings — skip suppressed / non-OSS / non-fixable.
    Delegates to agents.triage.triage_node.
    """
    return triage_node(state)


def version_resolver(state: AgentState) -> AgentState:
    """
    Iteration 4: Resolve next/greatest safe version from Fortify recommendations.
    Client is injected via closure when the graph is invoked — see fortifyai.py.
    Stub until client is bound; delegates to agents.version_resolver.version_resolver_node.
    """
    client = state.get("_client")  # type: ignore[attr-defined]
    if client is None:
        return _stub("VersionResolver", state)
    return version_resolver_node(state, client)


def context_agent(state: AgentState) -> AgentState:
    """
    Iteration 5: Locate dep in codebase — pom files + calling Java files.
    Delegates to agents.context.context_node.
    """
    project_path = state.get("_project_path")  # type: ignore[attr-defined]
    if project_path is None:
        return _stub("Context", state)
    return context_node(state, project_path)


def api_diff_agent(state: AgentState) -> AgentState:
    """
    Iteration 6: Run japicmp, parse breaking changes, map to calling files.
    Delegates to agents.api_diff.api_diff_node.
    """
    project_path = state.get("_project_path")  # type: ignore[attr-defined]
    japicmp_jar = state.get("_japicmp_jar")    # type: ignore[attr-defined]
    if project_path is None or japicmp_jar is None:
        return _stub("ApiDiff", state)
    return api_diff_node(state, project_path, japicmp_jar)


def ai_reasoning_agent(state: AgentState) -> AgentState:
    """
    Iteration 7: ChatVertexAI safety judgment — high/medium/low confidence.
    Delegates to agents.ai_reasoning.ai_reasoning_node.
    """
    gcp_project = state.get("_gcp_project")   # type: ignore[attr-defined]
    gcp_location = state.get("_gcp_location")  # type: ignore[attr-defined]
    if gcp_project is None:
        return _stub("AiReasoning", state)
    return ai_reasoning_node(state, gcp_project, gcp_location or "us-central1")


def adr_fix_agent(state: AgentState) -> AgentState:
    """
    Iteration 8: Invoke adr.py --commit --push, parse exit code + branch.
    Delegates to agents.adr_fix.adr_fix_node.
    """
    adr_path = state.get("_adr_path")          # type: ignore[attr-defined]
    project_path = state.get("_project_path")  # type: ignore[attr-defined]
    jira_prefix = state.get("_jira_prefix", "FORTIFY")  # type: ignore[attr-defined]
    if adr_path is None or project_path is None:
        return _stub("AdrFix", state)
    return adr_fix_node(state, adr_path, project_path, jira_prefix)


def failure_analysis_agent(state: AgentState) -> AgentState:
    """
    Iteration 9a: Parse Maven error log, prepare context for AI code fix.
    Delegates to agents.failure_analysis.failure_analysis_node.
    """
    project_path = state.get("_project_path")  # type: ignore[attr-defined]
    max_retries = state.get("_max_retries", 3)  # type: ignore[attr-defined]
    if project_path is None:
        return _stub("FailureAnalysis", state)
    return failure_analysis_node(state, project_path, max_retries)


def ai_code_fix_agent(state: AgentState) -> AgentState:
    """
    Iteration 9b: AI-generated patch for broken call sites after upgrade.
    Delegates to agents.ai_code_fix.ai_code_fix_node.
    """
    project_path = state.get("_project_path")  # type: ignore[attr-defined]
    gcp_project = state.get("_gcp_project", "")  # type: ignore[attr-defined]
    gcp_location = state.get("_gcp_location", "us-central1")  # type: ignore[attr-defined]
    if project_path is None:
        return _stub("AiCodeFix", state)
    return ai_code_fix_node(state, project_path, gcp_project, gcp_location)


def pr_agent(state: AgentState) -> AgentState:
    """
    Iteration 10: Create GitHub PR with full context, labels, draft flag.
    Delegates to agents.pr_agent.pr_agent_node.
    """
    github_token = state.get("_github_token", "")  # type: ignore[attr-defined]
    github_repo  = state.get("_github_repo", "")   # type: ignore[attr-defined]
    reviewers    = state.get("_reviewers", [])      # type: ignore[attr-defined]
    if not github_token or not github_repo:
        return _stub("PrAgent", state)
    return pr_agent_node(state, github_token, github_repo, reviewers)


def fortify_writeback_agent(state: AgentState) -> AgentState:
    """
    Iteration 11: Post fix outcome comment back to each Fortify vulnerability.
    Delegates to agents.fortify_writeback.fortify_writeback_node.
    """
    client = state.get("_fortify_client")  # type: ignore[attr-defined]
    if client is None:
        return _stub("FortifyWriteback", state)
    return fortify_writeback_node(state, client)


def escalate(state: AgentState) -> AgentState:
    """Terminal node: log escalation reason and mark state."""
    logger.warning(
        f"[Escalate] Escalating — reason: {state.get('escalation_reason', 'unknown')}"
    )
    state["status"] = "escalated"
    state["audit_trail"].append(
        {"node": "Escalate", "reason": state.get("escalation_reason")}
    )
    return state


# ── Routing functions (stubs) ─────────────────────────────────────────────────

def route_triage(
    state: AgentState,
) -> Literal["version_resolver", "escalate", END]:  # type: ignore[valid-type]
    """
    Iteration 3 will implement real skip logic.
    Stub: always proceed.
    """
    if state["status"] == "skipped":
        return END
    if state["status"] == "escalated":
        return "escalate"
    return "version_resolver"


def route_ai_reasoning(
    state: AgentState,
) -> Literal["adr_fix", "ai_code_fix", "escalate"]:
    """
    Iteration 7: Route based on AI confidence + safety verdict.
    Reads the first reasoned group's next_node from state.
    Falls back to adr_fix if not set (stub behaviour).
    """
    groups: list[dict] = state.get("_reasoned_groups", [])  # type: ignore[attr-defined]
    if not groups:
        return "adr_fix"
    # Use the first group's routing decision
    return groups[0].get("next_node", "adr_fix")


def route_build_result(
    state: AgentState,
) -> Literal["pr_agent", "failure_analysis", "escalate"]:
    """
    Iteration 8: Route based on ADR exit code.
    Reads state["adr_result"] set by adr_fix_node.
    """
    adr_result = state.get("adr_result")
    if adr_result is None:
        return "pr_agent"   # stub fallback
    if adr_result.get("success"):
        return "pr_agent"
    # Build failed — check retry budget
    retry_count = state.get("retry_count", 0)
    max_retries = 3  # matches config default; Iteration 9 will read from config
    if retry_count >= max_retries:
        return "escalate"
    return "failure_analysis"


def route_retry(
    state: AgentState,
) -> Literal["adr_fix", "version_resolver", "escalate"]:
    """
    Iteration 9: Route after failure_analysis based on retry budget and
    candidate availability. Reads state["_retry_route"] set by failure_analysis_node.
    """
    route = state.get("_retry_route", "escalate")  # type: ignore[attr-defined]
    if route == "retry":
        return "adr_fix"
    if route == "next":
        return "version_resolver"   # advance to next candidate version
    return "escalate"


# ── Graph assembly ────────────────────────────────────────────────────────────

def build_graph() -> StateGraph:
    """
    Assemble and compile the full FortifyAI LangGraph pipeline.
    Returns a compiled graph ready to invoke.
    """
    graph = StateGraph(AgentState)

    # Register all nodes
    graph.add_node("triage", triage)
    graph.add_node("version_resolver", version_resolver)
    graph.add_node("context", context_agent)
    graph.add_node("api_diff_agent", api_diff_agent)
    graph.add_node("ai_reasoning_agent", ai_reasoning_agent)
    graph.add_node("adr_fix", adr_fix_agent)
    graph.add_node("failure_analysis", failure_analysis_agent)
    graph.add_node("ai_code_fix", ai_code_fix_agent)
    graph.add_node("pr_agent", pr_agent)
    graph.add_node("fortify_writeback", fortify_writeback_agent)
    graph.add_node("escalate", escalate)

    # Entry point
    graph.set_entry_point("triage")

    # ── Edges ─────────────────────────────────────────────────────────────────

    # Triage → branch
    graph.add_conditional_edges(
        "triage",
        route_triage,
        {
            "version_resolver": "version_resolver",
            "escalate": "escalate",
            END: END,
        },
    )

    # Happy path (no conditionals yet)
    graph.add_edge("version_resolver", "context")
    graph.add_edge("context", "api_diff_agent")
    graph.add_edge("api_diff_agent", "ai_reasoning_agent")

    # AI reasoning → branch on confidence
    graph.add_conditional_edges(
        "ai_reasoning_agent",
        route_ai_reasoning,
        {
            "adr_fix": "adr_fix",
            "ai_code_fix": "ai_code_fix",
            "escalate": "escalate",
        },
    )

    # Pre-patch AI code fix → ADR fix
    graph.add_edge("ai_code_fix", "adr_fix")

    # ADR fix → branch on build result
    graph.add_conditional_edges(
        "adr_fix",
        route_build_result,
        {
            "pr_agent": "pr_agent",
            "failure_analysis": "failure_analysis",
            "escalate": "escalate",
        },
    )

    # Retry loop
    graph.add_conditional_edges(
        "failure_analysis",
        route_retry,
        {
            "adr_fix": "adr_fix",
            "version_resolver": "version_resolver",  # try next candidate
            "escalate": "escalate",
        },
    )

    # PR → writeback → end
    graph.add_edge("pr_agent", "fortify_writeback")
    graph.add_edge("fortify_writeback", END)

    # Escalate → end
    graph.add_edge("escalate", END)

    logger.info("[Graph] Pipeline graph assembled — all nodes registered")
    return graph


# ── Convenience: pre-compiled singleton ──────────────────────────────────────

_compiled_graph = None


def get_compiled_graph():
    """Return a cached compiled graph (compiled once on first call)."""
    global _compiled_graph
    if _compiled_graph is None:
        _compiled_graph = build_graph().compile()
        logger.info("[Graph] Graph compiled successfully")
    return _compiled_graph