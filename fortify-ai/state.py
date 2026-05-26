"""
FortifyAI Agent State
---------------------
Single TypedDict passed through every node in the LangGraph pipeline.
All fields are Optional so each node can add its slice without requiring
earlier nodes to have run (useful for testing individual nodes).
"""

from __future__ import annotations

from typing import Any, Optional, TypedDict


# ── Nested types ─────────────────────────────────────────────────────────────

class DependencyInfo(TypedDict):
    group_id: str
    artifact_id: str
    current_version: str


class VersionCandidates(TypedDict):
    next_safe: Optional[str]
    greatest_safe: Optional[str]
    candidates: list[str]          # ordered: next_safe first, greatest_safe second
    explanation: str
    links: list[str]


class PomLocation(TypedDict):
    pom_file: str                  # relative path from project root
    line_number: Optional[int]
    is_direct: bool                # True = declared here; False = transitive
    version_property: Optional[str]  # e.g. "${spring.version}" or None if hardcoded
    property_defined_in: Optional[str]  # pom file where the property lives


class ApiDiffResult(TypedDict):
    has_breaking_changes: bool
    breaking_count: int
    affected_lines: list[str]      # e.g. ["Service.java:42", "Config.java:88"]
    raw_output: str                # full japicmp stdout


class AiReasoningResult(TypedDict):
    safe: bool
    confidence: str                # "high" | "medium" | "low"
    at_risk_lines: list[str]
    reason: str
    pre_fix_required: bool
    recommended_candidate: str


class AdrResult(TypedDict):
    success: bool
    branch_name: Optional[str]
    commit_hash: Optional[str]
    pdf_path: Optional[str]
    build_time_seconds: Optional[int]
    error_reason: Optional[str]


class PrResult(TypedDict):
    pr_url: str
    pr_number: int
    is_draft: bool


# ── Main state ────────────────────────────────────────────────────────────────

class AgentState(TypedDict):
    # ── Input ────────────────────────────────────────────────────────────────
    release_id: int                         # Fortify release ID passed via CLI
    vuln_id: Optional[str]                  # Fortify vulnerability UUID (per finding)
    cve_list: list[str]                     # CVE IDs for this dep, e.g. ["CVE-2024-38820"]
    max_upgrades: int                       # 0 = unlimited; N = cap deps at N (highest severity first)

    # ── Fortify finding fields ────────────────────────────────────────────────
    dependency: Optional[DependencyInfo]    # parsed from primaryLocation
    severity: Optional[str]                # "Critical" | "High" | "Medium" | "Low"
    owasp_2021: Optional[str]              # e.g. "A06:2021"
    sonatype_explanation: Optional[str]
    primary_location: Optional[str]        # raw string "group:artifact@version"
    is_suppressed: bool
    auditor_status: Optional[str]
    closed_status: bool

    # ── Version resolution ────────────────────────────────────────────────────
    version_candidates: Optional[VersionCandidates]
    current_candidate: Optional[str]       # candidate being attempted this iteration
    candidate_index: int                   # which candidate we're on (0-based)

    # ── Context agent output ──────────────────────────────────────────────────
    pom_location: Optional[PomLocation]
    calling_files: list[str]               # paths to Java files that use this dep
    calling_code_snippet: Optional[str]    # extracted code for AI reasoning

    # ── API diff agent output ─────────────────────────────────────────────────
    api_diff: Optional[ApiDiffResult]

    # ── AI reasoning agent output ─────────────────────────────────────────────
    ai_reasoning: Optional[AiReasoningResult]

    # ── ADR fix agent output ──────────────────────────────────────────────────
    adr_result: Optional[AdrResult]

    # ── Retry loop ────────────────────────────────────────────────────────────
    retry_count: int                       # incremented on each ADR failure
    last_build_error: Optional[str]        # Maven error log from last failed run
    ai_code_fix_applied: bool              # True once pre/post-patch fix has been tried

    # ── PR agent output ───────────────────────────────────────────────────────
    pr_result: Optional[PrResult]

    # ── Pipeline control ──────────────────────────────────────────────────────
    status: str                            # "running" | "fixed" | "escalated" | "skipped"
    skip_reason: Optional[str]            # populated when status == "skipped"
    escalation_reason: Optional[str]      # populated when status == "escalated"

    # ── Audit trail ───────────────────────────────────────────────────────────
    audit_trail: list[dict[str, Any]]      # append-only log of every agent action