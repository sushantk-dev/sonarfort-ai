"""
SonarAI + FortifyAI — Unified Configuration  (Iteration 2)
All settings loaded from environment variables or .env file via Pydantic Settings.

New in Iteration 2:
  - chroma_persist_dir      : local path for ChromaDB vector store
  - langsmith_api_key       : LangSmith tracing
  - langsmith_project       : LangSmith project name
  - sonar_rescan_timeout    : seconds to wait for Sonar analysis after fix
  - enable_rag              : toggle RAG retrieval
  - enable_sonar_rescan     : toggle post-fix Sonar API verification
  - parallel_issues         : process issues in parallel via LangGraph Send API
  - max_parallel_workers    : cap on concurrent issue pipelines

Merged from FortifyAI:
  - fortify_username/password/scope : OAuth credential flow for Fortify token refresh
  - github_repo             : target repo in owner/repo format
  - project_path            : local Maven project root
  - adr_path                : path to adr.py remediation script
  - japicmp_jar_path        : path to japicmp fat-jar
  - max_upgrades            : cap on dependency upgrades per run
  - jira_id_prefix          : prefix for commit/branch JIRA identifiers
  - reviewers               : comma-separated GitHub reviewers for auto-assign
  - adr_output_dir          : local dir for ADR PDF reports and logs
"""

from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

import tempfile as _tempfile


_ENV_FILE = Path(__file__).parent.parent / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(_ENV_FILE),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── GCP / Vertex AI ──────────────────────────────────────────────────────
    gcp_project: str = Field(..., description="GCP project ID for Vertex AI")
    gcp_location: str = Field(default="us-central1", description="GCP region")
    vertex_model: str = Field(
        default="gemini-2.5-flash",
        description="Vertex AI model (Gemini fallback)",
    )
    vertex_fallback_model: str = Field(
        default="gemini-1.5-pro-002",
        description="Fallback model if primary is unavailable",
    )
    embedding_model: str = Field(
        default="text-embedding-005",
        description="Vertex AI embedding model",
    )
    max_tokens: int = Field(default=8192, description="Max tokens per LLM call")

    # ── GitHub ────────────────────────────────────────────────────────────────
    github_token: str = Field(..., description="GitHub personal access token")
    github_base_url: str = Field(
        default="https://api.github.com",
        description="GitHub API base URL (override for GHE)",
    )
    github_repo: str = Field(
        default="",
        description="Target GitHub repo in owner/repo format, e.g. acme/backend",
    )

    # ── Sonar ─────────────────────────────────────────────────────────────────
    sonar_token: str = Field(default="", description="SonarQube/SonarCloud API token")
    sonar_host_url: str = Field(
        default="https://sonarcloud.io",
        description="SonarQube host URL",
    )

    # ── Fortify ───────────────────────────────────────────────────────────────
    fortify_api_token: str = Field(
        default="",
        description=(
            "Fortify Bearer token. Leave empty to have the pipeline fetch it "
            "automatically via OAuth using fortify_username + fortify_password."
        ),
    )
    fortify_host_url: str = Field(
        default="https://api.ams.fortify.com",
        description="Fortify on Demand / SSC host URL",
    )
    fortify_username: str = Field(
        default="",
        description=(
            "Fortify login username, e.g. 'equifax\\\\sushant.kumar'. "
            "Used with POST /oauth/token (grant_type=password)."
        ),
    )
    fortify_password: str = Field(
        default="",
        description="Fortify login password. Used with POST /oauth/token.",
    )
    fortify_scope: str = Field(
        default="api-tenant",
        description="OAuth scope sent to /oauth/token (default: api-tenant).",
    )

    # ── Project / ADR paths ───────────────────────────────────────────────────
    project_path: str = Field(
        default=".",
        description="Absolute path to the Maven project root on disk",
    )
    adr_path: str = Field(
        default="",
        description="Absolute path to adr.py (Automated Dependency Remediation script)",
    )
    japicmp_jar_path: str = Field(
        default="",
        description="Absolute path to japicmp fat-jar for API diff analysis",
    )
    adr_output_dir: str = Field(
        default="/tmp/fortifyai",
        description="Local directory where ADR PDF reports and logs are written",
    )

    # ── Agent temperatures ────────────────────────────────────────────────────
    planner_temperature: float = Field(default=0.1, description="Temperature for the Planner LLM")
    generator_temperature: float = Field(default=0.3, description="Temperature for the Generator LLM")

    # ── Pipeline behaviour ────────────────────────────────────────────────────
    max_critic_retries: int = Field(default=3, description="Max LLM fix retry loops")
    compile_timeout: int = Field(default=120, description="mvn compile timeout seconds")
    test_timeout: int = Field(default=180, description="mvn test timeout seconds")
    clone_dir: str = Field(
        default_factory=lambda: str(Path(_tempfile.gettempdir()) / "sonar-ai-repos"),
        description="Base dir for cloned repos",
    )
    escalation_dir: str = Field(default="escalations", description="Dir for escalation markdown files")
    max_upgrades: int = Field(
        default=0,
        description=(
            "Maximum number of dependencies to upgrade in a single pipeline run. "
            "0 (default) means no limit — all triaged deps are processed. "
            "When set, deps are prioritised by severity (Critical → High → Medium → Low) "
            "and only the top N are forwarded to remediation."
        ),
        ge=0,
    )
    jira_id_prefix: str = Field(
        default="FORTIFY",
        description="Prefix used when generating commit/branch JIRA identifiers",
    )
    reviewers: str = Field(
        default="",
        description=(
            "Comma-separated GitHub usernames to auto-assign on high-confidence PRs. "
            "e.g. alice,bob,charlie"
        ),
    )

    # ── Confidence thresholds ─────────────────────────────────────────────────
    confidence_high_threshold: float = Field(default=0.8, description="Score >= this → HIGH confidence")
    confidence_medium_threshold: float = Field(default=0.5, description="Score >= this → MEDIUM confidence")

    # ── RAG / ChromaDB (Iteration 2) ─────────────────────────────────────────
    enable_rag: bool = Field(
        default=True,
        description="Enable ChromaDB RAG retrieval for prior fix examples",
    )
    chroma_persist_dir: str = Field(
        default_factory=lambda: str(Path(_tempfile.gettempdir()) / "sonar-ai-chroma"),
        description="Directory for ChromaDB persistent vector store",
    )
    rag_top_k: int = Field(default=3, description="Number of similar fixes to retrieve")

    # ── LangSmith tracing (Iteration 2) ──────────────────────────────────────
    langsmith_api_key: str = Field(default="", description="LangSmith API key for tracing")
    langsmith_project: str = Field(default="sonar-ai", description="LangSmith project name")
    langsmith_endpoint: str = Field(
        default="https://api.smith.langchain.com",
        description="LangSmith API endpoint",
    )

    # ── Sonar rescan (Iteration 2) ────────────────────────────────────────────
    enable_sonar_rescan: bool = Field(
        default=False,
        description="Query Sonar API after fix to verify the rule no longer fires",
    )
    sonar_rescan_timeout: int = Field(
        default=300,
        description="Max seconds to wait for Sonar analysis to complete",
    )

    # ── Parallel processing (Iteration 2) ────────────────────────────────────
    parallel_issues: bool = Field(
        default=False,
        description="Process multiple issues in parallel via LangGraph Send API",
    )
    max_parallel_workers: int = Field(
        default=3,
        description="Max concurrent issue pipelines when parallel_issues=True",
    )
    max_issues: int = Field(
        default=1,
        description="Max issues to process per run (0 = no limit)",
    )

    def get_reviewers(self) -> list[str]:
        """Parse the comma-separated reviewers string into a list."""
        if not self.reviewers.strip():
            return []
        return [r.strip() for r in self.reviewers.split(",") if r.strip()]


# Module-level singleton — import this everywhere
settings = Settings()


# ── LangSmith bootstrap ───────────────────────────────────────────────────────

def configure_langsmith() -> None:
    """
    Set LangSmith environment variables so LangChain auto-traces all LLM calls.
    Call once at startup before any LLM calls are made.
    Silently no-ops if langsmith_api_key is not configured.
    """
    import os
    if not settings.langsmith_api_key:
        return
    os.environ.setdefault("LANGCHAIN_TRACING_V2", "true")
    os.environ.setdefault("LANGCHAIN_API_KEY", settings.langsmith_api_key)
    os.environ.setdefault("LANGCHAIN_PROJECT", settings.langsmith_project)
    os.environ.setdefault("LANGCHAIN_ENDPOINT", settings.langsmith_endpoint)
    from loguru import logger
    logger.info(
        f"[LangSmith] Tracing enabled — project={settings.langsmith_project}"
    )