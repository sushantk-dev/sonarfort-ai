"""
FortifyAI Configuration
-----------------------
All environment variables loaded via Pydantic BaseSettings, directly from
the process environment. No .env file is read — set the variables in the
shell, container, or orchestrator running this service.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class FortifyAIConfig(BaseSettings):
    # ── Pydantic v2 settings config ──────────────────────────────────────────
    # env_file is intentionally omitted: values come from the real process
    # environment only, never from a .env file on disk.
    # extra="allow" preserves the original behaviour — any additional env vars
    # not declared as fields are still accessible on the config object.
    model_config = SettingsConfigDict(
        case_sensitive=False,
        extra="allow",
    )

    # ── Fortify SSC ──────────────────────────────────────────────────────────
    fortify_base_url: str = Field(
        default="",
        description="Fortify SSC base URL, e.g. https://api.ams.fortify.com",
    )
    fortify_api_token: str = Field(
        default="",
        description=(
            "Fortify Bearer token. Leave empty to have the API server fetch it "
            "automatically via OAuth using fortify_username + fortify_password."
        ),
    )

    # ── Fortify OAuth credentials (used to obtain / refresh the Bearer token) ─
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

    # ── GitHub ───────────────────────────────────────────────────────────────
    github_token: str = Field(
        default="",
        description="GitHub personal access token with repo + PR permissions",
    )
    github_repo: str = Field(
        default="",
        description="Target GitHub repo in owner/repo format, e.g. acme/backend",
    )

    # ── Project / ADR ────────────────────────────────────────────────────────
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

    # ── GCP / Vertex AI ──────────────────────────────────────────────────────
    gcp_project: str = Field(
        default="",
        description="GCP project ID for Vertex AI, e.g. my-gcp-project-123",
    )
    gcp_location: str = Field(
        default="us-central1",
        description="GCP region for Vertex AI endpoints",
    )
    vertex_model: str = Field(
        default="gemini-2.5-flash",
        description=(
            "Vertex AI model name used by the AI reasoning and code-fix agents. "
            "e.g. gemini-2.5-flash, gemini-2.5-pro, claude-sonnet-4-5@20251001"
        ),
    )
    max_tokens: int = Field(
        default=8192,
        description=(
            "Maximum output tokens for LLM calls. "
            "Use ≥4096 for AI Code Fix (multi-patch JSON); 1024 is sufficient for "
            "AI Reasoning verdicts."
        ),
        ge=256,
        le=65536,
    )

    # ── Pipeline behaviour ───────────────────────────────────────────────────
    max_retries: int = Field(
        default=3,
        description="Max AI code-fix retry attempts before escalating",
        ge=1,
        le=10,
    )
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

    # ── Optional ADR output path ─────────────────────────────────────────────
    adr_output_dir: str = Field(
        default="/tmp/fortifyai",
        description="Local directory where ADR PDF reports and logs are written",
    )

    def get_reviewers(self) -> list[str]:
        """Parse the comma-separated reviewers string into a list."""
        if not self.reviewers.strip():
            return []
        return [r.strip() for r in self.reviewers.split(",") if r.strip()]


def load_config() -> FortifyAIConfig:
    """Load and validate config from the process environment only.

    No .env file is read or searched for — every field (and any extra
    `extra="allow"` vars) must be set as a real environment variable on
    the process running this service.
    """
    return FortifyAIConfig()