"""
FortifyAI Configuration
-----------------------
All environment variables loaded via Pydantic BaseSettings.
Copy .env.example → .env and fill in your values before running.
"""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class FortifyAIConfig(BaseSettings):
    # ── Pydantic v2 settings config ──────────────────────────────────────────
    # Replaces the inner `class Config` (v1 pattern) so that _env_file passed
    # in load_config() is actually honoured instead of silently ignored.
    # extra="allow" preserves the original behaviour — any additional env vars
    # not declared as fields are still accessible on the config object.
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
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
    """Load and validate config from the correct .env file.

    Search order:
      1. .env in the same directory as this file (alongside config.py)
      2. .env in the current working directory (fallback)

    Using SettingsConfigDict (pydantic-settings v2) means _env_file passed
    to the constructor is honoured correctly, so the resolved path is the
    one that actually gets read.
    """
    parent_env = Path(__file__).resolve().parent.parent / ".env"
    local_env  = Path(".env")
    env_path   = str(parent_env) if parent_env.exists() else str(local_env)
    return FortifyAIConfig(_env_file=env_path)