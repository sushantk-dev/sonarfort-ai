"""
FortifyAI Configuration
-----------------------
All environment variables loaded via Pydantic BaseSettings, directly from
the process environment. No .env file is read — set the variables in the
shell, container, or orchestrator running this service.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator
from typing import Optional


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
    build_workflow_file: str = Field(
        default="runMavenSharedWorkflow.yml",
        description=(
            "Workflow file under .github/workflows/ dispatched by build_validation "
            "to run the Maven build on a GitHub Actions runner (this pipeline no "
            "longer runs mvn locally). Must declare 'on: workflow_dispatch'."
        ),
    )

    # ── Local Maven build (build_validation — Iteration 10+) ───────────────────
    # build_validation.py runs 'mvn clean install' LOCALLY on this pod, and
    # resolves JAVA_HOME from the project's detected required_jdk via
    # FORTIFYAI_JDK_REGISTRY when java_home isn't given explicitly — see
    # agents/build_validation.py's _resolve_java_home. These fields are the
    # process-wide defaults used by the full/partial pipeline runners
    # (_run_full_pipeline / _run_until); the standalone /stages/build-validation
    # endpoint takes the same knobs per-request via BuildValidationRequest.
    mvn_exe: str = Field(
        default="",
        description="Path to the mvn executable. Empty = auto-detect via PATH.",
    )
    java_home: str = Field(
        default="",
        validation_alias="FORTIFYAI_JAVA_HOME",
        description=(
            "Explicit JAVA_HOME override for the local mvn build. Bound to "
            "FORTIFYAI_JAVA_HOME (NOT the bare JAVA_HOME env var) on purpose — "
            "this pod's/shell's ambient JAVA_HOME is commonly already set for "
            "other tooling (this build_validation's own subprocess env, git, "
            "other Java tools on PATH, etc.) and Pydantic BaseSettings would "
            "otherwise silently bind a same-named field to it, making this "
            "'explicit override' actually always-on and permanently shadowing "
            "required_jdk/FORTIFYAI_JDK_REGISTRY (explicit always wins per "
            "build_validation._resolve_java_home's priority order) regardless "
            "of what JDK the project was detected to need. Set FORTIFYAI_JAVA_HOME "
            "only when you want to force one specific JDK for every build "
            "regardless of required_jdk; leave it unset to let the registry "
            "lookup do its job."
        ),
    )
    skip_tests: bool = Field(
        default=False,
        description="Pass -DskipTests to the local 'mvn clean install' build.",
    )
    build_threads: str = Field(
        default="1C",
        description=(
            "Value passed to Maven's -T flag, e.g. '1C' (one thread per CPU "
            "core), '4', or '1' (single-threaded, disables reactor parallelism)."
        ),
    )
    maven_heap_mb: Optional[int] = Field(
        default=None,
        ge=0,
        description=(
            "Per-JVM MAVEN_OPTS -Xmx cap for local mvn subprocess calls. "
            "None/omit = use build_validation's own default heap cap "
            "(currently 512MB); 0 disables the cap entirely."
        ),
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
    jira_ticket_id: str = Field(
        default="",
        description=(
            "Optional real JIRA ticket ID (e.g. 'PROJ-1234'). When set, overrides the "
            "auto-generated branch/commit naming: the ADR branch becomes "
            "'feature/<jira_ticket_id>-<uid>' and the commit subject is prefixed "
            "'<jira_ticket_id> : <msg>' instead of jira_id_prefix's generated ID. "
            "Empty (default) preserves the existing auto-generated naming."
        ),
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

    # ── Fortify Scan — ScanCentral packaging ─────────────────────────────────
    # Used by POST /fortify/scan to trigger an actual new SAST scan, as
    # opposed to every other endpoint here which only reads vulnerabilities
    # off an already-existing release.
    scancentral_exe: str = Field(
        default="scancentral",
        description=(
            "scancentral executable name/path. Default assumes it's on PATH "
            "(confirmed for this deployment) — set an absolute path if that "
            "ever changes."
        ),
    )
    scancentral_build_tool: str = Field(
        default="mvn",
        description="Build tool passed to `scancentral package -bt <value>`.",
    )
    scancentral_exclude_patterns: str = Field(
        default=(
            "DFD/**:CODEOWNERS:**/Dockerfile:**/Jenkinsfile:**/scm/**:"
            "**/sonar-project*:**/.gitignore:**/.gitattributes:**/.git:"
            "**/.git/**:**/.github:**/.github/**:**/.DS_Store"
        ),
        description=(
            "Colon-separated glob patterns passed to `scancentral package "
            "-exclude`."
        ),
    )
    scancentral_package_timeout_seconds: int = Field(
        default=900,
        ge=30,
        description="Subprocess timeout for `scancentral package` (Maven reactor resolution can be slow on large repos).",
    )

    # ── Fortify Scan — fcli / Fortify on Demand SAST submission ──────────────
    # fcli's FoD login (`fcli fod session login`) reuses fortify_base_url /
    # fortify_username / fortify_password above — no separate URL/creds
    # fields here, since /fortify/scan takes those as required per-request
    # inputs (not env defaults) rather than a standing server identity.
    fcli_jar_path: str = Field(
        default="fcli.jar",
        description="Absolute path to fcli.jar (Fortify CLI). Relative default assumes it's on the working directory/PATH.",
    )
    fod_tenant: str = Field(
        default="",
        description="Fortify on Demand tenant name, e.g. 'equifax' — passed to `fcli fod session login --tenant`.",
    )
    fod_session_name: str = Field(
        default="default",
        description="Name of the fcli FoD session created/reused by ensure_fod_session.",
    )
    fod_session_ttl_seconds: int = Field(
        default=18000,
        description=(
            "How long a freshly-logged-in fcli FoD session is trusted before "
            "ensure_fod_session re-logs in. Kept conservatively under the "
            "~6h expiry observed from fcli itself."
        ),
    )
    fod_remediation_preference: str = Field(
        default="NonRemediationScanOnly",
        description="Value passed to `fcli fod sast-scan start --remediation-preference`.",
    )
    fod_submit_timeout_seconds: int = Field(
        default=1800,
        ge=60,
        description=(
            "Subprocess timeout for `fcli fod sast-scan start` — this call "
            "uploads the packaged zip to FoD in chunks, which can take a "
            "long time for a large repo over a slow connection. 300s was "
            "the original placeholder default and is too short for a real "
            "upload; raise further if you're still seeing timeouts here on "
            "very large payloads."
        ),
    )
    scan_poll_interval_seconds: int = Field(
        default=60,
        ge=5,
        description="How often (fcli's own --interval and our own progress-tick granularity) to check scan status.",
    )
    scan_poll_timeout_seconds: int = Field(
        default=7200,
        ge=60,
        description="Overall budget for a scan to reach a terminal status before /fortify/scan gives up and fails the job.",
    )

    def get_reviewers(self) -> list[str]:
        """Parse the comma-separated reviewers string into a list."""
        if not self.reviewers.strip():
            return []
        return [r.strip() for r in self.reviewers.split(",") if r.strip()]

    def get_scancentral_exclude_patterns(self) -> list[str]:
        """Parse the colon-separated scancentral exclude patterns into a list."""
        return [p.strip() for p in self.scancentral_exclude_patterns.split(":") if p.strip()]

    # Env vars for executable/jar paths are easy to accidentally set WITH
    # the quotes needed for shell quoting still attached (e.g.
    # FCLI_JAR_PATH="C:\path\fcli.jar") — those quote characters then
    # become literal, non-existent path text once read as a raw env var
    # value (subprocess.run doesn't go through a shell, so it never strips
    # them). Strip one layer of wrapping quotes and surrounding whitespace
    # so a copy-pasted, shell-quoted value still works instead of failing
    # with a cryptic "Unable to access jarfile "..."" / "Executable not
    # found" error that looks like a wrong path rather than a formatting
    # mistake.
    @field_validator("scancentral_exe", "fcli_jar_path", mode="after")
    @classmethod
    def _strip_wrapping_quotes(cls, value: str) -> str:
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1].strip()
        return value


def load_config() -> FortifyAIConfig:
    """Load and validate config from the process environment only.

    No .env file is read or searched for — every field (and any extra
    `extra="allow"` vars) must be set as a real environment variable on
    the process running this service.
    """
    return FortifyAIConfig()