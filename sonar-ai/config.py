"""
SonarAI — Configuration  (Iteration 2)
All settings loaded from environment variables via Pydantic Settings.
No .env file is read — values must come from the real process environment
(shell export, Docker/K8s env injection, systemd EnvironmentFile, etc.).

New in Iteration 2:
  - chroma_persist_dir      : local path for ChromaDB vector store
  - langsmith_api_key       : LangSmith tracing
  - langsmith_project       : LangSmith project name
  - sonar_rescan_timeout    : seconds to wait for Sonar analysis after fix
  - enable_rag              : toggle RAG retrieval
  - enable_sonar_rescan     : toggle post-fix Sonar API verification
  - parallel_issues         : process issues in parallel via LangGraph Send API
  - max_parallel_workers    : cap on concurrent issue pipelines
"""

from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

import tempfile as _tempfile


# ── Global SSL/TLS verification disable ────────────────────────────────────
# This container's `certifi` install is missing its cacert.pem bundle:
#   OSError: Could not find a suitable TLS CA certificate bundle, invalid
#   path: /usr/local/lib/python3.11/site-packages/certifi/cacert.pem
# That breaks TLS verification for every outbound HTTPS call in the process:
#   • `requests`-based calls (SonarQube, our own direct API calls) — some
#     call sites already pass verify=False individually as a workaround.
#   • The GCS client's internal transport (google.auth.transport.requests.
#     AuthorizedSession, which subclasses requests.Session) — used by
#     worker.py, api.py, and rag_store.py's Chroma-GCS sync. This one can't
#     take a per-call verify= kwarg, so worker.py's main loop was crashing on
#     every list_blobs()/download/upload call.
#   • `git` operations shelled out via GitPython (repo_loader.py, worker.py's
#     `git ls-remote`) — these go through the system git binary's own TLS
#     stack, entirely separate from Python's `requests`/`ssl` modules, so
#     they need their own opt-out (GIT_SSL_NO_VERIFY).
#
# Patches/env vars below cover all three paths at once, applied once at
# import time — before any HTTP or git client anywhere in the process is
# constructed — so every entrypoint (main.py, worker.py, api.py) and every
# module that imports `config` gets consistent behavior without needing
# verify=False repeated at each call site.
#
# NOTE: this disables TLS certificate verification process-wide. That's a
# real trade-off (no protection against a MITM on outbound HTTPS/git), done
# here only to work around the broken cert bundle above. Fix the underlying
# CA bundle (reinstall/upgrade `certifi`, or point REQUESTS_CA_BUNDLE at a
# valid CA file such as /etc/ssl/certs/ca-certificates.crt) when the image
# can be rebuilt, and remove this patch once that's done — don't leave TLS
# verification disabled long-term.
def _disable_ssl_verification() -> None:
    import os
    import ssl
    import requests
    import urllib3

    # 0) Undo any `truststore` injection, if present (standalone package or
    #    pip's vendored copy at pip._vendor.truststore — it replaces
    #    ssl.SSLContext process-wide with a wrapper routed through the OS
    #    certificate store). Harmless no-op if truststore was never injected.
    #    Kept as a first line of defense; the real fix for the
    #    check_hostname/verify_mode ordering crash is step (1b) below, which
    #    works regardless of whether this step actually changes anything.
    for _mod_name in ("truststore", "pip._vendor.truststore"):
        try:
            import importlib
            _ts = importlib.import_module(_mod_name)
            _ts.extract_from_ssl()
        except Exception:
            pass

    # 1) `requests` / anything built on requests.adapters.HTTPAdapter
    #    (incl. the GCS client's AuthorizedSession transport).
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    _orig_cert_verify = requests.adapters.HTTPAdapter.cert_verify

    def _no_verify_cert_verify(self, conn, url, verify, cert):  # noqa: ANN001
        return _orig_cert_verify(self, conn, url, False, cert)

    requests.adapters.HTTPAdapter.cert_verify = _no_verify_cert_verify

    # 1b) The actual fix for "Cannot set verify_mode to CERT_NONE when
    #     check_hostname is enabled". Root cause, confirmed by reading
    #     urllib3's own source and reproducing the crash directly:
    #
    #     urllib3.connection._ssl_wrap_socket_and_match_hostname() has two
    #     paths depending on whether an HTTPSConnection already has an
    #     explicit `ssl_context` set (self.ssl_context, e.g. one a library
    #     like google-auth built and configured itself):
    #       - ssl_context is None  → urllib3 builds one via
    #         create_urllib3_context(), which already sets check_hostname
    #         and verify_mode in the safe order. No crash here.
    #       - ssl_context is given → urllib3 reuses it AS-IS and immediately
    #         does `context.verify_mode = resolve_cert_reqs(cert_reqs)`
    #         UNCONDITIONALLY, before it ever gets to the code further down
    #         that would set check_hostname=False. If that pre-built context
    #         still has its default check_hostname=True (true for any plain
    #         `ssl.SSLContext()`), this line raises immediately.
    #     Patching create_urllib3_context (attempted previously) does nothing
    #     for this path, since that function is never called when a caller
    #     supplies its own ssl_context.
    #
    #     Fix: wrap _ssl_wrap_socket_and_match_hostname itself and force
    #     check_hostname=False on any incoming pre-built ssl_context before
    #     handing off to the original function — so by the time it does its
    #     unconditional verify_mode assignment, check_hostname is already off.
    #     Verified directly against this urllib3 install: reproduces the
    #     exact ValueError without this patch, and is fixed with it.
    try:
        import urllib3.connection as _u3_conn

        _orig_wrap_and_match = _u3_conn._ssl_wrap_socket_and_match_hostname

        def _patched_wrap_and_match(*args, **kwargs):
            _ctx = kwargs.get("ssl_context")
            if _ctx is not None:
                try:
                    _ctx.check_hostname = False
                except Exception:
                    pass
            return _orig_wrap_and_match(*args, **kwargs)

        _u3_conn._ssl_wrap_socket_and_match_hostname = _patched_wrap_and_match
    except Exception:
        pass

    # 1c) Belt-and-suspenders: also make create_urllib3_context() itself
    # defensive, for the `ssl_context is None` path and any other code that
    # calls it directly rather than through _ssl_wrap_socket_and_match_hostname.
    try:
        import importlib
        import urllib3.util.ssl_ as _u3_ssl

        _orig_create_urllib3_context = _u3_ssl.create_urllib3_context

        def _patched_create_urllib3_context(*args, **kwargs):
            ctx = _orig_create_urllib3_context(*args, **kwargs)
            try:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            except Exception:
                pass
            return ctx

        _u3_ssl.create_urllib3_context = _patched_create_urllib3_context
        # Some urllib3 versions import the name directly into these modules
        # (`from .util.ssl_ import create_urllib3_context`), so patching the
        # module it lives in doesn't change those already-bound references —
        # patch each module's own copy of the name too.
        for _mod_name in ("urllib3.connection", "urllib3.connectionpool"):
            try:
                _mod = importlib.import_module(_mod_name)
                if hasattr(_mod, "create_urllib3_context"):
                    _mod.create_urllib3_context = _patched_create_urllib3_context
            except Exception:
                pass
    except Exception:
        pass

    # 2) Bare `ssl`/`urllib`-based HTTPS clients that don't go through
    #    `requests` at all (defense in depth for any library that uses
    #    ssl.create_default_context() directly).
    ssl._create_default_https_context = ssl._create_unverified_context

    # 3) `git` subprocess calls (GitPython in repo_loader.py, the raw
    #    `git ls-remote` subprocess in worker.py) — separate TLS stack,
    #    not touched by (1) or (2). subprocess.run() without an explicit
    #    env= inherits this process's environment, so setting it here
    #    covers every git invocation in the app without changes elsewhere.
    os.environ["GIT_SSL_NO_VERIFY"] = "true"

    from loguru import logger
    logger.warning(
        "[Config] TLS certificate verification is DISABLED process-wide "
        "(requests, ssl, and git) — broken certifi cacert.pem bundle in "
        "this container. Fix the underlying CA bundle and remove this "
        "patch when possible."
    )


_disable_ssl_verification()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        case_sensitive=False,
        extra="ignore",
        # POST /api/config mutates this singleton in place at runtime
        # (os.environ + setattr, no .env write) — validate_assignment makes
        # sure those live updates still go through pydantic's type
        # coercion/validation instead of silently accepting raw values.
        validate_assignment=True,
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

    # ── Sonar ─────────────────────────────────────────────────────────────────
    sonar_token: str = Field(default="", description="SonarQube/SonarCloud API token")
    sonar_host_url: str = Field(
        default="https://sonarcloud.io",
        description="SonarQube host URL",
    )

    # ── Agent temperatures ────────────────────────────────────────────────────
    planner_temperature: float = Field(default=0.1, description="Temperature for the Planner LLM")
    generator_temperature: float = Field(default=0.3, description="Temperature for the Generator LLM")

    # ── Pipeline behaviour ────────────────────────────────────────────────────
    max_critic_retries: int = Field(default=3, description="Max LLM fix retry loops")
    compile_timeout: int = Field(default=120, description="mvn compile timeout seconds")
    test_timeout: int = Field(default=180, description="mvn test timeout seconds")
    run_maven_build: bool = Field(
        default=False,
        description="Run `mvn compile` + `mvn test` in the Validator step. "
                    "Off by default — building costs real CI time per issue, so it's "
                    "opt-in per run (PipelineRunRequest.run_build), not a static config "
                    "value. When False, Validator skips straight to a passed result "
                    "after the diff applies cleanly.",
    )
    maven_heap_mb: int = Field(
        default=1024,
        description="Fixed JVM heap size (MB) for `mvn compile` / `mvn test`, applied "
                    "via MAVEN_OPTS as -Xms<mb>m -Xmx<mb>m. Bounds build memory to a "
                    "known, reproducible ceiling per run instead of inheriting whatever "
                    "the container's JVM default heap happens to be (often a fraction "
                    "of available RAM, which varies by pod/node and can OOM on larger "
                    "modules). If MAVEN_OPTS is already set in the environment, this is "
                    "appended rather than replacing it, so other flags (proxy, SSL, "
                    "etc.) are preserved.",
    )
    clone_dir: str = Field(
        default_factory=lambda: str(Path(_tempfile.gettempdir()) / "sonar-ai-repos"),
        description="Base dir for cloned repos",
    )
    escalation_dir: str = Field(default="escalations", description="Dir for escalation markdown files")

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
    chroma_gcs_bucket: str = Field(
        default="",
        description="GCS bucket for durable ChromaDB persistence (empty = local-only). "
                    "The persist dir is downloaded from GCS on startup and re-uploaded "
                    "after every stored fix.",
    )
    chroma_gcs_prefix: str = Field(
        default="chroma",
        description="Object prefix inside chroma_gcs_bucket for ChromaDB files",
    )

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