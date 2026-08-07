"""
FortifyAI — CLI Entry Point
----------------------------
Usage:
    python fortifyai.py --release <RELEASE_ID>
    python fortifyai.py --release 0 --report /path/to/report.json   # offline mode
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

from loguru import logger

from config import FortifyAIConfig, load_config
from fortify_client import FortifyClient
from graph import get_compiled_graph
from state import AgentState


# ── Logging setup ─────────────────────────────────────────────────────────────

def configure_logging(verbose: bool = False) -> None:
    """Configure loguru: one line per event, coloured, with timestamps."""
    logger.remove()
    level = "DEBUG" if verbose else "INFO"
    logger.add(
        sys.stderr,
        level=level,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{line}</cyan> — "
            "<level>{message}</level>"
        ),
        colorize=True,
    )


# ── Background Maven cache warm-up ──────────────────────────────────────────────
#
# adr_fortify.py's Phase 1b (mvn dependency:tree) tries an offline resolution
# first and only falls back to a live remote fetch if the local .m2 cache is
# incomplete — that remote fallback is what makes ADR runs slow (silently, for
# up to 5 minutes, since it's not streamed). By the time the pipeline reaches
# adr_fix, triage / version-resolution / context-location / api-diff have
# already spent real wall-clock time doing non-Maven work — this warms the
# .m2 cache in a background thread during that window so the offline attempt
# inside adr_fortify.py is more likely to succeed outright.
#
# This is strictly best-effort: failure or a slow/incomplete warm-up here is
# never fatal — adr_fortify.py's own offline→online fallback logic still runs
# exactly as before and handles a cold or partially-warmed cache correctly.

def _warm_maven_cache(project_path: str) -> None:
    """Run 'mvn dependency:go-offline' in the background to pre-populate the
    local .m2 repository while earlier pipeline stages (triage, version
    resolution, context location, api-diff) are doing non-Maven work.

    Runs on a daemon thread — never joined/blocked on by the main pipeline,
    so it can only ever help (a warmer cache by the time adr_fix runs) and
    never slow anything down or hang the process on exit.
    """
    try:
        pom = Path(project_path) / "pom.xml"
        if not pom.is_file():
            logger.debug(f"[MavenWarm] No pom.xml at {project_path} — skipping warm-up")
            return

        mvn_exe = shutil.which("mvn")
        if not mvn_exe:
            logger.debug("[MavenWarm] mvn not found on PATH — skipping warm-up")
            return

        logger.info(f"[MavenWarm] Starting background 'mvn dependency:go-offline' "
                    f"on {pom} ...")
        t0 = time.time()
        result = subprocess.run(
            [mvn_exe, "dependency:go-offline", "-f", str(pom), "--no-transfer-progress"],
            capture_output=True, text=True,
            timeout=280,   # stay under adr_fortify.py's own 300s fallback timeout
        )
        elapsed = time.time() - t0
        if result.returncode == 0:
            logger.info(f"[MavenWarm] ✅ .m2 cache warmed in {elapsed:.0f}s — "
                        f"adr_fortify.py's offline dependency:tree should now succeed")
        else:
            logger.warning(f"[MavenWarm] go-offline exited {result.returncode} after "
                            f"{elapsed:.0f}s — adr_fortify.py will fall back to its own "
                            f"online resolution as usual")
    except subprocess.TimeoutExpired:
        logger.warning("[MavenWarm] go-offline timed out after 280s — proceeding; "
                        "adr_fortify.py will still fall back to its own resolution")
    except Exception as exc:
        logger.warning(f"[MavenWarm] skipped due to error: {exc}")


def _start_maven_warmup(project_path: "Path | str") -> "threading.Thread | None":
    """Kick off _warm_maven_cache() on a daemon thread. Returns the thread
    (for optional status logging later) or None if it couldn't be started."""
    try:
        thread = threading.Thread(
            target=_warm_maven_cache, args=(str(project_path),),
            name="maven-cache-warmup", daemon=True,
        )
        thread.start()
        return thread
    except Exception as exc:
        logger.warning(f"[MavenWarm] could not start background warm-up: {exc}")
        return None


# ── State factory ─────────────────────────────────────────────────────────────

def initial_state(release_id: int, max_upgrades: int = 0) -> AgentState:
    """Return a fully-typed initial AgentState for a new pipeline run."""
    return AgentState(
        release_id=release_id,
        max_upgrades=max_upgrades,
        vuln_id=None,
        cve_list=[],
        dependency=None,
        severity=None,
        owasp_2021=None,
        sonatype_explanation=None,
        primary_location=None,
        is_suppressed=False,
        auditor_status=None,
        closed_status=False,
        version_candidates=None,
        current_candidate=None,
        candidate_index=0,
        pom_location=None,
        calling_files=[],
        calling_code_snippet=None,
        api_diff=None,
        ai_reasoning=None,
        adr_result=None,
        retry_count=0,
        last_build_error=None,
        ai_code_fix_applied=False,
        required_jdk=None,
        is_jdk_mismatch=None,
        jdk_mismatch_version=None,
        pr_result=None,
        status="running",
        skip_reason=None,
        escalation_reason=None,
        audit_trail=[],
    )


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="fortifyai",
        description="FortifyAI — Automated Security Dependency Remediation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Live mode — by release ID
  python fortifyai.py --release 1723380

  # Live mode — by application name (resolves latest release automatically)
  python fortifyai.py --app-name 1038_US_D360-Citi-Triggers-on-Cloud_USIS

  # List all releases for an application and exit (no pipeline run)
  python fortifyai.py --app-name 1038_US_D360-Citi-Triggers-on-Cloud_USIS --list-releases

  # Application name with repo override
  python fortifyai.py --app-name 1038_US_D360-Citi-Triggers-on-Cloud_USIS --repo acme/backend

  # Override repo at runtime (no need to edit environment variables)
  python fortifyai.py --release 1723380 --repo acme/backend

  # Offline mode with repo override
  python fortifyai.py --report /path/to/report.json --repo acme/backend

  # Verbose debug logging
  python fortifyai.py --release 1723380 --verbose
        """,
    )
    parser.add_argument(
        "--release",
        type=int,
        default=0,
        metavar="RELEASE_ID",
        help=(
            "Fortify SSC release ID to remediate (e.g. 1723380). "
            "Defaults to 0 when --report is used and the ID is embedded in the file."
        ),
    )
    parser.add_argument(
        "--report",
        metavar="JSON_FILE",
        default=None,
        help=(
            "Path to a saved Fortify API JSON report file. "
            "When supplied, skips all live Fortify API calls — "
            "useful for testing without SSC credentials. "
            "Accepts the raw /vulnerabilities endpoint response or a bare list."
        ),
    )
    parser.add_argument(
        "--repo",
        metavar="OWNER/REPO",
        default=None,
        help=(
            "GitHub repository in owner/repo format (e.g. acme/backend). "
            "Overrides the GITHUB_REPO environment variable when provided."
        ),
    )
    parser.add_argument(
        "--app-name",
        metavar="APPLICATION_NAME",
        default=None,
        help=(
            "Fortify application name "
            "(e.g. '1038_US_D360-Citi-Triggers-on-Cloud_USIS'). "
            "Looks up applicationId by name and resolves the latest release. "
            "Cannot be combined with --report (offline mode)."
        ),
    )
    parser.add_argument(
        "--list-releases",
        action="store_true",
        default=False,
        help=(
            "List all releases for the application supplied via --app-name, "
            "then exit without running the remediation pipeline. "
            "Output is sorted newest-first (DESC) and includes releaseId, "
            "releaseName, status, rating, and severity counts."
        ),
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable DEBUG-level logging",
    )
    parser.add_argument(
        "--max-upgrades",
        type=int,
        default=0,
        metavar="N",
        help=(
            "Maximum number of dependencies to upgrade in this run. "
            "Deps are prioritised by severity (Critical first). "
            "0 (default) means no limit. "
            "Overrides the MAX_UPGRADES environment variable when provided."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    configure_logging(verbose=args.verbose)

    offline_mode = args.report is not None

    # ── Guards ───────────────────────────────────────────────────────────────────
    if args.app_name and args.report:
        print("ERROR: --app-name and --report cannot be used together.", file=sys.stderr)
        return 1
    if args.list_releases and not args.app_name:
        print("ERROR: --list-releases requires --app-name.", file=sys.stderr)
        return 1

    logger.info("=" * 60)
    logger.info("FortifyAI starting up")
    logger.info(f"  Mode       : {'OFFLINE (--report)' if offline_mode else 'LIVE'}")
    if offline_mode:
        logger.info(f"  Report     : {args.report}")
    elif args.app_name:
        mode_label = "list releases" if args.list_releases else "will resolve latest release"
        logger.info(f"  App Name   : {args.app_name}  ({mode_label})")
    else:
        logger.info(f"  Release ID : {args.release}")
    if args.repo:
        logger.info(f"  Repo (CLI) : {args.repo}")
    logger.info(f"  Max Upgrades: {args.max_upgrades or 'unlimited (0)'}")
    logger.info("=" * 60)

    # ── Config ────────────────────────────────────────────────────────────────
    try:
        config: FortifyAIConfig = load_config()
        logger.info("[Config] ✅ Configuration loaded successfully")
    except Exception as exc:
        logger.error(f"[Config] ❌ Failed to load configuration: {exc}")
        return 1

    # ── CLI overrides (take priority over environment variables) ──────────────
    if args.repo:
        object.__setattr__(config, "github_repo", args.repo)
        logger.info(f"[Config] github_repo overridden by --repo: {args.repo}")

    if args.max_upgrades:
        object.__setattr__(config, "max_upgrades", args.max_upgrades)
        logger.info(f"[Config] max_upgrades overridden by --max-upgrades: {args.max_upgrades}")

    # ── Validate required fields based on mode ────────────────────────────────
    errors = []

    # Fortify credentials — required in live mode only
    if not offline_mode:
        if not config.fortify_base_url:
            errors.append("FORTIFY_BASE_URL is required in live mode")
        if not config.fortify_api_token:
            errors.append("FORTIFY_API_TOKEN is required in live mode")

    # project_path: NOT required when --repo is given (will be cloned below)
    repo_will_clone = bool(args.repo)
    if not repo_will_clone:
        if not config.project_path or config.project_path == ".":
            errors.append("PROJECT_PATH is required (or pass --repo org/name to clone automatically)")
        elif not __import__('pathlib').Path(config.project_path).exists():
            errors.append(f"PROJECT_PATH does not exist: {config.project_path}")

    if not config.adr_path:
        errors.append("ADR_PATH is required")
    if not config.japicmp_jar_path:
        errors.append("JAPICMP_JAR_PATH is required")
    if not config.github_token:
        errors.append("GITHUB_TOKEN is required")
    if not config.github_repo:
        errors.append("GITHUB_REPO is required")
    if not config.gcp_project:
        errors.append("GCP_PROJECT is required")

    if errors:
        for err in errors:
            logger.error(f"[Config] ❌ {err}")
        return 1

    # ── Graph ─────────────────────────────────────────────────────────────────
    try:
        get_compiled_graph()
        logger.info("[Graph] ✅ Pipeline graph compiled")
    except Exception as exc:
        logger.error(f"[Graph] ❌ Failed to compile graph: {exc}")
        return 1

    # ── Clone repo if --repo was passed ───────────────────────────────────────
    import tempfile

    clone_dir = None   # track temp dir for cleanup

    if repo_will_clone:
        repo_url = f"https://{config.github_token}@github.com/{config.github_repo}.git"
        clone_dir = tempfile.mkdtemp(prefix="fortifyai_clone_")
        logger.info(f"[Clone] Cloning {config.github_repo} → {clone_dir}")
        try:
            result = subprocess.run(
                ["git", "-c", "http.sslVerify=false", "clone", "--depth", "1", repo_url, clone_dir],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode != 0:
                logger.error(f"[Clone] ❌ git clone failed:\n{result.stderr[:500]}")
                shutil.rmtree(clone_dir, ignore_errors=True)
                return 1
            logger.info(f"[Clone] ✅ Repository cloned successfully")
            # Override project_path with the cloned directory
            object.__setattr__(config, "project_path", clone_dir)
        except subprocess.TimeoutExpired:
            logger.error("[Clone] ❌ git clone timed out after 300s")
            shutil.rmtree(clone_dir, ignore_errors=True)
            return 1
        except FileNotFoundError:
            logger.error("[Clone] ❌ git not found on PATH")
            shutil.rmtree(clone_dir, ignore_errors=True)
            return 1

    # ── Background Maven cache warm-up ─────────────────────────────────────────
    # project_path is now final (cloned dir, or the pre-validated PROJECT_PATH)
    # regardless of which branch above ran. Kick off 'mvn dependency:go-offline'
    # here, in the background, so the .m2 cache has the whole triage /
    # version-resolution / context / api-diff window to warm up before
    # adr_fix's Phase 1b (mvn dependency:tree) needs it. See _warm_maven_cache
    # docstring for why this makes ADR noticeably faster without changing its
    # own offline/online fallback behaviour.
    maven_warmup_thread = _start_maven_warmup(config.project_path)

    # ── Resolve vulnerabilities ───────────────────────────────────────────────
    release_id = args.release

    if not offline_mode and args.app_name:
        try:
            client_tmp = FortifyClient.from_config(config)

            # ── --list-releases: print all releases and exit ───────────────────
            if args.list_releases:
                try:
                    client_tmp.print_releases_summary(args.app_name)
                except ValueError as exc:
                    logger.error(f"[ListReleases] ❌ {exc}")
                    return 1
                except Exception as exc:
                    logger.error(f"[ListReleases] ❌ Unexpected error: {exc}")
                    return 1
                return 0   # done — no pipeline run

            # ── Normal: resolve latest releaseId then continue ─────────────────
            release_id = client_tmp.resolve_release_id_from_app_name(args.app_name)
            logger.info(
                f"[AppName] ✅ Resolved '{args.app_name}' → releaseId={release_id}"
            )
        except ValueError as exc:
            logger.error(f"[AppName] ❌ {exc}")
            return 1
        except Exception as exc:
            logger.error(f"[AppName] ❌ Unexpected error during name lookup: {exc}")
            return 1
    elif not offline_mode and release_id == 0:
        logger.error(
            "[Config] ❌ Provide --release <ID> or --app-name <NAME> in live mode"
        )
        return 1

    if offline_mode:
        # ── Offline path: load from JSON file ─────────────────────────────────
        from offline_loader import load_report, NullFortifyClient
        try:
            raw_vulns, file_release_id = load_report(args.report)
        except FileNotFoundError as exc:
            logger.error(f"[Offline] ❌ {exc}")
            return 1
        except Exception as exc:
            logger.error(f"[Offline] ❌ Failed to load report: {exc}")
            return 1

        # Prefer release_id from the file, fall back to --release arg
        if file_release_id is not None:
            release_id = file_release_id
            logger.info(f"[Offline] Using release_id={release_id} from file")
        elif release_id == 0:
            logger.warning(
                "[Offline] No release_id in file and --release not set. "
                "Defaulting to 0 — writeback calls will be suppressed anyway."
            )

        client = NullFortifyClient(raw_vulns)
        logger.info(f"[Offline] ✅ NullFortifyClient ready ({len(raw_vulns)} vulns)")

    else:
        # ── Live path: call the real Fortify API ──────────────────────────────
        try:
            client = FortifyClient.from_config(config)
            logger.info("[Client] ✅ FortifyClient initialised")
        except Exception as exc:
            logger.error(f"[Client] ❌ Failed to build FortifyClient: {exc}")
            return 1

        try:
            raw_vulns = client.get_vulnerabilities(release_id)
            logger.info(f"Fetched {len(raw_vulns)} vulnerabilities")
        except Exception as exc:
            logger.error(f"[Client] ❌ API call failed: {exc}")
            logger.error("Check FORTIFY_BASE_URL and FORTIFY_API_TOKEN environment variables")
            return 1

    # ── Triage ────────────────────────────────────────────────────────────────
    logger.info("─" * 60)
    from agents.triage import group_by_dependency, apply_max_upgrades
    groups = group_by_dependency(raw_vulns)
    groups = apply_max_upgrades(groups, config.max_upgrades)

    if not groups:
        logger.warning("[Triage] No actionable findings — nothing to remediate")
        return 0

    # ── Version resolution ────────────────────────────────────────────────────
    logger.info("─" * 60)
    from agents.version_resolver import resolve_all_groups
    resolved_groups = resolve_all_groups(client, release_id, groups)

    # ── Context ───────────────────────────────────────────────────────────────
    logger.info("─" * 60)
    from agents.context import locate_all_groups, detect_required_jdk
    project_path = Path(config.project_path) if config.project_path else Path(".")
    context_groups = locate_all_groups(project_path, resolved_groups)

    # Detect the JDK this project needs so run_adr_fix (below) can tell
    # adr_fortify.py which JAVA_HOME to build with. This CLI path doesn't go
    # through context_node (the LangGraph node) — it calls the same
    # locate_all_groups() helper directly — so JDK detection has to be called
    # here explicitly too, or it silently never happens for CLI-driven runs.
    #
    # detect_required_jdk() itself already logs every step of what it finds
    # (INFO/WARNING) — the block below only adds the final "here's the
    # outcome for this run" line, and — critically — logs the failure case
    # too. Silently saying nothing on required_jdk == None was the actual
    # bug here: it made a real detection failure indistinguishable from
    # "this code path never ran at all", which is exactly what happened.
    required_jdk = detect_required_jdk(project_path)
    if required_jdk:
        logger.info(f"[Context] Project requires JDK {required_jdk}")
    else:
        logger.warning(
            "[Context] required_jdk is None for this run — downstream agents "
            "(AI Reasoning, JDK registry selection) will treat this project's "
            "JDK as unknown"
        )

    # ── API diff ──────────────────────────────────────────────────────────────
    logger.info("─" * 60)
    from agents.api_diff import run_api_diff_all_groups
    japicmp_path = config.japicmp_jar_path or "/nonexistent/japicmp.jar"
    diff_groups = run_api_diff_all_groups(context_groups, project_path, japicmp_path)

    # ── AI reasoning ──────────────────────────────────────────────────────────
    logger.info("─" * 60)
    from agents.ai_reasoning import reason_all_groups
    gcp_project  = config.gcp_project
    gcp_location = config.gcp_location
    reasoned_groups = reason_all_groups(diff_groups, gcp_project, gcp_location)

    # ── ADR fix ───────────────────────────────────────────────────────────────
    logger.info("─" * 60)
    if maven_warmup_thread is not None:
        if maven_warmup_thread.is_alive():
            logger.info(
                "[MavenWarm] Still warming .m2 cache in the background — "
                "adr_fortify.py will use whatever is cached so far and fall "
                "back to its own online resolution for the rest"
            )
        else:
            logger.info("[MavenWarm] ✅ Background .m2 warm-up already finished")
    from agents.adr_fix import run_adr_fix
    adr_results: list[dict] = []
    for group in reasoned_groups:
        if group.get("next_node") == "escalate":
            logger.warning(
                f"[ADR Fix] Skipping {group['parsed']['artifact_id']} — escalated"
            )
            adr_results.append({
                "artifact_id": group["parsed"]["artifact_id"],
                "result": {
                    "success": False, "branch_name": None, "commit_hash": None,
                    "build_time_seconds": None, "pdf_path": None,
                    # NOTE: group["escalation_reason"] is never actually set by
                    # either version_resolver.py or ai_reasoning.py — the real
                    # reason lives at group["escalate_reason"] (version
                    # resolver, earlier stage) or group["ai_reasoning"]["reason"]
                    # (AI reasoning). Check those instead of the generic
                    # placeholder, mirroring api_server.py's _escalation_reason().
                    "error_reason": (
                        group.get("escalate_reason")
                        or (group.get("ai_reasoning") or {}).get("reason")
                        or "Escalated — no reason recorded"
                    ),
                },
            })
            continue

        if config.adr_path:
            result = run_adr_fix(
                group,
                adr_path=config.adr_path,
                project_path=str(project_path),
                jira_prefix=config.jira_id_prefix,
                required_jdk=required_jdk,
            )
        else:
            from state import AdrResult
            logger.warning("[ADR Fix] ADR_PATH not set — skipping ADR invocation")
            result = AdrResult(
                success=False, branch_name=None, commit_hash=None,
                build_time_seconds=None, pdf_path=None,
                error_reason="ADR_PATH not configured",
            )

        adr_results.append({
            "artifact_id": group["parsed"]["artifact_id"],
            "result": result,
        })

    # ── PR creation ───────────────────────────────────────────────────────────
    logger.info("─" * 60)
    from agents.pr_agent import create_prs_for_all_groups
    pr_results = []
    if config.github_token and config.github_repo:
        pr_results = create_prs_for_all_groups(
            groups=reasoned_groups,
            adr_results=adr_results,
            release_id=release_id,
            github_token=config.github_token,
            github_repo=config.github_repo,
            reviewers=config.get_reviewers(),
        )
    else:
        logger.warning("[PR] GitHub config not set — skipping PR creation")

    # ── Escalation reports ────────────────────────────────────────────────────
    logger.info("─" * 60)
    from agents.fortify_writeback import run_all_reports
    summary = run_all_reports(
        groups=reasoned_groups,
        adr_results=adr_results,
        pr_results=pr_results,
        output_dir=config.adr_output_dir,
    )

    # ── Done ──────────────────────────────────────────────────────────────────
    logger.info("─" * 60)
    mode_tag = "OFFLINE" if offline_mode else "LIVE"
    logger.info(
        f"[Done] ✅ FortifyAI complete [{mode_tag}] — "
        f"fixed={summary['total_fixed']}, "
        f"escalated={summary['total_escalated']}, "
        f"failed={summary['total_failed']}"
    )
    logger.info("─" * 60)

    # ── Cleanup cloned repo ───────────────────────────────────────────────────
    if clone_dir:
        shutil.rmtree(clone_dir, ignore_errors=True)
        logger.info(f"[Clone] Temp clone removed: {clone_dir}")

    return 0


if __name__ == "__main__":
    sys.exit(main())