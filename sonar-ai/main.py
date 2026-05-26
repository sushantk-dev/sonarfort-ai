#!/usr/bin/env python3
"""
SonarAI — CLI Entry Point  (Iteration 2)

Usage:
    python main.py --report sonar-report.json \\
                   --repo   https://github.com/owner/repo.git \\
                   --sha    abc123def456

New flags (Iteration 2):
    --max-issues N     Process only the top N priority issues (default: all)
    --parallel         Fan-out issues in parallel via LangGraph Send API
    --rescan           Enable Sonar API rescan after each fix
    --no-rag           Disable ChromaDB RAG retrieval
    --dry-run          Print patches but don't commit or create PRs
    --summary          Print JSON summary to stdout after pipeline
"""

import argparse
import json
import os
import sys

from loguru import logger

# Configure loguru: structured one-line format
logger.remove()
logger.add(
    sys.stderr,
    format="<green>{time:HH:mm:ss}</green> | <level>{level:<8}</level> | {message}",
    colorize=True,
    level="INFO",
)
logger.add(
    "sonar_ai.log",
    format="{time:YYYY-MM-DD HH:mm:ss} | {level:<8} | {name}:{line} | {message}",
    level="DEBUG",
    rotation="10 MB",
    retention="7 days",
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SonarAI — automated Sonar issue remediation pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Required args
    parser.add_argument(
        "--report", required=True, metavar="PATH",
        help="Path to sonar-report.json",
    )
    parser.add_argument(
        "--repo", required=True, metavar="URL",
        help="GitHub HTTPS clone URL (e.g. https://github.com/owner/repo.git)",
    )
    parser.add_argument(
        "--sha", required=True, metavar="SHA",
        help="Exact commit SHA used during the Sonar scan",
    )

    # Iteration 2 optional flags
    parser.add_argument(
        "--max-issues", type=int, default=0, metavar="N",
        help="Process only top N issues by severity (default: all)",
    )
    parser.add_argument(
        "--parallel", action="store_true",
        help="Fan-out issues in parallel via LangGraph Send API",
    )
    parser.add_argument(
        "--rescan", action="store_true",
        help="Enable Sonar API rescan after each fix to confirm issue resolution",
    )
    parser.add_argument(
        "--no-rag", action="store_true",
        help="Disable ChromaDB RAG retrieval (useful for first run or debugging)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print patches to console but don't commit or open PRs",
    )
    parser.add_argument(
        "--summary", action="store_true",
        help="Print JSON pipeline summary to stdout after completion",
    )

    args = parser.parse_args()

    # Apply CLI flags to environment / settings overrides
    if args.dry_run:
        os.environ["SONAR_AI_DRY_RUN"] = "1"
        logger.info("DRY RUN mode enabled")

    if args.parallel:
        os.environ["PARALLEL_ISSUES"] = "true"

    if args.rescan:
        os.environ["ENABLE_SONAR_RESCAN"] = "true"

    if args.no_rag:
        os.environ["ENABLE_RAG"] = "false"

    # Late import so env overrides are in place before settings are loaded
    from graph import run_pipeline

    final_state = run_pipeline(
        sonar_report_path=args.report,
        repo_url=args.repo,
        commit_sha=args.sha,
        max_issues=args.max_issues,
    )

    results = final_state.get("pipeline_results", [])

    # Print JSON summary to stdout if requested
    if args.summary and results:
        summary = {
            "total": len(results),
            "results": [
                {
                    "issue_key": r.get("issue_key"),
                    "rule_key": r.get("rule_key"),
                    "outcome": r.get("outcome"),
                    "pr_url": r.get("pr_url"),
                    "escalation_path": r.get("escalation_path"),
                    "confidence": r.get("confidence"),
                    "sonar_rescan_ok": r.get("sonar_rescan_ok"),
                }
                for r in results
            ],
        }
        print(json.dumps(summary, indent=2))

    # Exit code
    if not results:
        print("\nℹ️  No issues found or processed.")
        return 0

    pr_count = sum(1 for r in results if r.get("pr_url"))
    esc_count = sum(1 for r in results if r.get("escalation_path"))
    err_count = sum(1 for r in results if r.get("outcome") == "error")

    print(f"\n{'='*50}")
    print(f"SonarAI Iteration 2 — Complete")
    print(f"  Issues processed : {len(results)}")
    print(f"  PRs opened       : {pr_count}")
    print(f"  Escalations      : {esc_count}")
    print(f"  Errors           : {err_count}")
    print(f"{'='*50}")

    if pr_count:
        for r in results:
            if r.get("pr_url"):
                print(f"  ✅  PR: {r['pr_url']}")

    if esc_count:
        for r in results:
            if r.get("escalation_path"):
                print(f"  ⚠️   Escalation: {r['escalation_path']}")

    # Non-zero exit if all issues failed or were escalated
    if pr_count == 0 and esc_count == len(results):
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())