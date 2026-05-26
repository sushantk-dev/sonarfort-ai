"""
FortifyAI — PR Agent (Iteration 10)
--------------------------------------
Responsibility:
  After ADR successfully commits and pushes the fix branch, open a GitHub
  Pull Request via PyGithub with the full FortifyAI context.

PR spec:
  Title:   [FortifyAI] FORTIFY-a4105c54: Fix CVE-2024-38820 — spring-context 5.3.31 → 6.1.20
  Labels:  security, dependency, auto-fix, <severity.lower()>
  Draft:   true  if confidence == "medium"
           false if confidence == "high"
  Reviewers: from config.reviewers (auto-assign on high-confidence only)
  Body:    Markdown table + Sonatype analysis + Validation section + References
  PDF:     Attached as a follow-up comment (GitHub API file upload)

Console output (done-when):
  [PR] ✅ PR created: https://github.com/acme/backend/pull/482
  [PR] Draft: false  Labels: security, dependency, auto-fix, high
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from loguru import logger

from state import AgentState, PrResult

# ── PR body builder ───────────────────────────────────────────────────────────

def _confidence_badge(confidence: str) -> str:
    return {
        "high":   "🟢 High",
        "medium": "🟡 Medium",
        "low":    "🔴 Low",
    }.get(confidence, "🟡 Medium")


def _api_diff_summary(api_diff: dict) -> str:
    if not api_diff:
        return "japicmp not run"
    count = api_diff.get("breaking_count", 0)
    affected = api_diff.get("affected_lines", [])
    if count == 0:
        return "✅ No breaking changes"
    lines_str = ", ".join(affected[:3]) + ("…" if len(affected) > 3 else "")
    return f"⚠️ {count} breaking change(s) — {lines_str}" if lines_str else f"⚠️ {count} breaking change(s)"


def build_pr_body(
    group: dict,
    release_id: int,
    adr_result: dict,
    ai_reasoning: dict,
) -> str:
    """
    Build the full PR body markdown from all pipeline data.
    """
    parsed      = group["parsed"]
    group_id    = parsed["group_id"]
    artifact_id = parsed["artifact_id"]
    current_ver = parsed["current_version"]
    candidate   = group.get("current_candidate") or (
        group.get("version_candidates", {}).get("candidates", ["?"])[0]
    )
    cves        = group.get("cves", [])
    severity    = group.get("severity", "High")
    owasp       = group.get("owasp_2021", "A06:2021 – Vulnerable and Outdated Components")
    explanation = (group.get("version_candidates") or {}).get("explanation", "")
    links       = (group.get("version_candidates") or {}).get("links", [])

    confidence  = ai_reasoning.get("confidence", "medium")
    at_risk     = ai_reasoning.get("at_risk_lines", [])
    ai_reason   = ai_reasoning.get("reason", "")

    build_time  = adr_result.get("build_time_seconds")
    branch      = adr_result.get("branch_name", "unknown")
    commit      = adr_result.get("commit_hash", "unknown")

    api_diff    = group.get("api_diff", {})

    # ── Overview table ────────────────────────────────────────────────────────
    cve_str    = ", ".join(f"`{c}`" for c in cves) or "(none)"
    build_cell = f"✅ PASSED ({build_time}s)" if build_time else "✅ PASSED"

    body = f"""\
## FortifyAI Automated Security Fix

| Field        | Detail |
|---|---|
| Release      | `{release_id}` |
| Dependency   | `{group_id}:{artifact_id}` |
| Fix          | `{current_ver}` → `{candidate}` |
| CVEs         | {cve_str} |
| Severity     | {severity} |
| OWASP        | {owasp} |
| Branch       | `{branch}` |
| Commit       | `{commit}` |

---

## Sonatype Analysis

{explanation or "_No Sonatype explanation available._"}

---

## Validation

| Check          | Result |
|---|---|
| API Diff       | {_api_diff_summary(api_diff)} |
| AI Confidence  | {_confidence_badge(confidence)} |
| AI Reason      | {ai_reason or "—"} |
| Build          | {build_cell} |
"""

    # At-risk lines (if any)
    if at_risk:
        at_risk_list = "\n".join(f"- `{l}`" for l in at_risk[:10])
        body += f"""
### At-Risk Call Sites
{at_risk_list}

"""

    # References
    if links:
        refs = "\n".join(f"- {l}" for l in links[:8])
        body += f"""---

## References

{refs}
"""

    # Next-steps checklist
    body += """
---

## Next Steps

- [ ] Review the diff and confirm pom.xml changes are correct
- [ ] Run `mvn clean verify` on this branch before merging
- [ ] QA validates patched JARs end-to-end before promotion
- [ ] Merge and close related JIRA ticket

> _Created automatically by [FortifyAI](https://github.com/fortifyai). \
Do not edit — re-run the pipeline to regenerate._
"""
    return body


# ── Label management ──────────────────────────────────────────────────────────

def _ensure_label(repo, name: str, color: str, description: str = "") -> None:
    """Create a label if it doesn't already exist on the repo."""
    try:
        repo.get_label(name)
    except Exception:
        try:
            repo.create_label(name=name, color=color, description=description)
            logger.debug(f"[PR] Created label '{name}'")
        except Exception as exc:
            logger.debug(f"[PR] Could not create label '{name}': {exc}")


_LABEL_DEFS = {
    "security":    ("d73a4a", "Security vulnerability fix"),
    "dependency":  ("0075ca", "Dependency version update"),
    "auto-fix":    ("cfd3d7", "Automatically applied by FortifyAI"),
    "critical":    ("b60205", "Critical severity"),
    "high":        ("e4e669", "High severity"),
    "medium":      ("fbca04", "Medium severity"),
    "low":         ("0e8a16", "Low severity"),
}


def _get_labels(repo, severity: str, confidence: str) -> list:
    """Return label objects to attach. Creates missing ones."""
    names = ["security", "dependency", "auto-fix", severity.lower()]
    result = []
    for name in names:
        color, desc = _LABEL_DEFS.get(name, ("cccccc", ""))
        _ensure_label(repo, name, color, desc)
        try:
            result.append(repo.get_label(name))
        except Exception:
            pass
    return result


# ── CODEOWNERS reader ─────────────────────────────────────────────────────────

def _read_codeowners(repo, branch: str) -> list[str]:
    """
    Read CODEOWNERS from the repo and return a list of GitHub usernames.
    Returns [] on any error.
    """
    for path in ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"]:
        try:
            content = repo.get_contents(path, ref=branch)
            text = content.decoded_content.decode("utf-8", errors="replace")
            # Extract @username mentions
            return list({
                m.lstrip("@")
                for m in re.findall(r"@[\w\-]+", text)
            })
        except Exception:
            continue
    return []


# ── PDF attachment ────────────────────────────────────────────────────────────

def _attach_pdf(pr, pdf_path: Optional[str]) -> None:
    """Post the ADR PDF report path as a PR comment."""
    if not pdf_path:
        return
    p = Path(pdf_path)
    if not p.exists():
        logger.debug(f"[PR] PDF not found at {pdf_path} — skipping attachment")
        return
    comment = (
        f"📄 **ADR Scan Report** attached: `{p.name}`\n\n"
        f"_(The PDF was generated locally by ADR at `{pdf_path}`. "
        "Upload it to your PR or artifact store as needed.)_"
    )
    try:
        pr.create_issue_comment(comment)
        logger.debug(f"[PR] PDF comment posted: {p.name}")
    except Exception as exc:
        logger.warning(f"[PR] Could not post PDF comment: {exc}")


# ── Main PR creation function ─────────────────────────────────────────────────

def create_pull_request(
    group: dict,
    adr_result: dict,
    ai_reasoning: dict,
    release_id: int,
    github_token: str,
    github_repo: str,
    reviewers: list[str],
) -> PrResult:
    """
    Open a GitHub PR for one fixed dependency group.

    Returns PrResult with pr_url, pr_number, is_draft.
    """
    try:
        from github import Github, GithubException  # type: ignore
    except ImportError:
        logger.error("[PR] PyGithub not installed — cannot create PR")
        return PrResult(pr_url="", pr_number=0, is_draft=False)

    parsed      = group["parsed"]
    artifact_id = parsed["artifact_id"]
    current_ver = parsed["current_version"]
    candidate   = group.get("current_candidate") or (
        group.get("version_candidates", {}).get("candidates", ["?"])[0]
    )
    cves        = group.get("cves", [])
    severity    = group.get("severity", "High")
    confidence  = ai_reasoning.get("confidence", "medium")

    branch_name = adr_result.get("branch_name", "")
    if not branch_name:
        logger.error("[PR] No branch name in ADR result — cannot create PR")
        return PrResult(pr_url="", pr_number=0, is_draft=False)

    # ── Build PR metadata ─────────────────────────────────────────────────────
    cve_short   = cves[0] if len(cves) == 1 else f"{cves[0]}+{len(cves)-1}" if cves else "CVE"
    commit_id   = re.search(r"(FORTIFY-\w+)", branch_name)
    jira_ref    = commit_id.group(1) if commit_id else branch_name
    title       = (
        f"[FortifyAI] {jira_ref}: Fix {cve_short} — "
        f"{artifact_id} {current_ver} → {candidate}"
    )
    is_draft    = confidence != "high"
    body        = build_pr_body(group, release_id, adr_result, ai_reasoning)

    # ── Connect to GitHub ─────────────────────────────────────────────────────
    try:
        gh   = Github(github_token)
        repo = gh.get_repo(github_repo)
    except Exception as exc:
        logger.error(f"[PR] GitHub connection failed: {exc}")
        return PrResult(pr_url="", pr_number=0, is_draft=False)

    # ── Determine base branch ─────────────────────────────────────────────────
    try:
        base_branch = repo.default_branch
    except Exception:
        base_branch = "main"

    # ── Create PR ─────────────────────────────────────────────────────────────
    # GitHub requires head in "owner:branch" format when the branch was pushed
    # from a cloned repo (e.g. via --repo auto-clone). Without the prefix the
    # API returns 422 {"field": "head", "code": "invalid"}.
    repo_owner = github_repo.split("/")[0] if "/" in github_repo else ""
    head_ref   = f"{repo_owner}:{branch_name}" if repo_owner else branch_name

    try:
        pr = repo.create_pull(
            title=title,
            body=body,
            head=head_ref,
            base=base_branch,
            draft=is_draft,
        )
        logger.info(f"[PR] ✅ PR created: {pr.html_url}")
    except Exception as exc:
        # Retry with bare branch name — works when the repo is not a fork
        if repo_owner and head_ref != branch_name:
            logger.warning(
                f"[PR] create_pull failed with '{head_ref}': {exc} — "
                f"retrying with bare branch '{branch_name}'"
            )
            try:
                pr = repo.create_pull(
                    title=title,
                    body=body,
                    head=branch_name,
                    base=base_branch,
                    draft=is_draft,
                )
                logger.info(f"[PR] ✅ PR created (bare branch): {pr.html_url}")
            except Exception as exc2:
                logger.error(f"[PR] Failed to create PR: {exc2}")
                return PrResult(pr_url="", pr_number=0, is_draft=is_draft)
        else:
            logger.error(f"[PR] Failed to create PR: {exc}")
            return PrResult(pr_url="", pr_number=0, is_draft=is_draft)

    # ── Labels ────────────────────────────────────────────────────────────────
    try:
        labels = _get_labels(repo, severity, confidence)
        pr.set_labels(*labels)
        label_names = [lb.name for lb in labels]
        logger.info(f"[PR] Draft: {is_draft}  Labels: {', '.join(label_names)}")
    except Exception as exc:
        logger.warning(f"[PR] Could not set labels: {exc}")

    # ── Reviewers (high confidence only) ─────────────────────────────────────
    if confidence == "high":
        effective_reviewers = reviewers or _read_codeowners(repo, base_branch)
        if effective_reviewers:
            try:
                pr.create_review_request(reviewers=effective_reviewers[:5])
                logger.info(f"[PR] Reviewers requested: {effective_reviewers[:5]}")
            except Exception as exc:
                logger.warning(f"[PR] Could not assign reviewers: {exc}")

    # ── PDF attachment ────────────────────────────────────────────────────────
    _attach_pdf(pr, adr_result.get("pdf_path"))

    return PrResult(
        pr_url=pr.html_url,
        pr_number=pr.number,
        is_draft=is_draft,
    )


def create_prs_for_all_groups(
    groups: list[dict],
    adr_results: list[dict],
    release_id: int,
    github_token: str,
    github_repo: str,
    reviewers: list[str],
) -> list[PrResult]:
    """
    Open a PR for every group that has a successful ADR result.
    adr_results is the list from adr_fix_node: [{"artifact_id": ..., "result": AdrResult}].
    """
    # Build a lookup from artifact_id → adr_result
    adr_by_artifact = {
        r["artifact_id"]: r["result"]
        for r in adr_results
        if r["result"].get("success")
    }

    pr_results: list[PrResult] = []

    for group in groups:
        artifact_id  = group["parsed"]["artifact_id"]
        adr_result   = adr_by_artifact.get(artifact_id)
        ai_reasoning = group.get("ai_reasoning", {})

        if not adr_result:
            logger.warning(f"[PR] No successful ADR result for {artifact_id} — skipping PR")
            continue

        result = create_pull_request(
            group=group,
            adr_result=adr_result,
            ai_reasoning=ai_reasoning,
            release_id=release_id,
            github_token=github_token,
            github_repo=github_repo,
            reviewers=reviewers,
        )
        pr_results.append(result)

    return pr_results


# ── LangGraph node ────────────────────────────────────────────────────────────

def pr_agent_node(
    state: AgentState,
    github_token: str,
    github_repo: str,
    reviewers: list[str],
) -> AgentState:
    """
    LangGraph node: pr_agent.

    Reads:  state["_reasoned_groups"]  (or _diff_groups)
            state["_adr_results"]
            state["release_id"]
    Writes: state["pr_result"]         (first PR result, for writeback)
            state["_all_pr_results"]
            state["audit_trail"]
    """
    groups: list[dict] = (
        state.get("_reasoned_groups")  # type: ignore[attr-defined]
        or state.get("_diff_groups")   # type: ignore[attr-defined]
        or []
    )
    adr_results: list[dict] = state.get("_adr_results", [])  # type: ignore[attr-defined]
    release_id: int = state.get("release_id", 0)

    if not groups or not adr_results:
        logger.warning("[PR] No groups or ADR results in state — skipping")
        state["status"] = "skipped"
        state["skip_reason"] = "No successful ADR result to raise PR for"
        state["audit_trail"].append({"node": "pr_agent", "status": "skipped"})
        return state

    pr_results = create_prs_for_all_groups(
        groups=groups,
        adr_results=adr_results,
        release_id=release_id,
        github_token=github_token,
        github_repo=github_repo,
        reviewers=reviewers,
    )

    successful = [r for r in pr_results if r.get("pr_url")]
    if successful:
        state["pr_result"] = successful[0]
        state["status"] = "fixed"
    else:
        logger.warning("[PR] No PRs were created successfully")

    state["_all_pr_results"] = pr_results  # type: ignore[typeddict-unknown-key]
    state["audit_trail"].append({
        "node": "pr_agent",
        "status": "ok",
        "prs_created": len(successful),
        "pr_urls": [r.get("pr_url") for r in successful],
    })

    return state