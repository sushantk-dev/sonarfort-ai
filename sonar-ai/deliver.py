"""
SonarAI — PR Delivery & Escalation  (Iteration 2)

Changes from Iteration 1:
  - After a successful PR, stores the fix in ChromaDB for future RAG retrieval.
  - Optionally runs a Sonar rescan to confirm the rule no longer fires.
  - Rescan result is included in the PR body and IssueResult.
  - Returns IssueResult in state for multi-issue pipeline summary.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

import git
from github import Github, GithubException
from loguru import logger

from config import settings
from state import AgentState, IssueResult


# ── Confidence helpers ────────────────────────────────────────────────────────

def _confidence_label(score: float) -> str:
    if score >= settings.confidence_high_threshold:
        return "HIGH"
    if score >= settings.confidence_medium_threshold:
        return "MEDIUM"
    return "LOW"


def _confidence_badge(label: str) -> str:
    colour = {"HIGH": "brightgreen", "MEDIUM": "yellow", "LOW": "red"}.get(label, "grey")
    return f"![Confidence: {label}](https://img.shields.io/badge/confidence-{label}-{colour})"


# ── Public entry point ────────────────────────────────────────────────────────

def deliver(state: AgentState) -> AgentState:
    """
    LangGraph node — commit the fix, evaluate confidence, and either open a PR or escalate.
    """
    issue = state["current_issue"]
    planner = state.get("planner_output", {})
    validation = state.get("validation", {})

    confidence_score: float = planner.get("confidence", 0.0)
    confidence_label = _confidence_label(confidence_score)
    validation_passed = validation.get("diff_ok") and validation.get("compile_ok")

    logger.info(
        f"[Deliver] confidence={confidence_label}({confidence_score:.2f}) "
        f"validation_passed={validation_passed} "
        f"tests_ok={validation.get('tests_ok')}"
    )

    # ── Dry-run guard ────────────────────────────────────────────────────────
    import os as _os
    if _os.environ.get("SONAR_AI_DRY_RUN") == "1":
        logger.info("[Deliver] DRY RUN — skipping commit, push, and PR creation")
        patch_preview = state.get("generator_output", {}).get("patch_hunks", "")[:500]
        logger.info(f"[Deliver] DRY RUN patch preview:\n{patch_preview}")
        result = _make_issue_result(issue, state, "skipped", confidence_score)
        return {**state, "done": True, **_append_result(state, result)}

    if confidence_label == "LOW" or not validation_passed:
        path = _write_escalation(state, confidence_label)
        result = _make_issue_result(
            issue, state, "escalated", confidence_score, escalation_path=path
        )
        return {**state, "escalation_path": path, "done": True, **_append_result(state, result)}

    # Snapshot the file content *before* committing for the PR body
    before_snippet = _read_method_region(
        state.get("file_path", ""),
        state.get("current_issue", {}).get("line", 0),
        lines=15,
    )

    # Commit the fix
    try:
        _commit_fix(state)
        _push_branch(state)
    except Exception as exc:
        logger.error(f"[Deliver] Git commit/push failed: {exc}")
        path = _write_escalation(state, confidence_label, extra_note=str(exc))
        result = _make_issue_result(
            issue, state, "error", confidence_score,
            escalation_path=path, error=str(exc)
        )
        return {**state, "escalation_path": path, "done": True, **_append_result(state, result)}

    # Snapshot after-commit content for PR body
    after_snippet = _read_method_region(
        state.get("file_path", ""),
        state.get("current_issue", {}).get("line", 0),
        lines=15,
    )

    # ── Sonar rescan (Iteration 2) ────────────────────────────────────────────
    sonar_rescan_ok: Optional[bool] = None
    sonar_rescan_message = ""
    if settings.enable_sonar_rescan:
        try:
            from sonar_rescan import rescan_issue
            sonar_rescan_ok, sonar_rescan_message = rescan_issue(
                issue_key=issue["key"],
                component_key=issue["component"],
            )
        except Exception as exc:
            logger.warning(f"[Deliver] Sonar rescan failed (non-fatal): {exc}")
            sonar_rescan_message = f"Rescan error: {exc}"

    # ── Duplicate PR guard ────────────────────────────────────────────────────
    # If a PR already exists for this branch (e.g. pipeline re-run on same report),
    # return the existing URL instead of creating a duplicate.
    try:
        existing_pr_url = _find_existing_pr(state)
    except Exception as exc:
        logger.warning(f"[Deliver] Duplicate PR check failed (non-fatal): {exc}")
        existing_pr_url = None

    if existing_pr_url:
        logger.info(f"[Deliver] PR already exists for branch — skipping creation: {existing_pr_url}")
        outcome = "pr_opened" if confidence_label == "HIGH" else "draft_pr"
        result = _make_issue_result(
            issue, state, outcome, confidence_score,
            pr_url=existing_pr_url, sonar_rescan_ok=sonar_rescan_ok
        )
        return {
            **state,
            "pr_url": existing_pr_url,
            "sonar_rescan_ok": sonar_rescan_ok,
            "sonar_rescan_message": sonar_rescan_message,
            "done": True,
            **_append_result(state, result),
        }

    # Open the PR
    try:
        pr_url = _open_pr(
            state, confidence_label, before_snippet, after_snippet,
            sonar_rescan_ok=sonar_rescan_ok, sonar_rescan_message=sonar_rescan_message,
        )
    except GithubException as exc:
        logger.error(f"[Deliver] GitHub PR creation failed: {exc}")
        path = _write_escalation(state, confidence_label, extra_note=str(exc))
        result = _make_issue_result(
            issue, state, "error", confidence_score,
            escalation_path=path, error=str(exc)
        )
        return {**state, "escalation_path": path, "done": True, **_append_result(state, result)}

    # ── Store fix in RAG (Iteration 2) ────────────────────────────────────────
    if settings.enable_rag:
        try:
            from rag_store import store_fix
            store_fix(
                rule_key=issue["rule_key"],
                method_context=state.get("method_context", ""),
                message=issue["message"],
                patch_hunks=state.get("generator_output", {}).get("patch_hunks", ""),
                reasoning=planner.get("reasoning", ""),
                confidence=confidence_score,
                file_name=Path(state.get("file_path", "unknown")).name,
            )
        except Exception as exc:
            logger.warning(f"[Deliver] RAG store_fix failed (non-fatal): {exc}")

    outcome = "pr_opened" if confidence_label == "HIGH" else "draft_pr"
    result = _make_issue_result(
        issue, state, outcome, confidence_score,
        pr_url=pr_url, sonar_rescan_ok=sonar_rescan_ok
    )
    return {
        **state,
        "pr_url": pr_url,
        "sonar_rescan_ok": sonar_rescan_ok,
        "sonar_rescan_message": sonar_rescan_message,
        "done": True,
        **_append_result(state, result),
    }


# ── IssueResult helpers ───────────────────────────────────────────────────────

def _make_issue_result(
    issue: dict,
    state: AgentState,
    outcome: str,
    confidence: float,
    pr_url: Optional[str] = None,
    escalation_path: Optional[str] = None,
    sonar_rescan_ok: Optional[bool] = None,
    error: Optional[str] = None,
) -> IssueResult:
    return {
        "issue_key": issue.get("key", ""),
        "rule_key": issue.get("rule_key", ""),
        "severity": issue.get("severity", ""),
        "file_path": state.get("file_path", ""),
        "line": issue.get("line", 0),
        "outcome": outcome,
        "pr_url": pr_url,
        "escalation_path": escalation_path,
        "confidence": confidence,
        "sonar_rescan_ok": sonar_rescan_ok,
        "error": error,
    }


def _append_result(state: AgentState, result: IssueResult) -> dict:
    """Return a dict with updated pipeline_results list."""
    existing = list(state.get("pipeline_results", []))
    existing.append(result)
    return {"pipeline_results": existing}


# ── Git commit & push ─────────────────────────────────────────────────────────

def _commit_fix(state: AgentState) -> None:
    repo = git.Repo(state["repo_local_path"])
    file_path = state["file_path"]
    issue = state["current_issue"]

    rule_short = issue["rule_key"].split(":")[-1] if ":" in issue["rule_key"] else issue["rule_key"]
    class_name = Path(file_path).stem
    commit_msg = (
        f"fix(sonar): resolve {rule_short} in {class_name}.java\n\n"
        f"SonarQube rule: {issue['rule_key']}\n"
        f"Severity: {issue['severity']}\n"
        f"Message: {issue['message']}\n\n"
        f"Auto-fixed by SonarAI"
    )

    repo_root = Path(repo.working_dir)
    try:
        rel_path = str(Path(file_path).relative_to(repo_root))
    except ValueError:
        rel_path = file_path

    repo.index.add([rel_path])
    repo.index.commit(commit_msg)
    logger.info(f"[Deliver] Committed: {commit_msg.splitlines()[0]!r}")


# Retry configuration for git push
_PUSH_MAX_ATTEMPTS  = 4   # 1 initial + 3 retries
_PUSH_BASE_DELAY    = 2   # seconds — doubles each attempt: 2, 4, 8
_PUSH_MAX_DELAY     = 30  # cap so we never wait more than 30 s between attempts

# Error substrings that indicate a transient network condition worth retrying
_PUSH_TRANSIENT_ERRORS = (
    "connection reset",
    "connection timed out",
    "unable to connect",
    "could not resolve host",
    "failed to connect",
    "the remote end hung up",
    "timed out",
    "eof",
    "broken pipe",
    "recv failure",
)

# Error substrings that are permanent — no point retrying
_PUSH_PERMANENT_ERRORS = (
    "rejected",          # non-fast-forward or protected branch
    "denied",            # permission error
    "repository not found",
    "authentication failed",
    "403",
    "401",
)


def _push_branch(state: AgentState) -> None:
    """
    Push the fix branch to origin with exponential backoff on transient failures.

    Retry schedule (seconds): 2 → 4 → 8  (capped at _PUSH_MAX_DELAY)
    Permanent errors (auth, rejected, not-found) are never retried.
    Transient errors (network reset, timeout, EOF) are retried up to
    _PUSH_MAX_ATTEMPTS - 1 times before giving up.
    """
    import time as _time

    repo = git.Repo(state["repo_local_path"])
    branch = state.get("fix_branch", "")
    if not branch:
        raise ValueError("fix_branch is not set in state")

    ref_spec = f"refs/heads/{branch}:refs/heads/{branch}"
    last_exc: Optional[Exception] = None

    for attempt in range(1, _PUSH_MAX_ATTEMPTS + 1):
        try:
            repo.git.push("origin", ref_spec, "--set-upstream")
            logger.info(f"[Deliver] Pushed branch {branch} → origin (attempt {attempt})")
            return  # success

        except git.GitCommandError as exc:
            stderr = (exc.stderr or "").lower()
            last_exc = exc

            # ── Permanent error — re-raise immediately, no retry ──────────────
            if any(marker in stderr for marker in _PUSH_PERMANENT_ERRORS):
                logger.error(
                    f"[Deliver] Push failed with permanent error (no retry): {exc.stderr.strip()}"
                )
                raise

            # ── Transient error — log and decide whether to retry ─────────────
            is_transient = any(marker in stderr for marker in _PUSH_TRANSIENT_ERRORS)
            if not is_transient:
                # Unknown error category — log as warning and still retry
                # (better to retry unnecessarily than to fail on a recoverable error)
                logger.warning(
                    f"[Deliver] Push failed with unrecognised error (will retry): {exc.stderr.strip()[:200]}"
                )

            if attempt < _PUSH_MAX_ATTEMPTS:
                delay = min(_PUSH_BASE_DELAY * (2 ** (attempt - 1)), _PUSH_MAX_DELAY)
                logger.warning(
                    f"[Deliver] Push attempt {attempt}/{_PUSH_MAX_ATTEMPTS} failed "
                    f"({'transient' if is_transient else 'unknown'} error) — "
                    f"retrying in {delay}s: {exc.stderr.strip()[:120]}"
                )
                _time.sleep(delay)
            else:
                logger.error(
                    f"[Deliver] Push failed after {_PUSH_MAX_ATTEMPTS} attempts. "
                    f"Last error: {exc.stderr.strip()[:300]}"
                )

    # All attempts exhausted — raise the last exception
    raise last_exc


# ── GitHub PR ─────────────────────────────────────────────────────────────────

def _find_existing_pr(state: AgentState) -> Optional[str]:
    """
    Check if an open or closed PR already exists for fix_branch on this repo.

    Returns the PR html_url if found, None otherwise.

    Prevents two scenarios:
      1. Pipeline re-run on the same Sonar report creates a duplicate PR for
         the same branch (branch name includes rule_key + issue_key, so it is
         deterministic across runs for the same issue).
      2. Parallel fan-out dispatching the same issue twice (edge-case in large
         reports where issue deduplication is imperfect).

    Closed/merged PRs are also matched so we never re-open already-delivered work.
    """
    fix_branch = state.get("fix_branch", "")
    repo_url = state.get("repo_url", "")
    if not fix_branch or not repo_url:
        return None

    gh = Github(settings.github_token, base_url=settings.github_base_url)
    repo_name = _repo_name_from_url(repo_url)
    gh_repo = gh.get_repo(repo_name)

    owner = gh_repo.owner.login
    head_filter = f"{owner}:{fix_branch}"

    # Check open PRs first (most common case on re-run)
    open_prs = list(gh_repo.get_pulls(state="open", head=head_filter))
    if open_prs:
        logger.info(
            f"[Deliver] Found existing open PR #{open_prs[0].number} "
            f"for branch '{fix_branch}': {open_prs[0].html_url}"
        )
        return open_prs[0].html_url

    # Also check closed/merged so we don't re-open already-delivered work
    closed_prs = list(gh_repo.get_pulls(state="closed", head=head_filter))
    if closed_prs:
        logger.info(
            f"[Deliver] Branch '{fix_branch}' already has a closed/merged PR "
            f"#{closed_prs[0].number} — treating as delivered: {closed_prs[0].html_url}"
        )
        return closed_prs[0].html_url

    return None


def _open_pr(
    state: AgentState,
    confidence_label: str,
    before_snippet: str,
    after_snippet: str,
    sonar_rescan_ok: Optional[bool] = None,
    sonar_rescan_message: str = "",
) -> str:
    """Open a GitHub PR and return the PR URL."""
    gh = Github(settings.github_token, base_url=settings.github_base_url)

    repo_url = state["repo_url"]
    repo_name = _repo_name_from_url(repo_url)
    gh_repo = gh.get_repo(repo_name)

    issue = state["current_issue"]
    fix_branch = state["fix_branch"]

    rule_short = issue["rule_key"].split(":")[-1] if ":" in issue["rule_key"] else issue["rule_key"]
    class_name = Path(state["file_path"]).stem

    title = f"fix(sonar): resolve {rule_short} in {class_name}.java [{confidence_label}]"
    body = _build_pr_body(
        state, confidence_label, before_snippet, after_snippet,
        sonar_rescan_ok=sonar_rescan_ok, sonar_rescan_message=sonar_rescan_message,
    )
    is_draft = confidence_label == "MEDIUM"

    pr = gh_repo.create_pull(
        title=title,
        body=body,
        head=fix_branch,
        base=gh_repo.default_branch,
        draft=is_draft,
    )
    logger.info(f"[Deliver] PR #{pr.number} opened: {pr.html_url} (draft={is_draft})")

    _ensure_label(gh_repo, pr)

    if confidence_label == "HIGH":
        _assign_codeowner(gh_repo, pr, state["file_path"])

    if confidence_label == "MEDIUM":
        pr.create_issue_comment(
            "⚠️ **Medium confidence fix** — this patch was automatically generated but "
            "the agent's confidence score is below the HIGH threshold. "
            "Please review the diff carefully before merging."
        )

    return pr.html_url


def _build_pr_body(
    state: AgentState,
    confidence_label: str,
    before_snippet: str,
    after_snippet: str,
    sonar_rescan_ok: Optional[bool] = None,
    sonar_rescan_message: str = "",
) -> str:
    issue = state["current_issue"]
    planner = state.get("planner_output", {})
    generator = state.get("generator_output", {})
    validation = state.get("validation", {})
    rag_ctx = state.get("rag_context", {})

    badge = _confidence_badge(confidence_label)
    compile_icon = "✅" if validation.get("compile_ok") else "❌"
    test_icon = "✅" if validation.get("tests_ok") else "⚠️ skipped / failed"

    # Sonar rescan row
    if sonar_rescan_ok is True:
        rescan_icon = "✅ Issue resolved"
    elif sonar_rescan_ok is False:
        rescan_icon = "❌ Issue still reported"
    else:
        rescan_icon = "⏭️ Skipped"

    patch = generator.get("patch_hunks", "")
    if len(patch) > 4000:
        patch = patch[:4000] + "\n... (truncated — see commit diff for full patch)"

    reasoning = planner.get("reasoning", "_No reasoning captured._")
    strategy = planner.get("strategy", "_N/A_")
    confidence_score = planner.get("confidence", 0.0)

    concerns = state.get("critic_output", {}).get("concerns", [])
    concerns_md = (
        "\n".join(f"- {c}" for c in concerns) if concerns else "_None recorded._"
    )

    before_block = f"```java\n{before_snippet}\n```" if before_snippet else "_Not available._"
    after_block = f"```java\n{after_snippet}\n```" if after_snippet else "_Not available._"

    # RAG context note
    rag_count = rag_ctx.get("retrieved_count", 0) if rag_ctx else 0
    rag_note = (
        f"_Fix informed by {rag_count} similar prior fix(es) from the vector store._"
        if rag_count > 0 else "_No similar prior fixes found in vector store._"
    )

    # Confidence factors breakdown table (Iteration 3)
    _FACTOR_LABELS = {
        "rule_understood":    "Rule understood",
        "fix_is_mechanical":  "Fix is mechanical",
        "context_sufficient": "Context sufficient",
        "side_effects_risk":  "Side-effects risk",
        "rag_match_quality":  "RAG match quality",
    }
    factors: dict = planner.get("confidence_factors", {})
    if factors:
        factor_rows = "\n".join(
            f"| {_FACTOR_LABELS.get(k, k)} | {'█' * round(v * 10):<10} {v:.0%} |"
            for k, v in factors.items()
            if k in _FACTOR_LABELS
        )
        confidence_breakdown = (
            "\n<details>\n<summary>Confidence factor breakdown</summary>\n\n"
            "| Factor | Score |\n"
            "|--------|-------|\n"
            f"{factor_rows}\n\n"
            "</details>\n"
        )
    else:
        confidence_breakdown = ""

    return f"""\
{badge}  **Confidence score: {confidence_score:.0%}**
{confidence_breakdown}
## 🔍 SonarQube Issue
| Field | Value |
|-------|-------|
| Rule | `{issue['rule_key']}` |
| Severity | `{issue['severity']}` |
| File | `{Path(state['file_path']).name}` |
| Line | {issue['line']} |
| Message | {issue['message']} |

---

## 🤖 Agent Reasoning (Planner)
{reasoning}

**Fix strategy:** {strategy}

> {rag_note}

---

## 📄 Full Patch
```diff
{patch}
```

---

## 🔎 Critic Notes
{concerns_md}

---

## ✅ Validation
| Check | Result |
|-------|--------|
| Diff applied cleanly | ✅ |
| Maven compile | {compile_icon} |
| Maven tests | {test_icon} |
| Sonar rescan | {rescan_icon} |

{f'> {sonar_rescan_message}' if sonar_rescan_message else ''}

---
*Generated by [SonarAI](https://github.com/sonar-ai) — automated Sonar remediation pipeline*
"""


def _ensure_label(gh_repo, pr) -> None:
    label_name = "sonar-ai"
    try:
        try:
            label = gh_repo.get_label(label_name)
        except GithubException:
            label = gh_repo.create_label(label_name, "0075ca", "Auto-fix by SonarAI")
        pr.add_to_labels(label)
    except Exception as exc:
        logger.warning(f"[Deliver] Could not apply label '{label_name}': {exc}")


def _assign_codeowner(gh_repo, pr, file_path: str) -> None:
    try:
        for path in ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"):
            try:
                content = gh_repo.get_contents(path).decoded_content.decode()
                break
            except GithubException:
                content = None
        if not content:
            logger.debug("[Deliver] No CODEOWNERS file found")
            return

        owner = _match_codeowner(content, file_path)
        if not owner:
            return

        handle = owner.lstrip("@")
        if "/" in handle:
            org_name, team_slug = handle.split("/", 1)
            pr.create_review_request(team_reviewers=[team_slug])
            logger.info(f"[Deliver] Requested review from team: {handle}")
        else:
            pr.create_review_request(reviewers=[handle])
            logger.info(f"[Deliver] Requested review from: {handle}")
    except Exception as exc:
        logger.warning(f"[Deliver] CODEOWNERS assignment failed: {exc}")


def _match_codeowner(content: str, file_path: str) -> Optional[str]:
    file_name = Path(file_path).name
    matched_owner: Optional[str] = None

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        pattern, owner = parts[0], parts[1]
        if _glob_match(pattern, file_path) or _glob_match(pattern, file_name):
            matched_owner = owner

    return matched_owner


def _glob_match(pattern: str, target: str) -> bool:
    import fnmatch
    pat = pattern.lstrip("/")
    return (
        fnmatch.fnmatch(target, pat)
        or fnmatch.fnmatch(Path(target).name, pat)
        or fnmatch.fnmatch(target, f"**/{pat}")
    )


# ── Escalation ────────────────────────────────────────────────────────────────

def _write_escalation(
    state: AgentState, confidence_label: str, extra_note: str = ""
) -> str:
    issue = state["current_issue"]
    planner = state.get("planner_output", {})
    generator = state.get("generator_output", {})
    validation = state.get("validation", {})

    esc_dir = Path(settings.escalation_dir)
    esc_dir.mkdir(parents=True, exist_ok=True)

    rule_short = issue["rule_key"].split(":")[-1] if ":" in issue["rule_key"] else issue["rule_key"]
    safe_key = re.sub(r"[^a-zA-Z0-9_-]", "", issue["key"])[:12]
    filename = f"{safe_key}_{rule_short}.md"
    esc_path = esc_dir / filename

    patch = generator.get("patch_hunks", "_No patch generated._")
    compiler_err = validation.get("compiler_error") or "None"
    test_err = validation.get("test_error") or "None"
    reasoning = planner.get("reasoning", "_Not available._")
    strategy = planner.get("strategy", "_Not available._")

    content = f"""\
# Escalation — {issue['rule_key']} in {Path(state.get('file_path', 'unknown')).name}

> **Action required:** This issue could not be auto-fixed with sufficient confidence.
> Reason: **Confidence = {confidence_label}** / Validation passed = {validation.get('diff_ok') and validation.get('compile_ok')}

---

## Issue Details
| Field | Value |
|-------|-------|
| Rule | `{issue['rule_key']}` |
| Severity | `{issue['severity']}` |
| File | `{state.get('file_path', 'unknown')}` |
| Line | {issue['line']} |
| Message | {issue['message']} |

## Agent Reasoning
{reasoning}

## Suggested Fix Strategy
{strategy}

## Generated Patch (for reference — may be partially correct)
```diff
{patch}
```

## Validation Results
| Check | Result |
|-------|--------|
| Diff applied | {validation.get('diff_ok', False)} |
| Maven compile | {validation.get('compile_ok', False)} |
| Maven tests | {validation.get('tests_ok', False)} |

### Compiler Error
```
{compiler_err}
```

### Test Failure
```
{test_err}
```
{chr(10) + '## Additional Note' + chr(10) + extra_note if extra_note else ''}

---
*Generated by SonarAI escalation handler — review and fix manually*
"""

    esc_path.write_text(content, encoding="utf-8")
    logger.info(f"[Deliver] Escalation written: {esc_path}")
    return str(esc_path)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _repo_name_from_url(url: str) -> str:
    match = re.search(r"github\.com[:/](.+?)(?:\.git)?/?$", url)
    if match:
        return match.group(1)
    raise ValueError(f"Cannot extract repo name from URL: {url}")


def _read_method_region(file_path: str, flagged_line: int, lines: int = 15) -> str:
    if not file_path or not flagged_line:
        return ""
    try:
        source_lines = Path(file_path).read_text(encoding="utf-8", errors="replace").splitlines()
        total = len(source_lines)
        start = max(0, flagged_line - lines - 1)
        end = min(total, flagged_line + lines)
        numbered = "\n".join(
            f"{start + i + 1:4d}  {line}" for i, line in enumerate(source_lines[start:end])
        )
        return numbered
    except Exception as exc:
        logger.debug(f"[Deliver] Could not read snippet from {file_path}: {exc}")
        return ""