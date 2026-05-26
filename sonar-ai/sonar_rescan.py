"""
SonarAI — Sonar Rescan Validator  (Iteration 2)

After a fix is committed and a PR is opened, this module queries the Sonar API
to verify the issue is no longer reported.  Because Sonar analyses run
asynchronously (triggered by CI), we poll with exponential back-off.

Strategy:
  1. Call POST /api/ce/submit to trigger an analysis (SonarQube CE only).
     On SonarCloud this step is skipped — analyses are triggered by push.
  2. Poll GET /api/ce/activity?component=<key>&type=REPORT to detect when
     the analysis task finishes (status = SUCCESS | FAILED | CANCELLED).
  3. Call GET /api/issues/search?issues=<key>&resolved=false to check whether
     the original issue still appears as unresolved.
  4. Return a (rescan_ok, message) tuple.

Graceful degradation: if the Sonar token is missing, the Sonar host is
unreachable, or the analysis doesn't complete within the timeout, the function
returns (None, "skipped") and the pipeline proceeds normally.

Timeout: configurable via settings.sonar_rescan_timeout (default: 300s).
Poll interval: exponential back-off from 10s → 60s.
"""

from __future__ import annotations

import time
from typing import Optional

import requests
from loguru import logger

from config import settings


# ── Public API ────────────────────────────────────────────────────────────────

def rescan_issue(
    issue_key: str,
    component_key: str,
    project_key: Optional[str] = None,
) -> tuple[Optional[bool], str]:
    """
    Verify via the Sonar API that the given issue is no longer unresolved.

    Args:
        issue_key     : Sonar issue UUID (e.g. "AY...")
        component_key : Sonar component string (e.g. "proj:src/.../Foo.java")
        project_key   : Sonar project key (optional; derived from component if absent)

    Returns:
        (True,  "Issue resolved by Sonar rescan")   — rule no longer fires
        (False, "Issue still open after rescan")    — rule still fires
        (None,  "Rescan skipped: ...")              — skipped gracefully
    """
    if not settings.sonar_token:
        logger.info("[Rescan] No SONAR_TOKEN configured — rescan skipped")
        return None, "Rescan skipped: SONAR_TOKEN not configured"

    if not settings.sonar_host_url:
        return None, "Rescan skipped: SONAR_HOST_URL not configured"

    if not project_key:
        project_key = _project_key_from_component(component_key)

    logger.info(
        f"[Rescan] Starting rescan for issue={issue_key} project={project_key}"
    )

    # Optionally trigger an analysis (SonarQube CE local; no-op on SonarCloud)
    _trigger_analysis(project_key)

    # Poll for analysis completion
    completed = _wait_for_analysis(project_key)
    if not completed:
        msg = (
            f"Rescan skipped: analysis did not complete within "
            f"{settings.sonar_rescan_timeout}s"
        )
        logger.warning(f"[Rescan] {msg}")
        return None, msg

    # Check whether the issue is still open
    still_open = _issue_still_open(issue_key)
    if still_open is None:
        return None, "Rescan skipped: could not query issue status"

    if still_open:
        msg = "Issue still reported by Sonar after fix"
        logger.warning(f"[Rescan] {msg} (issue={issue_key})")
        return False, msg

    msg = "Issue resolved — Sonar no longer reports this violation"
    logger.info(f"[Rescan] ✅ {msg} (issue={issue_key})")
    return True, msg


# ── Internal helpers ──────────────────────────────────────────────────────────

def _auth() -> tuple[str, str]:
    """Return (user, password) for requests Basic auth."""
    return (settings.sonar_token, "")


def _base() -> str:
    return settings.sonar_host_url.rstrip("/")


def _project_key_from_component(component: str) -> str:
    """Extract project key from 'project-key:path/to/File.java'."""
    return component.split(":")[0] if ":" in component else component


def _trigger_analysis(project_key: str) -> None:
    """
    Attempt to trigger a SonarQube CE analysis.
    Silently no-ops on SonarCloud or any API error.
    """
    url = f"{_base()}/api/ce/submit"
    try:
        resp = requests.post(
            url,
            auth=_auth(),
            data={"projectKey": project_key},
            timeout=15,
        )
        if resp.status_code == 200:
            task_id = resp.json().get("taskId", "?")
            logger.info(f"[Rescan] Analysis task submitted: {task_id}")
        else:
            # SonarCloud returns 404/405 for this endpoint — expected
            logger.debug(
                f"[Rescan] Trigger skipped (status={resp.status_code}) — "
                "this is normal for SonarCloud"
            )
    except Exception as exc:
        logger.debug(f"[Rescan] Analysis trigger error (non-fatal): {exc}")


def _wait_for_analysis(project_key: str, timeout: Optional[int] = None) -> bool:
    """
    Poll /api/ce/activity until the latest analysis task succeeds or timeout.
    Returns True if a SUCCESS task is seen within the timeout.
    """
    timeout = timeout or settings.sonar_rescan_timeout
    deadline = time.time() + timeout
    interval = 10  # seconds, grows to 60

    url = f"{_base()}/api/ce/activity"
    params = {"component": project_key, "type": "REPORT", "ps": 1}

    while time.time() < deadline:
        try:
            resp = requests.get(url, auth=_auth(), params=params, timeout=15)
            if resp.status_code != 200:
                logger.debug(f"[Rescan] CE activity poll: status={resp.status_code}")
                time.sleep(interval)
                interval = min(interval * 2, 60)
                continue

            tasks = resp.json().get("tasks", [])
            if tasks:
                status = tasks[0].get("status", "")
                logger.info(f"[Rescan] Latest analysis task status: {status}")
                if status == "SUCCESS":
                    return True
                if status in ("FAILED", "CANCELLED"):
                    logger.warning(f"[Rescan] Analysis task ended with status={status}")
                    return False
        except Exception as exc:
            logger.debug(f"[Rescan] Poll error (non-fatal): {exc}")

        time.sleep(interval)
        interval = min(interval * 2, 60)

    return False


def _issue_still_open(issue_key: str) -> Optional[bool]:
    """
    Query /api/issues/search for the given issue key with resolved=false.
    Returns True if the issue is still open, False if resolved, None on error.
    """
    url = f"{_base()}/api/issues/search"
    params = {"issues": issue_key, "resolved": "false"}

    try:
        resp = requests.get(url, auth=_auth(), params=params, timeout=15)
        if resp.status_code != 200:
            logger.warning(f"[Rescan] Issues search returned {resp.status_code}")
            return None

        data = resp.json()
        total = data.get("total", data.get("paging", {}).get("total", -1))
        if total == -1:
            # Try counting issues array directly
            total = len(data.get("issues", []))

        return total > 0  # True means still open

    except Exception as exc:
        logger.warning(f"[Rescan] Issue status check failed: {exc}")
        return None
