"""
FortifyAI — Fortify OAuth Authentication
-----------------------------------------
Handles Bearer token acquisition and refresh via the Fortify OAuth2
password-grant endpoint:

    POST https://api.ams.fortify.com/oauth/token
    Content-Type: application/x-www-form-urlencoded

    grant_type=password
    scope=api-tenant
    username=<FORTIFY_USERNAME>
    password=<FORTIFY_PASSWORD>
    security_code=
    do_totp=false

Usage:
    from fortify_auth import fetch_token, refresh_token_in_env

    token_info = fetch_token(cfg)
    # → {"access_token": "...", "token_type": "Bearer", "expires_in": 28800, ...}

    # Persist the new token back to .env automatically:
    refresh_token_in_env(cfg, env_path=".env")
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Optional

import requests
from loguru import logger

from config import FortifyAIConfig

# Fortify OAuth endpoint path (relative to fortify_base_url)
_OAUTH_PATH = "/oauth/token"
_REQUEST_TIMEOUT = 30  # seconds


# ═══════════════════════════════════════════════════════════════════════════════
# Core token fetch
# ═══════════════════════════════════════════════════════════════════════════════

def fetch_token(
    cfg: FortifyAIConfig,
    username: Optional[str] = None,
    password: Optional[str] = None,
    scope: Optional[str] = None,
) -> dict:
    """
    POST /oauth/token with password grant.

    Parameters override .env values when provided — useful for one-off
    token requests without modifying config.

    Returns the full token response dict:
        {
            "access_token": "eyJ...",
            "token_type":   "Bearer",
            "expires_in":   28800,       # seconds (8 h typical)
            "scope":        "api-tenant",
            ...
        }

    Raises:
        ValueError  — if required credentials are missing
        requests.HTTPError — on non-2xx response from Fortify
    """
    resolved_username = username or cfg.fortify_username
    resolved_password = password or cfg.fortify_password
    resolved_scope    = scope    or cfg.fortify_scope or "api-tenant"

    if not resolved_username:
        raise ValueError(
            "FORTIFY_USERNAME is required for OAuth token fetch. "
            "Set it in .env or pass as a request parameter."
        )
    if not resolved_password:
        raise ValueError(
            "FORTIFY_PASSWORD is required for OAuth token fetch. "
            "Set it in .env or pass as a request parameter."
        )
    if not cfg.fortify_base_url:
        raise ValueError(
            "FORTIFY_BASE_URL is required. Set it in .env."
        )

    url = cfg.fortify_base_url.rstrip("/") + _OAUTH_PATH

    payload = {
        "grant_type":    "password",
        "scope":         resolved_scope,
        "username":      resolved_username,
        "password":      resolved_password,
        "security_code": "",
        "do_totp":       "false",
    }

    logger.info(
        f"[FortifyAuth] Fetching OAuth token for user '{resolved_username}' "
        f"scope='{resolved_scope}' → {url}"
    )

    t0 = time.time()
    resp = requests.post(
        url,
        data=payload,                          # form-encoded, NOT JSON
        headers={"Accept": "application/json"},
        timeout=_REQUEST_TIMEOUT,
    )

    elapsed = round(time.time() - t0, 2)

    if not resp.ok:
        logger.error(
            f"[FortifyAuth] ❌ Token fetch failed — "
            f"HTTP {resp.status_code} ({elapsed}s): {resp.text[:300]}"
        )
        resp.raise_for_status()

    token_data: dict = resp.json()
    access_token = token_data.get("access_token", "")
    expires_in   = token_data.get("expires_in", "?")

    logger.info(
        f"[FortifyAuth] ✅ Token obtained ({elapsed}s) — "
        f"expires_in={expires_in}s  "
        f"preview={access_token[:12]}..."
    )

    return token_data


# ═══════════════════════════════════════════════════════════════════════════════
# .env writeback
# ═══════════════════════════════════════════════════════════════════════════════

def write_token_to_env(token: str, env_path: str | Path = ".env") -> None:
    """
    Update FORTIFY_API_TOKEN in the .env file in-place.

    - If the key already exists, the value is replaced on that line.
    - If the key is absent, a new line is appended.
    - A relative env_path is resolved against the directory containing
      this file (fortify_auth.py), so it works regardless of the cwd
      uvicorn was launched from.

    The file is read and written as UTF-8; all other lines are untouched.
    """
    env_file = Path(env_path)
    if not env_file.is_absolute():
        # Resolve relative to the project root (same dir as this module)
        env_file = (Path(__file__).parent / env_path).resolve()
    original = env_file.read_text(encoding="utf-8") if env_file.exists() else ""

    key = "FORTIFY_API_TOKEN"
    new_line = f'{key}={token}'
    pattern = re.compile(rf"^{key}\s*=.*$", re.MULTILINE)

    if pattern.search(original):
        updated = pattern.sub(new_line, original)
    else:
        # Append — ensure there's a trailing newline before the new line
        updated = original.rstrip("\n") + "\n" + new_line + "\n"

    env_file.write_text(updated, encoding="utf-8")
    logger.info(
        f"[FortifyAuth] ✅ FORTIFY_API_TOKEN written to {env_file.resolve()} "
        f"(preview: {token[:12]}...)"
    )


def refresh_token_in_env(
    cfg: FortifyAIConfig,
    env_path: str | Path = ".env",
    username: Optional[str] = None,
    password: Optional[str] = None,
    scope: Optional[str] = None,
) -> dict:
    """
    Convenience: fetch a fresh token and write it to .env in one call.

    Returns the full token response dict (same as fetch_token).
    """
    token_data = fetch_token(cfg, username=username, password=password, scope=scope)
    access_token = token_data.get("access_token", "")
    if access_token:
        write_token_to_env(access_token, env_path=env_path)
    return token_data