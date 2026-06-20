"""
FortifyAI -- Fortify OAuth Authentication
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

Proactive refresh (recommended usage)
--------------------------------------
Call `ensure_token(cfg)` before creating a FortifyClient.  It returns a new
config copy with a guaranteed-fresh token -- fetching from the Fortify OAuth
endpoint only when the cached token is absent or within 30 s of expiry.

    from fortify_auth import ensure_token

    cfg = ensure_token(cfg)          # fast no-op if token is still valid
    client = FortifyClient.from_config(cfg)

The token cache is a process-level in-memory dict keyed by
``(base_url, username)`` so multiple configs (e.g. different tenants) each
get their own independent cache entry.

Legacy helpers
--------------
``fetch_token`` and ``refresh_token_in_env`` are still available for
one-off CLI / script usage that wants to manage the token manually.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import requests
from loguru import logger

import urllib3 

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) 

from config import FortifyAIConfig

# Fortify OAuth endpoint path (relative to fortify_base_url)
_OAUTH_PATH = "/oauth/token"
_REQUEST_TIMEOUT = 30  # seconds

# How many seconds before actual expiry we treat the token as stale.
# 60 s gives one full poll-cycle of headroom even on slow networks.
_EXPIRY_BUFFER_SECS = 60


# ===============================================================================
# In-process token cache
# ===============================================================================

@dataclass
class _CachedToken:
    access_token: str
    expires_at: float          # epoch seconds (time.time() compatible)


# Cache keyed by (base_url, username) -- supports multiple tenants
_token_cache: dict[tuple[str, str], _CachedToken] = {}
_cache_lock  = threading.Lock()


def _cache_key(cfg: FortifyAIConfig) -> tuple[str, str]:
    return (cfg.fortify_base_url.rstrip("/"), cfg.fortify_username)


def _cached_token(cfg: FortifyAIConfig) -> Optional[str]:
    """Return a cached token if it is still valid (outside the expiry buffer)."""
    with _cache_lock:
        entry = _token_cache.get(_cache_key(cfg))
    if entry and time.time() < entry.expires_at - _EXPIRY_BUFFER_SECS:
        return entry.access_token
    return None


def _store_token(cfg: FortifyAIConfig, token_data: dict) -> str:
    """Parse a token response, compute ``expires_at``, and update the cache."""
    access_token = token_data["access_token"]
    expires_in   = int(token_data.get("expires_in", 28800))  # default 8 h
    expires_at   = time.time() + expires_in
    with _cache_lock:
        _token_cache[_cache_key(cfg)] = _CachedToken(
            access_token=access_token,
            expires_at=expires_at,
        )
    logger.debug(
        f"[FortifyAuth] Token cached -- expires in {expires_in}s "
        f"(at {time.strftime('%H:%M:%S', time.localtime(expires_at))}, "
        f"buffer {_EXPIRY_BUFFER_SECS}s)"
    )
    return access_token


def invalidate_cache(cfg: FortifyAIConfig) -> None:
    """Force the next ``ensure_token`` call to fetch a fresh token."""
    with _cache_lock:
        _token_cache.pop(_cache_key(cfg), None)
    logger.debug("[FortifyAuth] Token cache invalidated.")


# ===============================================================================
# Public proactive-refresh API
# ===============================================================================

def ensure_token(cfg: FortifyAIConfig) -> FortifyAIConfig:
    """
    Return a *new* ``FortifyAIConfig`` with a guaranteed-fresh Bearer token.

    Decision logic
    ~~~~~~~~~~~~~~
    1. ``cfg.fortify_api_token`` is already set **and** the in-process cache
       has a valid entry -> return ``cfg`` unchanged (zero network calls).
    2. The cache has a valid token but ``cfg.fortify_api_token`` is stale/empty
       -> return a copy with the cached token injected.
    3. Cache miss or token within ``_EXPIRY_BUFFER_SECS`` of expiry
       -> fetch a fresh token, update the cache, return a copy with the new
       token injected and set it in the process environment.
    4. OAuth credentials missing **and** ``fortify_api_token`` is already set
       -> assume the caller manages the token manually; return ``cfg`` unchanged.

    The returned config is a Pydantic ``model_copy`` -- the original ``cfg``
    is never mutated.
    """
    # Fast path: check the in-process cache first (no credential check needed)
    cached = _cached_token(cfg)
    if cached:
        if cfg.fortify_api_token == cached:
            return cfg  # already in sync
        logger.debug("[FortifyAuth] Injecting cached token into config copy.")
        return cfg.model_copy(update={"fortify_api_token": cached})

    # If we have no OAuth credentials, fall back to the static token in cfg
    if not cfg.fortify_username or not cfg.fortify_password:
        if cfg.fortify_api_token:
            logger.debug(
                "[FortifyAuth] No OAuth credentials -- using static FORTIFY_API_TOKEN."
            )
            # Still seed the cache with a generous TTL so repeated calls are free
            with _cache_lock:
                _token_cache[_cache_key(cfg)] = _CachedToken(
                    access_token=cfg.fortify_api_token,
                    expires_at=time.time() + 28800,  # assume 8 h
                )
            return cfg
        raise ValueError(
            "No valid Fortify token available: FORTIFY_API_TOKEN is empty and "
            "FORTIFY_USERNAME / FORTIFY_PASSWORD are not set."
        )

    # Fetch a fresh token from the OAuth endpoint
    logger.info("[FortifyAuth] Token missing or near expiry -- fetching fresh token.")
    token_data   = fetch_token(cfg)
    access_token = _store_token(cfg, token_data)

    # Set the new token in the process environment so the next fresh
    # FortifyAIConfig() read (e.g. a future load_config() call) sees it too
    write_token_to_env(access_token)

    return cfg.model_copy(update={"fortify_api_token": access_token})


# ===============================================================================
# Core token fetch
# ===============================================================================

def fetch_token(
    cfg: FortifyAIConfig,
    username: Optional[str] = None,
    password: Optional[str] = None,
    scope: Optional[str] = None,
) -> dict:
    """
    POST /oauth/token with password grant.

    Parameters override environment-variable values when provided -- useful
    for one-off token requests without modifying config.

    Returns the full token response dict:
        {
            "access_token": "eyJ...",
            "token_type":   "Bearer",
            "expires_in":   28800,       # seconds (8 h typical)
            "scope":        "api-tenant",
            ...
        }

    Raises:
        ValueError  -- if required credentials are missing
        requests.HTTPError -- on non-2xx response from Fortify
    """
    resolved_username = username or cfg.fortify_username
    resolved_password = password or cfg.fortify_password
    resolved_scope    = scope    or cfg.fortify_scope or "api-tenant"

    if not resolved_username:
        raise ValueError(
            "FORTIFY_USERNAME is required for OAuth token fetch. "
            "Set it as an environment variable or pass as a request parameter."
        )
    if not resolved_password:
        raise ValueError(
            "FORTIFY_PASSWORD is required for OAuth token fetch. "
            "Set it as an environment variable or pass as a request parameter."
        )
    if not cfg.fortify_base_url:
        raise ValueError(
            "FORTIFY_BASE_URL is required. Set it as an environment variable."
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
        f"scope='{resolved_scope}' -> {url}"
    )

    t0 = time.time()
    resp = requests.post(
        url,
        data=payload,                          # form-encoded, NOT JSON
        headers={"Accept": "application/json"},
        timeout=_REQUEST_TIMEOUT,
	verify=False,
    )

    elapsed = round(time.time() - t0, 2)

    if not resp.ok:
        logger.error(
            f"[FortifyAuth] ERROR Token fetch failed -- "
            f"HTTP {resp.status_code} ({elapsed}s): {resp.text[:300]}"
        )
        resp.raise_for_status()

    token_data: dict = resp.json()
    access_token = token_data.get("access_token", "")
    expires_in   = token_data.get("expires_in", "?")

    logger.info(
        f"[FortifyAuth] OK Token obtained ({elapsed}s) -- "
        f"expires_in={expires_in}s  "
        f"preview={access_token[:12]}..."
    )

    return token_data


# ===============================================================================
# Environment-variable writeback
# ===============================================================================

def write_token_to_env(token: str, env_path: str | Path | None = None) -> None:
    """
    Set FORTIFY_API_TOKEN in the current process's environment.

    This no longer writes to a .env file on disk -- config.py reads
    FortifyAIConfig fields straight from the process environment, so a
    value written only to a .env file would never be picked back up.

    ``env_path`` is accepted (and ignored) purely for backward
    compatibility with older callers that still pass it; it has no effect.

    Note: this only affects the *current process's* environment. It does
    NOT persist across a server restart -- set FORTIFY_API_TOKEN at the
    container / orchestrator level if you need it to survive a restart.
    """
    if env_path is not None:
        logger.debug(
            "[FortifyAuth] write_token_to_env: env_path is ignored -- the "
            "token is set directly in the process environment instead."
        )
    os.environ["FORTIFY_API_TOKEN"] = token
    logger.info(
        f"[FortifyAuth] OK FORTIFY_API_TOKEN set in process environment "
        f"(preview: {token[:12]}...)"
    )


def refresh_token_in_env(
    cfg: FortifyAIConfig,
    env_path: str | Path | None = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    scope: Optional[str] = None,
) -> dict:
    """
    Convenience: fetch a fresh token and set it as FORTIFY_API_TOKEN in the
    process environment in one call.

    ``env_path`` is accepted (and ignored) for backward compatibility.

    Returns the full token response dict (same as fetch_token).
    """
    token_data = fetch_token(cfg, username=username, password=password, scope=scope)
    access_token = token_data.get("access_token", "")
    if access_token:
        write_token_to_env(access_token, env_path=env_path)
    return token_data