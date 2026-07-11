"""
FortifyAI — Runtime Config Overrides (GCS-backed)
--------------------------------------------------
Makes Settings-page config changes and Fortify token refreshes stateless.

Problem this solves
~~~~~~~~~~~~~~~~~~~
``POST /api/config`` and ``POST /auth/token`` used to write values into
``os.environ`` of *one* process. In a multi-pod GKE deployment the other
replicas never saw the change, and everything was lost on restart.

Design
~~~~~~
- Overrides are stored as a single JSON object at
  ``gs://{GCS_BUCKET}/{GCS_CONFIG_PREFIX}runtime.json``
  (default prefix: ``fortifyai/config/``), e.g.::

      {"VERTEX_MODEL": "gemini-2.5-pro", "FORTIFY_API_TOKEN": "eyJ..."}

- ``persist_overrides(dict)`` merges new keys into the blob using a GCS
  generation precondition (compare-and-swap) so concurrent saves from
  different pods never lose each other's keys.

- ``apply_overrides()`` downloads the blob and sets each key into
  ``os.environ`` so the very next ``load_config()`` (Pydantic BaseSettings,
  which reads the process environment) picks the values up. The download is
  cached for ``CONFIG_SYNC_SECONDS`` (default 15 s) so calling it on every
  HTTP request (via middleware) costs one GCS GET per pod per 15 s.

- When ``GCS_BUCKET`` is unset, both functions degrade to plain
  ``os.environ`` behaviour (single-pod / local dev) and are no-ops for
  persistence.

Security note
~~~~~~~~~~~~~
Tokens (GITHUB_TOKEN, FORTIFY_API_TOKEN, SONAR_TOKEN) saved through the UI
end up in this blob. Keep the bucket private (uniform bucket-level access,
no public IAM bindings) — the same trust level as the escalation reports
and job docs already stored there. For deploy-time secrets, prefer Secret
Manager; this blob only carries *runtime* changes made through the UI.
"""

from __future__ import annotations

import json
import os
import threading
import time

from loguru import logger

_CONFIG_PREFIX = os.environ.get("GCS_CONFIG_PREFIX", "fortifyai/config/").rstrip("/") + "/"
_BLOB_NAME     = _CONFIG_PREFIX + "runtime.json"
_SYNC_SECONDS  = float(os.environ.get("CONFIG_SYNC_SECONDS", 15))
_CAS_RETRIES   = 4

_lock          = threading.Lock()
_last_sync     = 0.0
_last_applied: dict[str, str] = {}


def _bucket():
    """Return (bucket, name) or (None, None) when GCS is not configured."""
    name = os.environ.get("GCS_BUCKET", "").strip()
    if not name:
        return None, None
    try:
        from google.cloud import storage
        return storage.Client().bucket(name), name
    except Exception as exc:
        logger.warning(f"[RuntimeConfig] GCS unavailable ({exc})")
        return None, None


def _read_blob(bucket) -> tuple[dict, int | None]:
    """Return (overrides, generation). Missing blob → ({}, None)."""
    from google.api_core import exceptions as gexc
    blob = bucket.blob(_BLOB_NAME)
    try:
        raw = blob.download_as_bytes()
    except gexc.NotFound:
        return {}, None
    try:
        data = json.loads(raw.decode("utf-8")) or {}
    except Exception:
        logger.warning("[RuntimeConfig] runtime.json is corrupt — treating as empty")
        data = {}
    return data, blob.generation


def persist_overrides(updates: dict[str, str]) -> bool:
    """
    Merge *updates* into the shared runtime.json blob (CAS with retry) and
    apply them to this process's environment immediately.

    Returns True when persisted to GCS, False when GCS is not configured or
    the write failed (values are still applied to the local process env so
    single-pod behaviour matches the original).
    """
    # Always apply locally first — preserves original single-pod semantics.
    for k, v in updates.items():
        os.environ[k] = str(v)

    bucket, _name = _bucket()
    if bucket is None:
        return False

    from google.api_core import exceptions as gexc
    for attempt in range(_CAS_RETRIES):
        current, gen = _read_blob(bucket)
        current.update({k: str(v) for k, v in updates.items()})
        blob = bucket.blob(_BLOB_NAME)
        try:
            blob.upload_from_string(
                json.dumps(current, indent=2).encode("utf-8"),
                content_type="application/json",
                if_generation_match=gen if gen is not None else 0,
            )
            _mark_synced(current)
            logger.info(f"[RuntimeConfig] Persisted {len(updates)} key(s) to GCS "
                        f"({', '.join(sorted(updates))})")
            return True
        except gexc.PreconditionFailed:
            time.sleep(0.1 * (attempt + 1))     # another pod wrote — re-merge
        except Exception as exc:
            logger.error(f"[RuntimeConfig] Persist failed: {exc}")
            return False
    logger.error("[RuntimeConfig] Persist failed: CAS retries exhausted")
    return False


def apply_overrides(force: bool = False) -> None:
    """
    Pull the shared runtime.json (throttled to once per CONFIG_SYNC_SECONDS
    per process) and set every key into ``os.environ``.

    Safe to call on every request via middleware. No-op when GCS_BUCKET is
    unset. Keys removed from the blob are NOT unset locally (deploy-time env
    always remains as the base layer; the blob is an overlay).
    """
    global _last_sync
    now = time.time()
    with _lock:
        if not force and (now - _last_sync) < _SYNC_SECONDS:
            return
        _last_sync = now

    bucket, _name = _bucket()
    if bucket is None:
        return
    try:
        overrides, _gen = _read_blob(bucket)
    except Exception as exc:
        logger.debug(f"[RuntimeConfig] Sync skipped: {exc}")
        return

    changed = []
    for k, v in overrides.items():
        v = str(v)
        if os.environ.get(k) != v:
            os.environ[k] = v
            changed.append(k)
    _mark_synced(overrides)
    if changed:
        logger.info(f"[RuntimeConfig] Applied override(s) from GCS: {', '.join(sorted(changed))}")


def _mark_synced(overrides: dict) -> None:
    global _last_applied
    _last_applied = dict(overrides)


def is_persisted() -> bool:
    """True when a GCS bucket is configured for override persistence."""
    return bool(os.environ.get("GCS_BUCKET", "").strip())
