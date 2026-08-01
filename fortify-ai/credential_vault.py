"""
FortifyAI — Credential Vault
-----------------------------
Symmetric encryption (Fernet — AES-128-CBC + HMAC-SHA256) for the secret
fields inside a pipeline's ``resume_meta.config_overrides`` before it is
persisted to the job store (GCS or in-process — see job_store.py).

Why this exists
~~~~~~~~~~~~~~~~
Every full-pipeline endpoint (``/pipeline/live``, ``/offline``,
``/app-name``, ``/app-id``, ``/dry-run``) snapshots the request's
``ConfigOverrides`` into ``resume_meta`` so a later
``POST /pipeline/resume/{pipeline_id}`` — manual or automatic, see
``_run_orphan_sweep`` / ``startup_event`` in api_server.py — can rebuild
the *exact* ``FortifyAIConfig`` the original run used, including any
per-request credentials that were supplied instead of the server's
default env vars. That snapshot lives in the job store, which is the same
GCS bucket used for escalation reports and job docs — readable by anyone
with bucket access. Persisting Fortify passwords / GitHub PATs / Sonar
tokens into it in plaintext would be a straightforward credential leak.

Design
~~~~~~
- Only ``SECRET_FIELDS`` (below) are encrypted. Everything else in
  ``config_overrides`` (paths, repo name, gcp project/location, retry
  counts, ...) stays plain JSON so status polls / debugging remain
  readable without needing the key.
- ``encrypt_resume_meta`` pops the secret keys out of ``config_overrides``,
  JSON-serializes just that sub-dict, and Fernet-encrypts it into one
  opaque ``config_overrides_secret`` string stored alongside the now
  secret-free ``config_overrides``.
- ``decrypt_resume_meta`` reverses this on resume.
- Key material: ``CREDENTIAL_ENCRYPTION_KEY``, a urlsafe-base64 32-byte
  Fernet key.
    * If already set (process env, or synced in via the
      ``runtime_config.py`` GCS overlay), every pod agrees and resume
      works cross-pod.
    * If unset, one is generated on first use and pushed through
      ``runtime_config.persist_overrides`` — the same GCS-overlay
      mechanism already used to fan out refreshed Fortify tokens — so
      every other pod picks it up within ``CONFIG_SYNC_SECONDS``. In
      production, prefer setting ``CREDENTIAL_ENCRYPTION_KEY`` explicitly
      from Secret Manager rather than relying on this bootstrap path.
    * If GCS isn't configured at all (local/single-pod dev), the
      generated key just stays process-local, which is fine since resume
      only needs to work within that one process in that mode anyway.
- Fernet tokens are self-describing and carry a MAC, so a rotated key or
  corrupted blob decrypts to an exception rather than garbage. That's
  treated as "no saved credentials" (falls back to whatever the server's
  default env credentials are) instead of failing the resume outright —
  losing a saved override is much better than crashing an otherwise
  resumable pipeline.
"""

from __future__ import annotations

import json
import os
import threading

from loguru import logger

# Keep in sync with ConfigOverrides in api_server.py — these are the only
# fields ever pulled out of config_overrides for encryption.
SECRET_FIELDS = frozenset({
    "fortify_api_token",
    "fortify_username",
    "fortify_password",
    "github_token",
    "sonar_token",
})

_ENV_KEY = "CREDENTIAL_ENCRYPTION_KEY"

_lock = threading.Lock()
_cached_key: bytes | None = None
_cached_fernet = None  # cryptography.fernet.Fernet, cached against _cached_key


def _generate_key() -> str:
    from cryptography.fernet import Fernet
    return Fernet.generate_key().decode("ascii")


def _get_key() -> bytes:
    """
    Return the active Fernet key as bytes, generating + sharing one on
    first use if nothing is configured yet. Re-checks the environment on
    every call (cheap) so a key another pod generated and synced in via
    runtime_config.apply_overrides() is picked up automatically.
    """
    global _cached_key, _cached_fernet

    raw = os.environ.get(_ENV_KEY, "").strip()
    if raw:
        raw_bytes = raw.encode("ascii")
        with _lock:
            if raw_bytes != _cached_key:
                _cached_key = raw_bytes
                _cached_fernet = None
            return _cached_key

    with _lock:
        if _cached_key is not None:
            # No env value synced in yet, but this process already minted
            # one — keep using it rather than generating a second key
            # every call (which would make our own writes undecryptable).
            return _cached_key

    new_key = _generate_key()
    try:
        from runtime_config import persist_overrides
        persist_overrides({_ENV_KEY: new_key})
        logger.warning(
            "[CredentialVault] No CREDENTIAL_ENCRYPTION_KEY was configured — "
            "generated one and persisted it via the shared runtime config "
            "so every pod can decrypt resumable pipelines' saved "
            "credentials. For production, set CREDENTIAL_ENCRYPTION_KEY "
            "explicitly (e.g. sourced from Secret Manager) instead."
        )
    except Exception as exc:
        os.environ[_ENV_KEY] = new_key
        logger.warning(
            f"[CredentialVault] No CREDENTIAL_ENCRYPTION_KEY configured and "
            f"the generated key could not be shared via runtime_config "
            f"({exc}) — using a process-local key instead. Saved "
            f"credentials will only be decryptable on THIS pod; resumes "
            f"picked up by another pod will fall back to server-default "
            f"env credentials."
        )

    with _lock:
        _cached_key = new_key.encode("ascii")
        _cached_fernet = None
        return _cached_key


def _fernet():
    from cryptography.fernet import Fernet
    key = _get_key()
    global _cached_fernet
    with _lock:
        if _cached_fernet is None:
            _cached_fernet = Fernet(key)
        return _cached_fernet


def encrypt_resume_meta(resume_meta: dict) -> dict:
    """
    Return a copy of *resume_meta* with any SECRET_FIELDS values inside
    ``config_overrides`` removed from plaintext and replaced with one
    encrypted ``config_overrides_secret`` string. A resume_meta with no
    secrets set (e.g. an offline run using only server-default
    credentials) is returned unchanged aside from the pop — no encrypted
    field is added.
    """
    meta = dict(resume_meta or {})
    overrides = dict(meta.get("config_overrides") or {})

    secret_payload = {
        k: overrides.pop(k)
        for k in list(overrides)
        if k in SECRET_FIELDS and overrides.get(k) is not None
    }
    meta["config_overrides"] = overrides
    meta.pop("config_overrides_secret", None)

    if secret_payload:
        try:
            token = _fernet().encrypt(json.dumps(secret_payload).encode("utf-8"))
            meta["config_overrides_secret"] = token.decode("ascii")
        except Exception as exc:
            logger.error(
                f"[CredentialVault] Encryption failed — per-request "
                f"credentials for this run will NOT be saved for resume "
                f"({exc}); a resume will fall back to server-default env "
                f"credentials."
            )
    return meta


def decrypt_resume_meta(resume_meta: dict | None) -> dict:
    """
    Return a copy of *resume_meta* with ``config_overrides_secret``
    decrypted and merged back into ``config_overrides``. Safe to call on
    a resume_meta that has no encrypted secrets (older jobs, or runs that
    never had per-request credentials) — returns it unchanged. If
    decryption fails (rotated/missing key, corrupt blob), the secret
    fields are silently dropped rather than raising, so the resume still
    proceeds using whatever credentials are configured in the process
    environment.
    """
    meta = dict(resume_meta or {})
    token = meta.pop("config_overrides_secret", None)
    overrides = dict(meta.get("config_overrides") or {})

    if token:
        try:
            raw = _fernet().decrypt(token.encode("ascii"))
            secret_payload = json.loads(raw.decode("utf-8"))
            overrides.update(secret_payload)
        except Exception as exc:
            logger.warning(
                f"[CredentialVault] Could not decrypt saved credentials for "
                f"this resume ({exc}) — continuing with server-default env "
                f"credentials instead."
            )

    meta["config_overrides"] = overrides
    return meta
