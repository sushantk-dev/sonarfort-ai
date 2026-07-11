"""
FortifyAI — Job Store
----------------------
Stateless, GCS-backed replacement for the in-memory ``_JOBS`` dict in
``api_server.py``.  All pipeline state is persisted in a Cloud Storage bucket
so any pod in a Kubernetes deployment can serve status queries for a job
started by another pod.

Configuration
~~~~~~~~~~~~~
``GCS_BUCKET``       — bucket name (same bucket used for escalation reports).
``GCS_JOB_PREFIX``   — object prefix for job docs (default ``fortifyai/jobs/``).
``JOB_TTL_SECONDS``  — lazy-purge age for old jobs (default 24 h).

Auth uses Application Default Credentials / Workload Identity on GKE —
no key file needed (same as fortify_writeback.py).

Key design
~~~~~~~~~~
- Each job is stored as a JSON object at
  ``gs://{GCS_BUCKET}/{GCS_JOB_PREFIX}{pipeline_id}.json``.
- The (potentially large) ``result`` payload is stored separately at
  ``{pipeline_id}.result.json`` so status polling and ``/pipeline/runs``
  listings never download the full result blob.
- ``started_at`` is mirrored into custom blob metadata so ``list_jobs`` can
  sort newest-first from the listing alone, without downloading every doc.
- Read-modify-write updates use GCS generation preconditions
  (``if_generation_match``) with a small retry loop, so concurrent stage
  updates from different threads/pods never silently overwrite each other.
- TTL: unlike Redis, GCS objects can't expire client-side. Configure a
  bucket lifecycle rule (age > 1 day, prefix ``fortifyai/jobs/``) for real
  cleanup. A lazy in-process purge also runs opportunistically as a backstop.
- A ``NullJobStore`` (in-process dict) is used as fallback when GCS is
  unavailable, so the service still works in local / single-pod mode.

Thread safety
~~~~~~~~~~~~~
google-cloud-storage clients are thread-safe for concurrent requests.
Generation preconditions provide cross-thread / cross-pod write safety.
``NullJobStore`` uses a threading.Lock to match the original behaviour.
"""

from __future__ import annotations

import json
import os
import time
import threading
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from loguru import logger

# ── Constants ─────────────────────────────────────────────────────────────────

_GCS_BUCKET   = os.environ.get("GCS_BUCKET", "").strip()
_JOB_PREFIX   = os.environ.get("GCS_JOB_PREFIX", "fortifyai/jobs/").rstrip("/") + "/"
_JOB_TTL_SEC  = int(os.environ.get("JOB_TTL_SECONDS", 86400))   # 24 h default

_SAVE_RETRIES = 4          # optimistic-concurrency retry attempts
_PURGE_EVERY  = 600        # lazy purge at most once per 10 min per process

ALL_STAGE_NAMES = [
    "triage", "version-resolver", "context", "api-diff",
    "ai-reasoning", "adr-fix", "pr-agent", "fortify-writeback",
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _blank_stages(stages: list[str] | None) -> dict:
    return {
        s: {
            "status": "pending",
            "started_at": None,
            "finished_at": None,
            "elapsed_seconds": None,
            "error": None,
            "output_summary": None,
        }
        for s in (stages or ALL_STAGE_NAMES)
    }


def _blank_job(pipeline_id: str, stages: list[str] | None = None) -> dict:
    return {
        "pipeline_id":     pipeline_id,
        "status":          "queued",
        "started_at":      _now(),
        "finished_at":     None,
        "elapsed_seconds": None,
        "error":           None,
        "result":          None,
        "stages":          _blank_stages(stages),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Abstract interface
# ═══════════════════════════════════════════════════════════════════════════════

class JobStore(ABC):
    """Interface that api_server.py depends on."""

    @abstractmethod
    def new_job(self, stages: list[str] | None = None) -> dict:
        """Create and persist a fresh job; return it."""

    @abstractmethod
    def get_job(self, pipeline_id: str) -> dict | None:
        """Return the job dict or None if not found."""

    @abstractmethod
    def update_job(self, pipeline_id: str, **fields) -> None:
        """Merge top-level fields into the job record."""

    @abstractmethod
    def update_stage(self, pipeline_id: str, stage: str, **fields) -> None:
        """Merge fields into a specific stage sub-dict."""

    @abstractmethod
    def finish_job(
        self,
        pipeline_id: str,
        status: str,
        result: dict | None = None,
        error: str | None = None,
        t0: float | None = None,
    ) -> None:
        """Mark a job complete / failed."""

    @abstractmethod
    def list_jobs(self, limit: int = 50, offset: int = 0) -> list[dict]:
        """Return recent jobs newest-first (summary records)."""


# ═══════════════════════════════════════════════════════════════════════════════
# GCS implementation
# ═══════════════════════════════════════════════════════════════════════════════

class GcsJobStore(JobStore):
    """
    Objects
    ~~~~~~~
    ``{prefix}{pid}.json``          — job doc WITHOUT the ``result`` field
                                      (small; safe to poll every 1.5 s)
    ``{prefix}{pid}.result.json``   — result payload, written once at finish

    Custom metadata on the job doc:
      ``started_at_epoch`` — float string, used to sort listings newest-first
      ``status``           — mirrored for cheap future filtering
    """

    def __init__(self, bucket_name: str = _GCS_BUCKET, prefix: str = _JOB_PREFIX,
                 ttl: int = _JOB_TTL_SEC):
        from google.cloud import storage  # lazy import — module loads without lib
        self._client = storage.Client()
        self._bucket = self._client.bucket(bucket_name)
        self._bucket_name = bucket_name
        self._prefix = prefix
        self._ttl = ttl
        self._last_purge = 0.0
        self._purge_lock = threading.Lock()
        logger.info(
            f"[JobStore] Using GCS bucket gs://{bucket_name}/{prefix} "
            f"(TTL={ttl}s — configure a bucket lifecycle rule for hard cleanup)"
        )

    # ── Blob helpers ──────────────────────────────────────────────────────────

    def _doc_blob_name(self, pid: str) -> str:
        return f"{self._prefix}{pid}.json"

    def _result_blob_name(self, pid: str) -> str:
        return f"{self._prefix}{pid}.result.json"

    def _epoch(self, iso_ts: str) -> float:
        try:
            return datetime.fromisoformat(iso_ts).timestamp()
        except Exception:
            return time.time()

    def _write_doc(self, job: dict, if_generation_match: int | None = None) -> None:
        """
        Upload the job doc (result stripped). ``if_generation_match=0`` means
        create-only; a concrete generation means compare-and-swap; ``None``
        means unconditional overwrite (used only after retries are exhausted).
        """
        doc = {k: v for k, v in job.items() if k != "result"}
        blob = self._bucket.blob(self._doc_blob_name(job["pipeline_id"]))
        blob.metadata = {
            "started_at_epoch": str(self._epoch(job.get("started_at") or _now())),
            "status": str(job.get("status", "")),
        }
        blob.upload_from_string(
            json.dumps(doc).encode("utf-8"),
            content_type="application/json",
            if_generation_match=if_generation_match,
        )

    def _read_doc(self, pid: str) -> tuple[dict | None, int | None]:
        """Return (doc, generation) or (None, None) if the job doesn't exist."""
        from google.api_core import exceptions as gexc
        blob = self._bucket.blob(self._doc_blob_name(pid))
        try:
            data = blob.download_as_bytes()
        except gexc.NotFound:
            return None, None
        # download_as_bytes populates blob.generation from response headers,
        # so no extra reload() round-trip is needed for the CAS precondition.
        return json.loads(data.decode("utf-8")), blob.generation

    def _read_result(self, pid: str) -> Any:
        from google.api_core import exceptions as gexc
        blob = self._bucket.blob(self._result_blob_name(pid))
        try:
            raw = blob.download_as_bytes()
        except gexc.NotFound:
            return None
        return json.loads(raw.decode("utf-8")) if raw else None

    def _mutate(self, pid: str, fn, op_name: str) -> None:
        """
        Read-modify-write with generation precondition + retry.
        ``fn(doc)`` mutates the doc in place.
        """
        from google.api_core import exceptions as gexc
        for attempt in range(_SAVE_RETRIES):
            doc, gen = self._read_doc(pid)
            if doc is None:
                logger.warning(f"[JobStore] {op_name}: unknown pipeline_id {pid}")
                return
            fn(doc)
            try:
                self._write_doc(doc, if_generation_match=gen)
                return
            except gexc.PreconditionFailed:
                # Someone else wrote between our read and write — re-read & retry
                time.sleep(0.1 * (attempt + 1))
        # Last resort: unconditional write so progress isn't lost entirely
        logger.warning(f"[JobStore] {op_name}: CAS retries exhausted for {pid} — "
                       f"forcing unconditional write")
        doc, _ = self._read_doc(pid)
        if doc is not None:
            fn(doc)
            self._write_doc(doc)

    # ── Interface implementation ─────────────────────────────────────────────

    def new_job(self, stages: list[str] | None = None) -> dict:
        from google.api_core import exceptions as gexc
        pid = str(uuid.uuid4())
        job = _blank_job(pid, stages)
        try:
            self._write_doc(job, if_generation_match=0)   # create-only
        except gexc.PreconditionFailed:                   # UUID collision — absurd, but safe
            return self.new_job(stages)
        self._maybe_purge()
        return job

    def get_job(self, pipeline_id: str) -> dict | None:
        doc, _ = self._read_doc(pipeline_id)
        if doc is None:
            return None
        # Reattach the result payload only for direct single-job reads
        doc["result"] = self._read_result(pipeline_id)
        return doc

    def update_job(self, pipeline_id: str, **fields) -> None:
        fields.pop("result", None)  # result is written only via finish_job
        self._mutate(pipeline_id, lambda d: d.update(fields), "update_job")

    def update_stage(self, pipeline_id: str, stage: str, **fields) -> None:
        def _apply(doc: dict) -> None:
            doc.setdefault("stages", {}).setdefault(stage, {}).update(fields)
        self._mutate(pipeline_id, _apply, "update_stage")

    def finish_job(
        self,
        pipeline_id: str,
        status: str,
        result: dict | None = None,
        error: str | None = None,
        t0: float | None = None,
    ) -> None:
        # Write the heavy result blob first (idempotent overwrite is fine)
        if result is not None:
            try:
                blob = self._bucket.blob(self._result_blob_name(pipeline_id))
                blob.upload_from_string(
                    json.dumps(result).encode("utf-8"),
                    content_type="application/json",
                )
            except Exception as exc:
                logger.error(f"[JobStore] finish_job: result upload failed for "
                             f"{pipeline_id}: {exc}")

        def _apply(doc: dict) -> None:
            doc["status"]          = status
            doc["finished_at"]     = _now()
            doc["elapsed_seconds"] = round(time.time() - t0, 3) if t0 else None
            doc["error"]           = error

        self._mutate(pipeline_id, _apply, "finish_job")

    def list_jobs(self, limit: int = 50, offset: int = 0) -> list[dict]:
        # 1. List job-doc blobs (skip .result.json), sort by started_at metadata
        entries: list[tuple[float, str]] = []   # (epoch, pid)
        for blob in self._client.list_blobs(self._bucket_name, prefix=self._prefix):
            name = blob.name
            if not name.endswith(".json") or name.endswith(".result.json"):
                continue
            pid = name[len(self._prefix):-len(".json")]
            meta = blob.metadata or {}
            try:
                epoch = float(meta.get("started_at_epoch", ""))
            except (TypeError, ValueError):
                epoch = blob.time_created.timestamp() if blob.time_created else 0.0
            entries.append((epoch, pid))

        entries.sort(key=lambda e: e[0], reverse=True)   # newest first
        page = entries[offset: offset + limit]

        # 2. Download only the docs in the requested page (small blobs, no result)
        jobs: list[dict] = []
        for _, pid in page:
            doc, _gen = self._read_doc(pid)
            if doc:
                doc.pop("result", None)   # defensive — doc never contains it
                jobs.append(doc)
        return jobs

    # ── Lazy TTL purge (backstop — prefer a bucket lifecycle rule) ───────────

    def _maybe_purge(self) -> None:
        now = time.time()
        with self._purge_lock:
            if now - self._last_purge < _PURGE_EVERY:
                return
            self._last_purge = now
        try:
            cutoff = now - self._ttl
            for blob in self._client.list_blobs(self._bucket_name, prefix=self._prefix):
                meta = blob.metadata or {}
                try:
                    epoch = float(meta.get("started_at_epoch", ""))
                except (TypeError, ValueError):
                    epoch = blob.time_created.timestamp() if blob.time_created else now
                if epoch < cutoff:
                    blob.delete()
        except Exception as exc:
            logger.debug(f"[JobStore] lazy purge skipped: {exc}")


# ═══════════════════════════════════════════════════════════════════════════════
# In-process fallback (single-pod / local dev)
# ═══════════════════════════════════════════════════════════════════════════════

class NullJobStore(JobStore):
    """
    In-process dict store — identical to the original ``_JOBS`` behaviour.
    Used automatically when GCS is not reachable.  NOT safe for multi-pod
    deployments — set ``GCS_BUCKET`` in production.
    """

    def __init__(self) -> None:
        self._jobs: Dict[str, dict] = {}
        self._lock = threading.Lock()
        logger.warning(
            "[JobStore] GCS unavailable — using in-process NullJobStore. "
            "Pipeline status will NOT survive pod restarts or be visible across replicas. "
            "Set GCS_BUCKET to enable shared state."
        )

    def new_job(self, stages: list[str] | None = None) -> dict:
        pid = str(uuid.uuid4())
        job = _blank_job(pid, stages)
        with self._lock:
            self._jobs[pid] = job
        return job

    def get_job(self, pipeline_id: str) -> dict | None:
        with self._lock:
            return self._jobs.get(pipeline_id)

    def update_job(self, pipeline_id: str, **fields) -> None:
        with self._lock:
            if pipeline_id in self._jobs:
                self._jobs[pipeline_id].update(fields)

    def update_stage(self, pipeline_id: str, stage: str, **fields) -> None:
        with self._lock:
            job = self._jobs.get(pipeline_id)
            if job:
                job["stages"][stage].update(fields)

    def finish_job(
        self,
        pipeline_id: str,
        status: str,
        result: dict | None = None,
        error: str | None = None,
        t0: float | None = None,
    ) -> None:
        with self._lock:
            j = self._jobs.get(pipeline_id)
            if j:
                j["status"]          = status
                j["finished_at"]     = _now()
                j["elapsed_seconds"] = round(time.time() - t0, 3) if t0 else None
                j["result"]          = result
                j["error"]           = error

    def list_jobs(self, limit: int = 50, offset: int = 0) -> list[dict]:
        with self._lock:
            jobs = sorted(
                self._jobs.values(),
                key=lambda j: j.get("started_at", ""),
                reverse=True,
            )
        return [
            {k: v for k, v in j.items() if k != "result"}
            for j in jobs[offset: offset + limit]
        ]


# ═══════════════════════════════════════════════════════════════════════════════
# Factory — called once at api_server startup
# ═══════════════════════════════════════════════════════════════════════════════

def create_job_store() -> JobStore:
    """
    Return a ``GcsJobStore`` if GCS_BUCKET is set and reachable, else
    ``NullJobStore``.

    The probe is a single metadata GET with a short timeout so startup is
    not blocked when GCS is optional (e.g. local development).
    """
    bucket_name = os.environ.get("GCS_BUCKET", "").strip()
    if not bucket_name:
        return NullJobStore()
    try:
        from google.cloud import storage
        client = storage.Client()
        client.get_bucket(bucket_name, timeout=5)   # probe: existence + IAM
        return GcsJobStore(bucket_name)
    except Exception as exc:
        logger.warning(f"[JobStore] GCS probe failed ({exc}) — falling back to NullJobStore")
        return NullJobStore()