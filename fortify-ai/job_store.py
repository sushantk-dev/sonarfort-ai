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
- Each completed stage's JSON-serializable output is checkpointed to
  ``{pipeline_id}.checkpoint.json`` (also kept out of the small job doc for
  the same reason). If a run later fails or is cancelled, ``POST
  /pipeline/resume/{pipeline_id}`` reads this checkpoint and re-enters
  ``_run_full_pipeline`` partway through instead of from stage 1 — stages
  with side effects (adr-fix, pr-agent) are not redone once their output is
  checkpointed. Cleared automatically once the job completes successfully.
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
        "cancel_requested": False,
        "stages":          _blank_stages(stages),
        # Non-secret request metadata needed to reconstruct cfg/client on a
        # resume (release_id, repo, report_path, dry_run, ...). Set once at
        # job creation by api_server.py. None means "resume unsupported"
        # (e.g. a job created before this feature existed).
        "resume_meta":     None,
        # Name of the next stage a resume would start at. Mirrored from the
        # checkpoint doc onto this small record so status polls can show
        # resumability without downloading the (potentially large) checkpoint.
        "resume_stage":    None,
        # NullJobStore keeps the checkpoint payload inline (GcsJobStore keeps
        # it in a separate blob) — always present so save/get/delete_checkpoint
        # don't need special-casing.
        "checkpoint":      None,
        # Bumped on every update_job/update_stage call. Used by the orphan-job
        # sweep (find_stale_running) to distinguish a job that is genuinely
        # still working from one whose pod died silently (OOM kill, node
        # loss) without ever reaching finish_job — a "running" job with no
        # progress for longer than the sweep timeout is presumed orphaned.
        "last_progress_at": _now(),
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

    @abstractmethod
    def request_cancel(self, pipeline_id: str) -> None:
        """Flag a running job for cooperative cancellation.

        This does NOT stop work already executing inside a thread-pool
        stage — it sets a flag that the pipeline runner checks between
        stages (see ``_check_cancelled`` in api_server.py) so the run
        stops advancing to the next stage/side-effect as soon as possible.
        """

    @abstractmethod
    def is_cancel_requested(self, pipeline_id: str) -> bool:
        """Return True if ``request_cancel`` was called for this job."""

    @abstractmethod
    def save_checkpoint(self, pipeline_id: str, **fields) -> None:
        """
        Persist the full accumulated checkpoint for a job (the completed
        stages' JSON-serializable output, plus ``resume_stage`` — the name
        of the next stage to run). Called once per completed stage by the
        pipeline runner with the *entire* checkpoint so far, not a delta.

        Kept separate from the main job doc so frequent status polls never
        have to download the (potentially large) intermediate stage data.
        """

    @abstractmethod
    def get_checkpoint(self, pipeline_id: str) -> dict | None:
        """Return the saved checkpoint dict, or None if the job has none."""

    @abstractmethod
    def delete_checkpoint(self, pipeline_id: str) -> None:
        """Best-effort cleanup once a job completes successfully and its
        checkpoint is no longer needed for a resume."""

    @abstractmethod
    def find_stale_running(self, timeout_seconds: float) -> list[dict]:
        """
        Return job docs with status == 'running' whose last_progress_at is
        older than *timeout_seconds*. Used by the orphan-job sweep to find
        jobs whose pod died (OOM kill, node eviction, hard crash) without
        ever calling finish_job, so they don't stay stuck at 'running'
        forever. Callers should finish_job(..., status='failed') on each
        result — this does NOT mutate anything itself.
        """


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

    def _checkpoint_blob_name(self, pid: str) -> str:
        return f"{self._prefix}{pid}.checkpoint.json"

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
            "last_progress_epoch": str(self._epoch(job.get("last_progress_at") or _now())),
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
        def _apply(doc: dict) -> None:
            doc.update(fields)
            doc["last_progress_at"] = _now()
        self._mutate(pipeline_id, _apply, "update_job")

    def update_stage(self, pipeline_id: str, stage: str, **fields) -> None:
        def _apply(doc: dict) -> None:
            doc.setdefault("stages", {}).setdefault(stage, {}).update(fields)
            doc["last_progress_at"] = _now()
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
            if status == "completed":
                # No longer needed for a resume — free the checkpoint blob.
                doc["resume_stage"] = None

        self._mutate(pipeline_id, _apply, "finish_job")
        if status == "completed":
            self.delete_checkpoint(pipeline_id)

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

    def request_cancel(self, pipeline_id: str) -> None:
        def _apply(doc: dict) -> None:
            doc["cancel_requested"] = True
        self._mutate(pipeline_id, _apply, "request_cancel")

    def is_cancel_requested(self, pipeline_id: str) -> bool:
        doc, _gen = self._read_doc(pipeline_id)
        return bool(doc and doc.get("cancel_requested"))

    # ── Checkpoint / resume support ───────────────────────────────────────────

    def save_checkpoint(self, pipeline_id: str, **fields) -> None:
        # Only the single pipeline run that owns this job ever writes its
        # checkpoint, sequentially, one stage at a time — no concurrent
        # writers, so a plain overwrite is safe (no CAS needed here, unlike
        # update_job/update_stage which can race with cancel/poll writers).
        try:
            blob = self._bucket.blob(self._checkpoint_blob_name(pipeline_id))
            blob.upload_from_string(
                json.dumps(fields).encode("utf-8"),
                content_type="application/json",
            )
        except Exception as exc:
            logger.error(f"[JobStore] save_checkpoint failed for {pipeline_id}: {exc}")
            return
        # Mirror the resume point onto the small job doc so status polls can
        # show "resumable from: X" without downloading the checkpoint blob.
        self.update_job(pipeline_id, resume_stage=fields.get("resume_stage"))

    def get_checkpoint(self, pipeline_id: str) -> dict | None:
        from google.api_core import exceptions as gexc
        blob = self._bucket.blob(self._checkpoint_blob_name(pipeline_id))
        try:
            raw = blob.download_as_bytes()
        except gexc.NotFound:
            return None
        return json.loads(raw.decode("utf-8")) if raw else None

    def delete_checkpoint(self, pipeline_id: str) -> None:
        from google.api_core import exceptions as gexc
        try:
            self._bucket.blob(self._checkpoint_blob_name(pipeline_id)).delete()
        except gexc.NotFound:
            pass
        except Exception as exc:
            logger.debug(f"[JobStore] delete_checkpoint skipped for {pipeline_id}: {exc}")

    # ── Orphan-job sweep support ───────────────────────────────────────────────

    def find_stale_running(self, timeout_seconds: float) -> list[dict]:
        """
        Cheap two-pass scan: filter candidates using only blob metadata
        (no downloads), then fetch the small job docs for just those
        candidates. Safe to call frequently from a background sweep loop
        without downloading every job in the bucket each time.
        """
        cutoff = time.time() - timeout_seconds
        candidates: list[str] = []
        for blob in self._client.list_blobs(self._bucket_name, prefix=self._prefix):
            name = blob.name
            if not name.endswith(".json") or name.endswith(".result.json") \
                    or name.endswith(".checkpoint.json"):
                continue
            meta = blob.metadata or {}
            if meta.get("status") != "running":
                continue
            try:
                progress_epoch = float(meta.get("last_progress_epoch", ""))
            except (TypeError, ValueError):
                progress_epoch = blob.time_created.timestamp() if blob.time_created else time.time()
            if progress_epoch < cutoff:
                candidates.append(name[len(self._prefix):-len(".json")])

        stale: list[dict] = []
        for pid in candidates:
            doc, _gen = self._read_doc(pid)
            # Re-check status/timestamp on the freshly read doc — the blob
            # metadata snapshot above can be a request or two stale.
            if doc and doc.get("status") == "running":
                progress_epoch = self._epoch(doc.get("last_progress_at") or _now())
                if progress_epoch < cutoff:
                    stale.append(doc)
        return stale

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
                self._jobs[pipeline_id]["last_progress_at"] = _now()

    def update_stage(self, pipeline_id: str, stage: str, **fields) -> None:
        with self._lock:
            job = self._jobs.get(pipeline_id)
            if job:
                job["stages"][stage].update(fields)
                job["last_progress_at"] = _now()

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
                if status == "completed":
                    j["checkpoint"] = None
                    j["resume_stage"] = None

    def list_jobs(self, limit: int = 50, offset: int = 0) -> list[dict]:
        with self._lock:
            jobs = sorted(
                self._jobs.values(),
                key=lambda j: j.get("started_at", ""),
                reverse=True,
            )
        return [
            {k: v for k, v in j.items() if k not in ("result", "checkpoint")}
            for j in jobs[offset: offset + limit]
        ]

    def request_cancel(self, pipeline_id: str) -> None:
        with self._lock:
            j = self._jobs.get(pipeline_id)
            if j:
                j["cancel_requested"] = True

    def is_cancel_requested(self, pipeline_id: str) -> bool:
        with self._lock:
            j = self._jobs.get(pipeline_id)
            return bool(j and j.get("cancel_requested"))

    # ── Checkpoint / resume support ───────────────────────────────────────────

    def save_checkpoint(self, pipeline_id: str, **fields) -> None:
        with self._lock:
            j = self._jobs.get(pipeline_id)
            if j:
                j["checkpoint"] = dict(fields)
                j["resume_stage"] = fields.get("resume_stage")

    def get_checkpoint(self, pipeline_id: str) -> dict | None:
        with self._lock:
            j = self._jobs.get(pipeline_id)
            ckpt = j.get("checkpoint") if j else None
            return dict(ckpt) if ckpt else None

    def delete_checkpoint(self, pipeline_id: str) -> None:
        with self._lock:
            j = self._jobs.get(pipeline_id)
            if j:
                j["checkpoint"] = None

    # ── Orphan-job sweep support ───────────────────────────────────────────────

    def find_stale_running(self, timeout_seconds: float) -> list[dict]:
        cutoff = time.time() - timeout_seconds
        stale: list[dict] = []
        with self._lock:
            for j in self._jobs.values():
                if j.get("status") != "running":
                    continue
                try:
                    progress_epoch = datetime.fromisoformat(
                        j.get("last_progress_at") or j.get("started_at")
                    ).timestamp()
                except Exception:
                    continue
                if progress_epoch < cutoff:
                    stale.append(dict(j))
        return stale


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