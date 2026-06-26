"""
FortifyAI — Job Store
----------------------
Stateless, Redis-backed replacement for the in-memory ``_JOBS`` dict in
``api_server.py``.  All pipeline state is persisted in Redis so any pod in
a Kubernetes deployment can serve status queries for a job started by another
pod.

Configuration
~~~~~~~~~~~~~
Set the ``REDIS_URL`` environment variable (default: ``redis://localhost:6379/0``).
All other settings come from ``FortifyAIConfig`` / environment variables.

Key design
~~~~~~~~~~
- Each job is stored as a Redis hash at key ``fortifyai:job:<pipeline_id>``.
- Stage maps are stored as a nested JSON string inside the ``stages`` hash field.
- A sorted set ``fortifyai:jobs`` tracks pipeline_id → started_at (epoch) so
  ``/pipeline/runs`` can paginate without scanning all keys.
- TTL defaults to 24 hours so Redis does not grow unboundedly.
- A ``NullJobStore`` (in-process dict) is used as fallback when Redis is
  unavailable, so the service still works in local / single-pod mode.

Thread safety
~~~~~~~~~~~~~
redis-py's connection pool is thread-safe; no additional locking is required.
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

_KEY_PREFIX  = "fortifyai:job:"
_INDEX_KEY   = "fortifyai:jobs"
_JOB_TTL_SEC = int(os.environ.get("JOB_TTL_SECONDS", 86400))   # 24 h default
_REDIS_URL   = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

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
# Redis implementation
# ═══════════════════════════════════════════════════════════════════════════════

class RedisJobStore(JobStore):
    """
    Each job is stored as a Redis hash.  The ``stages`` field is a JSON string
    because Redis hashes only support flat string values.

    Keys
    ~~~~
    ``fortifyai:job:<uuid>``   — hash with all job fields
    ``fortifyai:jobs``         — sorted set: score = started_at epoch, member = pipeline_id
    """

    def __init__(self, redis_url: str = _REDIS_URL, ttl: int = _JOB_TTL_SEC):
        import redis  # imported lazily so the module loads without redis installed
        self._r = redis.from_url(redis_url, decode_responses=True)
        self._ttl = ttl
        logger.info(f"[JobStore] Using Redis at {redis_url} (TTL={ttl}s)")

    def _key(self, pid: str) -> str:
        return _KEY_PREFIX + pid

    def _save(self, job: dict) -> None:
        """Serialise the job dict to the Redis hash."""
        pid = job["pipeline_id"]
        key = self._key(pid)
        flat: dict[str, str] = {}
        for field, value in job.items():
            if field == "stages":
                flat["stages"] = json.dumps(value)
            elif field == "result":
                flat["result"] = json.dumps(value) if value is not None else ""
            elif value is None:
                flat[field] = ""
            else:
                flat[field] = str(value)
        pipe = self._r.pipeline()
        pipe.hset(key, mapping=flat)
        pipe.expire(key, self._ttl)
        # Index for listing: score = started_at as epoch float
        try:
            score = datetime.fromisoformat(job["started_at"]).timestamp()
        except Exception:
            score = time.time()
        pipe.zadd(_INDEX_KEY, {pid: score})
        pipe.expire(_INDEX_KEY, self._ttl)
        pipe.execute()

    def _load(self, pid: str) -> dict | None:
        raw = self._r.hgetall(self._key(pid))
        if not raw:
            return None
        job: dict = {}
        for field, value in raw.items():
            if field == "stages":
                job["stages"] = json.loads(value) if value else {}
            elif field == "result":
                job["result"] = json.loads(value) if value else None
            elif value == "":
                job[field] = None
            else:
                job[field] = value
        return job

    def new_job(self, stages: list[str] | None = None) -> dict:
        pid = str(uuid.uuid4())
        job = _blank_job(pid, stages)
        self._save(job)
        return job

    def get_job(self, pipeline_id: str) -> dict | None:
        return self._load(pipeline_id)

    def update_job(self, pipeline_id: str, **fields) -> None:
        job = self._load(pipeline_id)
        if job is None:
            logger.warning(f"[JobStore] update_job: unknown pipeline_id {pipeline_id}")
            return
        job.update(fields)
        self._save(job)

    def update_stage(self, pipeline_id: str, stage: str, **fields) -> None:
        job = self._load(pipeline_id)
        if job is None:
            logger.warning(f"[JobStore] update_stage: unknown pipeline_id {pipeline_id}")
            return
        if stage not in job.get("stages", {}):
            job.setdefault("stages", {})[stage] = {}
        job["stages"][stage].update(fields)
        self._save(job)

    def finish_job(
        self,
        pipeline_id: str,
        status: str,
        result: dict | None = None,
        error: str | None = None,
        t0: float | None = None,
    ) -> None:
        job = self._load(pipeline_id)
        if job is None:
            logger.warning(f"[JobStore] finish_job: unknown pipeline_id {pipeline_id}")
            return
        job["status"]          = status
        job["finished_at"]     = _now()
        job["elapsed_seconds"] = round(time.time() - t0, 3) if t0 else None
        job["result"]          = result
        job["error"]           = error
        self._save(job)

    def list_jobs(self, limit: int = 50, offset: int = 0) -> list[dict]:
        # Sorted set is scored by started_at epoch; newest first = ZREVRANGE
        pids = self._r.zrevrange(_INDEX_KEY, offset, offset + limit - 1)
        jobs = []
        for pid in pids:
            job = self._load(pid)
            if job:
                # Return a lightweight summary (no full result blob)
                jobs.append({k: v for k, v in job.items() if k != "result"})
        return jobs


# ═══════════════════════════════════════════════════════════════════════════════
# In-process fallback (single-pod / local dev)
# ═══════════════════════════════════════════════════════════════════════════════

class NullJobStore(JobStore):
    """
    In-process dict store — identical to the original ``_JOBS`` behaviour.
    Used automatically when Redis is not reachable.  NOT safe for multi-pod
    deployments — set ``REDIS_URL`` in production.
    """

    def __init__(self) -> None:
        self._jobs: Dict[str, dict] = {}
        self._lock = threading.Lock()
        logger.warning(
            "[JobStore] Redis unavailable — using in-process NullJobStore. "
            "Pipeline status will NOT survive pod restarts or be visible across replicas. "
            "Set REDIS_URL to enable shared state."
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
    Return a ``RedisJobStore`` if Redis is reachable, else ``NullJobStore``.

    The probe is a single PING with a 2-second timeout so startup is not
    blocked when Redis is optional (e.g. local development).
    """
    redis_url = os.environ.get("REDIS_URL", "").strip()
    if not redis_url:
        return NullJobStore()
    try:
        import redis
        r = redis.from_url(redis_url, socket_connect_timeout=2, decode_responses=True)
        r.ping()
        return RedisJobStore(redis_url)
    except Exception as exc:
        logger.warning(f"[JobStore] Redis probe failed ({exc}) — falling back to NullJobStore")
        return NullJobStore()
