"""
FortifyAI — LLM Token Usage Tracker
------------------------------------
Central, thread-safe accumulator for LLM token consumption across all
pipeline stages that call Vertex AI (AI Reasoning, AI Code Fix, and the
LLM-generated Next Steps in Fortify Writeback).

Design
------
* Each pipeline run registers itself with ``start_run(pipeline_id)`` from
  the worker thread that executes the pipeline. Because the whole pipeline
  runs inside a single ThreadPoolExecutor task (see api_server.py), a
  ``threading.local`` is enough to associate LLM calls with their run —
  no need to thread pipeline_id through every agent signature.
* Call sites simply do ``token_tracker.record(stage, response)`` right
  after ``llm.invoke(...)``. Usage is extracted from the LangChain
  AIMessage (``usage_metadata`` first, Vertex ``response_metadata``
  as fallback).
* Calls made outside any run (CLI usage, fortifyai.py direct runs) are
  accumulated under the ``_global`` bucket so nothing is lost.
* ``summary(pipeline_id)`` can be polled live; ``end_run(pipeline_id)``
  returns the final summary for persisting into the job store result.

Usage
-----
    from token_tracker import token_tracker

    # in the pipeline runner (worker thread):
    token_tracker.start_run(pipeline_id)
    ...
    result["token_usage"] = token_tracker.end_run(pipeline_id)

    # at every LLM call site:
    response = llm.invoke(messages)
    token_tracker.record("ai-reasoning", response, model=getattr(llm, "model_name", None))
"""

from __future__ import annotations

import threading
import time
from typing import Any, Optional

from loguru import logger

_GLOBAL_KEY = "_global"


def _extract_usage(response: Any) -> dict[str, int]:
    """
    Pull token counts out of a LangChain AIMessage in a provider-tolerant way.

    Priority:
      1. response.usage_metadata            (LangChain standard:
         {"input_tokens", "output_tokens", "total_tokens"})
      2. response.response_metadata["usage_metadata"]  (raw Vertex/Gemini:
         {"prompt_token_count", "candidates_token_count", "total_token_count"})

    Returns zeros if nothing is available (e.g. heuristic fallback paths
    never call this, but a provider might omit usage on errors).
    """
    # 1) LangChain-standard usage_metadata
    um = getattr(response, "usage_metadata", None)
    if isinstance(um, dict) and um:
        inp = int(um.get("input_tokens", 0) or 0)
        out = int(um.get("output_tokens", 0) or 0)
        tot = int(um.get("total_tokens", inp + out) or (inp + out))
        return {"input_tokens": inp, "output_tokens": out, "total_tokens": tot}

    # 2) Raw Vertex metadata
    rm = getattr(response, "response_metadata", None)
    if isinstance(rm, dict):
        vm = rm.get("usage_metadata") or {}
        if vm:
            inp = int(vm.get("prompt_token_count", 0) or 0)
            out = int(vm.get("candidates_token_count", 0) or 0)
            tot = int(vm.get("total_token_count", inp + out) or (inp + out))
            return {"input_tokens": inp, "output_tokens": out, "total_tokens": tot}

    return {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}


def _empty_bucket() -> dict:
    return {
        "calls": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "models": {},          # model_name -> total_tokens
        "started_at": time.time(),
    }


class TokenTracker:
    """Thread-safe per-run + global token accumulator."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._runs: dict[str, dict] = {_GLOBAL_KEY: _empty_bucket()}
        # stages nested per run: run -> {"stages": {stage: {...}}}
        self._runs[_GLOBAL_KEY]["stages"] = {}
        self._local = threading.local()

    # ── Run lifecycle ────────────────────────────────────────────────────────

    def start_run(self, pipeline_id: str) -> None:
        """Register a run and bind it to the current thread."""
        with self._lock:
            if pipeline_id not in self._runs:
                bucket = _empty_bucket()
                bucket["stages"] = {}
                self._runs[pipeline_id] = bucket
        self._local.pipeline_id = pipeline_id

    def end_run(self, pipeline_id: str) -> dict:
        """
        Unbind the run from the current thread and return its final summary.
        The run's data is kept in memory so /tokens endpoints can still
        report it after completion (until process restart).
        """
        if getattr(self._local, "pipeline_id", None) == pipeline_id:
            self._local.pipeline_id = None
        return self.summary(pipeline_id)

    # ── Recording ────────────────────────────────────────────────────────────

    def record(
        self,
        stage: str,
        response: Any,
        model: Optional[str] = None,
        pipeline_id: Optional[str] = None,
    ) -> dict[str, int]:
        """
        Record one LLM call's usage under *stage*.

        pipeline_id resolution order:
          explicit arg → thread-bound run (start_run) → global bucket.

        Returns the extracted usage dict so callers can log it.
        """
        usage = _extract_usage(response)
        pid = pipeline_id or getattr(self._local, "pipeline_id", None) or _GLOBAL_KEY
        model = model or "unknown"

        with self._lock:
            for key in {pid, _GLOBAL_KEY}:          # always mirror into global
                bucket = self._runs.setdefault(key, {**_empty_bucket(), "stages": {}})
                self._accumulate(bucket, usage, model)
                stage_bucket = bucket["stages"].setdefault(stage, _empty_bucket())
                self._accumulate(stage_bucket, usage, model)

        logger.debug(
            f"[Tokens] {stage}: in={usage['input_tokens']} "
            f"out={usage['output_tokens']} total={usage['total_tokens']} "
            f"(run={pid}, model={model})"
        )
        return usage

    @staticmethod
    def _accumulate(bucket: dict, usage: dict[str, int], model: str) -> None:
        bucket["calls"] += 1
        bucket["input_tokens"] += usage["input_tokens"]
        bucket["output_tokens"] += usage["output_tokens"]
        bucket["total_tokens"] += usage["total_tokens"]
        bucket["models"][model] = bucket["models"].get(model, 0) + usage["total_tokens"]

    # ── Reporting ────────────────────────────────────────────────────────────

    def summary(self, pipeline_id: Optional[str] = None) -> dict:
        """
        Return a JSON-serialisable summary for one run (or the global bucket
        when pipeline_id is None). Unknown pipeline_ids return zeros rather
        than raising, so status endpoints stay robust.
        """
        key = pipeline_id or _GLOBAL_KEY
        with self._lock:
            bucket = self._runs.get(key)
            if bucket is None:
                return {
                    "pipeline_id": pipeline_id,
                    "calls": 0,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": 0,
                    "models": {},
                    "stages": {},
                }
            return {
                "pipeline_id": pipeline_id,
                "calls": bucket["calls"],
                "input_tokens": bucket["input_tokens"],
                "output_tokens": bucket["output_tokens"],
                "total_tokens": bucket["total_tokens"],
                "models": dict(bucket["models"]),
                "stages": {
                    name: {
                        "calls": s["calls"],
                        "input_tokens": s["input_tokens"],
                        "output_tokens": s["output_tokens"],
                        "total_tokens": s["total_tokens"],
                    }
                    for name, s in bucket.get("stages", {}).items()
                },
            }

    def all_runs(self) -> dict:
        """Global totals plus per-run totals (for a /tokens/usage endpoint)."""
        with self._lock:
            runs = {
                pid: {
                    "calls": b["calls"],
                    "total_tokens": b["total_tokens"],
                    "input_tokens": b["input_tokens"],
                    "output_tokens": b["output_tokens"],
                }
                for pid, b in self._runs.items()
                if pid != _GLOBAL_KEY
            }
        return {"global": self.summary(None), "runs": runs}


# Module-level singleton — import this everywhere.
token_tracker = TokenTracker()
