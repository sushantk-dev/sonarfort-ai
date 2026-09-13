"""
SonarAI — Pipeline Worker  (GCS-only stateless edition)
========================================================
Runs IN-PROCESS as a background thread inside the API server (api.py)
— there is no separate Deployment/process for this worker. No Redis.

api.py starts `worker.run_loop(stop_event)` on a daemon thread during
FastAPI startup, and signals `stop_event` on shutdown so the loop exits
cleanly. This module exposes no CLI entrypoint of its own; `main()` /
`run_loop()` are called by api.py, not launched via `python worker.py`.

Job queue = GCS blobs under jobs/pending/. The worker polls that prefix,
picks the oldest job, and CLAIMS it atomically by deleting the blob with
an `if_generation_match` precondition — if two workers race (e.g. two
API pod replicas, each running this thread), exactly one delete succeeds
and only that worker runs the job.

Concurrency (Iteration 5 fix): claimed jobs run on a bounded thread pool
(MAX_CONCURRENT_RUNS, default 3) instead of one at a time on the polling
loop itself. Previously the loop was `while True: claim → _run_job()
(blocks until the WHOLE pipeline finishes) → repeat` — every job, no
matter how many were queued, ran strictly sequentially. Now the loop keeps
claiming and dispatching jobs onto free pool slots while others are still
in flight, so several runs genuinely execute at the same time.

Making that safe required removing every place a single job used to
mutate *process-wide* state "for the duration of the job" (safe only
when jobs never overlapped):
  - github_token / sonar_token / run_build used to be written onto the
    `settings` singleton and into os.environ, then restored in `finally`.
    Two overlapping jobs with different overrides would have raced on
    that shared object and could each see (or finish with) the other's
    credentials/build flag.
  - dry_run / parallel / rescan / no_rag used to set
    os.environ["SONAR_AI_DRY_RUN"] etc. directly and NEVER restored them
    — they leaked into every later job in this process, concurrent or not
    (e.g. one dry-run request could silently flip every subsequent real
    run into dry-run mode for the rest of the process's life).
  - The step/detail log interceptor used to monkeypatch the process-wide
    `loguru.logger.info` itself, closing over that one job's run_id and
    step buffers, and restore it when the job finished. Two concurrent
    jobs would stomp each other's patched `.info`, misattributing log
    lines to the wrong run or losing step detail entirely.
All of the above are now either passed as explicit arguments into
graph.run_pipeline() (which puts them in the per-invocation AgentState —
see state.py's Iteration 5 fields) or handled via loguru's
`logger.contextualize()`, which binds `run_id` through a contextvar and
is safe across concurrent threads. See _run_job below.

Cancellation (Iteration 5 fix): previously `_is_cancelled(run_id)` was
only checked at a few points *before* `run_pipeline()` was called — once
the LangGraph invoke started, a Stop click had no effect until the whole
(possibly multi-issue) pipeline finished on its own, AND the worker's
success/error handlers then unconditionally overwrote the run's status to
"done"/"error", silently erasing a "cancelled" status the cancel endpoint
had already written mid-run. Now: (1) a `cancel_check` callable is passed
into run_pipeline() and checked by every graph node (see graph.py's
_check_cancelled), so a Stop click actually interrupts a running pipeline
between steps; (2) the terminal status write checks _is_cancelled(run_id)
first and never overwrites an already-cancelled run.

Every step event + the final result is written directly into the shared
GCS run document (runs/{run_id}.json) so any API pod can serve
GET /api/pipeline/status/{run_id}.

Escalation .md files produced locally during a run are uploaded to
GCS (escalations/ prefix) so the API escalation endpoints can list them.

Same env vars as api.py:
    GCS_BUCKET  — GCS bucket name
    GCP_PROJECT — GCP project ID
    GITHUB_TOKEN, SONAR_TOKEN, VERTEX_MODEL, … (K8s Secret / ConfigMap defaults)

Per-run overrides (see PipelineRunRequest in api.py) — now threaded through
graph.run_pipeline() as explicit arguments instead of mutating process-wide
state:
    github_token, sonar_token — optional; override the process default for
        this run only (repo clone/push, PR creation, live Sonar calls). Left
        blank → falls back to GITHUB_TOKEN / SONAR_TOKEN above.
    run_build                 — Maven `mvn compile` + `mvn test` in the
        Validator step. Defaults to False/off; must be explicitly set true
        per run (see validator.py / settings.run_maven_build).

New env var:
    MAX_CONCURRENT_RUNS — how many pipeline jobs this worker thread may run
        at the same time. Default 3. Raise/lower based on available CPU,
        memory, and how much load the shared GCS bucket / Sonar / GitHub /
        Vertex AI can take from one pod.
"""

from __future__ import annotations

import concurrent.futures as _cf
import json
import os
import re
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from google.api_core import exceptions as _gexc
from google.cloud import storage as _gcs_lib
from loguru import logger

import config as _config  # noqa: F401 — import for its side effect: applies the
                           # global TLS-verification patch (see config.py) before
                           # any GCS/HTTP/git client below ever makes a real request.

# ── Client ────────────────────────────────────────────────────────────────────

_gcs = _gcs_lib.Client(project=os.environ.get("GCP_PROJECT"))

_GCS_RUNS_PFX = "runs/"
_GCS_JOBS_PFX = "jobs/pending/"
_GCS_CONFIG   = "state/config.json"

_POLL_INTERVAL_S = 3.0    # how often to poll jobs/pending/ when idle or full
_DETAIL_MIN_GAP_S = 1.2   # min seconds between "running" detail writes per run
                          # (GCS caps object writes at ~1/sec)

_MAX_CONCURRENT_RUNS = max(1, int(os.environ.get("MAX_CONCURRENT_RUNS", "3")))


def _bucket():
    return _gcs.bucket(os.environ["GCS_BUCKET"])


# ── GCS helpers ───────────────────────────────────────────────────────────────

def _gcs_download_bytes(blob_name: str) -> bytes:
    return _bucket().blob(blob_name).download_as_bytes()


def _gcs_upload(blob_name: str, data: bytes, content_type: str = "text/markdown") -> None:
    _bucket().blob(blob_name).upload_from_string(data, content_type=content_type)


def _gcs_read_json(blob_name: str, default=None):
    try:
        return json.loads(_gcs_download_bytes(blob_name).decode("utf-8"))
    except Exception:
        return default


def _gcs_write_json(blob_name: str, data) -> None:
    _gcs_upload(blob_name, json.dumps(data).encode("utf-8"), "application/json")


# ── Run helpers ───────────────────────────────────────────────────────────────

def _run_blob(run_id: str) -> str:
    return f"{_GCS_RUNS_PFX}{run_id}.json"


def _get_run(run_id: str) -> dict | None:
    return _gcs_read_json(_run_blob(run_id), default=None)


def _update_run(run_id: str, updates: dict) -> None:
    doc = _get_run(run_id) or {}
    doc.update(updates)
    _gcs_write_json(_run_blob(run_id), doc)


_last_detail_write: dict[str, float] = {}   # run_id → monotonic ts of last detail write
_last_detail_lock = threading.Lock()        # guards _last_detail_write across run threads


def _push_step(run_id: str, label: str, status: str, detail: str = "", ms: int = 0,
               throttle: bool = False) -> None:
    """
    Upsert a single pipeline step in the GCS run document.
    With throttle=True, high-frequency 'running' detail updates are rate-limited
    so we stay under GCS's ~1 write/sec/object cap. Status transitions
    (pending/done/error/cancelled) are never throttled.
    """
    if throttle:
        now = time.monotonic()
        with _last_detail_lock:
            last = _last_detail_write.get(run_id, 0.0)
            if now - last < _DETAIL_MIN_GAP_S:
                return
            _last_detail_write[run_id] = now

    doc   = _get_run(run_id) or {}
    steps = doc.get("steps", [])
    for s in steps:
        if s["label"] == label:
            s["status"] = status
            if detail: s["detail"] = detail
            if ms:     s["ms"]     = ms
            break
    else:
        steps.append({"label": label, "status": status, "detail": detail, "ms": ms})
    _update_run(run_id, {"steps": steps})


def _is_cancelled(run_id: str) -> bool:
    doc = _get_run(run_id)
    return bool(doc and doc.get("status") == "cancelled")


# ── Sync GCS config overrides into this process env ──────────────────────────
# Note: these are process-wide ADMIN settings (Settings page), not per-run
# job overrides — unlike the per-run fields below, it's correct for these to
# apply to every run in this process, so no change needed here for the
# concurrency fix.

_ENV_MAP = {
    "gcp_project":           "GCP_PROJECT",
    "vertex_model":          "VERTEX_MODEL",
    "sonar_host_url":        "SONAR_HOST_URL",
    "embedding_model":       "EMBEDDING_MODEL",
    "max_issues":            "MAX_ISSUES",
    "max_tokens":            "MAX_TOKENS",
    "rag_top_k":             "RAG_TOP_K",
    "max_critic_retries":    "MAX_CRITIC_RETRIES",
    "planner_temperature":   "PLANNER_TEMPERATURE",
    "generator_temperature": "GENERATOR_TEMPERATURE",
}


def _sync_config_from_gcs() -> None:
    overrides = _gcs_read_json(_GCS_CONFIG, default={}) or {}
    for cfg_key, env_key in _ENV_MAP.items():
        if cfg_key in overrides:
            os.environ[env_key] = str(overrides[cfg_key])


# ── Job queue (GCS-backed) ────────────────────────────────────────────────────

def _claim_next_job() -> dict | None:
    """
    List jobs/pending/, pick the oldest blob, and claim it by deleting with
    if_generation_match. Exactly one worker wins a race; losers get a 412
    precondition failure and simply try the next blob (or the next poll).
    Returns the parsed job payload, or None if no job could be claimed.
    """
    blobs = sorted(
        _bucket().list_blobs(prefix=_GCS_JOBS_PFX),
        key=lambda b: b.time_created or 0,
    )
    for blob in blobs:
        if not blob.name.endswith(".json"):
            continue
        try:
            payload = blob.download_as_bytes()
            blob.delete(if_generation_match=blob.generation)   # atomic claim
            return json.loads(payload)
        except (_gexc.PreconditionFailed, _gexc.NotFound):
            continue   # another worker claimed it first
        except Exception as exc:
            logger.warning(f"[Worker] Could not claim job {blob.name}: {exc}")
            continue
    return None


# ── Pipeline step labels ──────────────────────────────────────────────────────

_STEP_LABELS = ["Ingest", "Load Repo", "RAG Fetch", "Rule Fetch",
                "Planner", "Generator", "Critic", "Validate", "Deliver"]

_TAG_TO_LABEL = {
    "[Ingest]":    "Ingest",
    "[LoadRepo]":  "Load Repo",
    "[RAG]":       "RAG Fetch",
    "[RuleFetch]": "Rule Fetch",
    "[Planner]":   "Planner",
    "[Generator]": "Generator",
    "[Critic]":    "Critic",
    "[Validator]": "Validate",
    "[Deliver]":   "Deliver",
}


# ── Per-run step-detail tracking (thread-safe) ────────────────────────────────
#
# Replaces the old approach of monkeypatching the process-wide
# `loguru.logger.info` per job (see module docstring). A single sink is
# registered once, below, and reads the run_id that `logger.contextualize()`
# bound for the *calling thread* — contextvars are correctly isolated per
# thread/task, so concurrent jobs never see each other's run_id or step
# buffers even though they share this one sink function and this one dict.

_step_details: dict[str, dict[str, list[str]]] = {}   # run_id → label → lines
_step_details_lock = threading.Lock()


def _clean(msg: str, prefix: str) -> str:
    cleaned = re.sub(r"^\[" + re.escape(prefix.strip("[]")) + r"\]\s*", "", msg).strip()
    return cleaned or msg.strip()


def _push_detail(run_id: str, label: str, msg: str, tag: str) -> None:
    if _is_cancelled(run_id):
        return
    line = _clean(msg, tag)
    with _step_details_lock:
        details = _step_details.setdefault(run_id, {lbl: [] for lbl in _STEP_LABELS})
        lst = details.setdefault(label, [])
        if line and (not lst or lst[-1] != line):
            lst.append(line)
        joined = " · ".join(lst[-3:])
    _push_step(run_id, label, "running", joined, throttle=True)


def _log_sink(message) -> None:
    """
    Registered once at import time (below). Every logger.info(...) call made
    from ANYWHERE in the process passes through here; we only act on the
    ones made inside a `with logger.contextualize(run_id=...)` block (see
    _run_job) — everything else (e.g. startup logs, other threads not
    running a pipeline job) has no 'run_id' in extra and is ignored.
    """
    record = message.record
    run_id = record["extra"].get("run_id")
    if not run_id:
        return
    text = record["message"]
    for tag, label in _TAG_TO_LABEL.items():
        if tag in text:
            _push_detail(run_id, label, text, tag)
            return


logger.add(_log_sink, level="INFO", format="{message}")


# ── Job handler ───────────────────────────────────────────────────────────────

def _run_job(job: dict) -> None:
    run_id      = job["run_id"]
    req_dict    = job["req"]
    report_blob = job["report_blob"]

    logger.info(f"[Worker] Starting run {run_id}")

    # Run may have been cancelled while still queued
    if _is_cancelled(run_id):
        logger.info(f"[Worker] Run {run_id} was cancelled before start — skipping")
        return

    # Initialise all steps in one write (avoids 9 sequential GCS writes)
    doc   = _get_run(run_id) or {}
    steps = [{"label": lbl, "status": "pending", "detail": "", "ms": 0}
             for lbl in _STEP_LABELS]
    doc.update({"steps": steps, "status": "running"})
    _gcs_write_json(_run_blob(run_id), doc)

    def cancel_check() -> bool:
        return _is_cancelled(run_id)

    try:
        # Admin config (Settings page) sync — process-wide by design, see note above.
        _sync_config_from_gcs()

        if cancel_check():
            return

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            tf.write(_gcs_download_bytes(report_blob))
            local_report = tf.name

        # Resolve HEAD commit SHA. Always via `git ls-remote` now — the old
        # "check for an existing local clone first" shortcut assumed the
        # shared, repo-name-only clone directory from before the run_id
        # scoping fix (repo_loader.clone_repo), which no longer exists for a
        # brand-new run_id. ls-remote is a few hundred ms slower but always
        # correct and needs no local state.
        commit_sha = req_dict.get("commit_sha", "").strip()
        if not commit_sha or commit_sha.upper() in ("HEAD", "LATEST", ""):
            try:
                from config import settings as _cfg
                from repo_loader import _inject_token
                _auth_url = _inject_token(
                    req_dict["repo_url"], req_dict.get("github_token") or _cfg.github_token
                )
                result = subprocess.run(
                    ["git", "ls-remote", _auth_url, "HEAD"],
                    capture_output=True, text=True, timeout=30,
                )
                commit_sha = (result.stdout.split()[0]
                              if result.returncode == 0 and result.stdout else "HEAD")
                logger.info(f"[Worker] Resolved HEAD → {commit_sha[:12]}")
            except Exception as exc:
                logger.warning(f"[Worker] Could not resolve HEAD SHA: {exc} — using HEAD")
                commit_sha = "HEAD"

        if cancel_check():
            return

        with logger.contextualize(run_id=run_id):
            t0 = time.time()
            from graph import run_pipeline
            final_state = run_pipeline(
                sonar_report_path=local_report,
                repo_url=req_dict["repo_url"],
                commit_sha=commit_sha,
                max_issues=req_dict.get("max_issues", 0),
                severities=req_dict.get("severities", "BLOCKER,CRITICAL,MAJOR,MINOR,INFO"),
                run_id=run_id,
                dry_run=bool(req_dict.get("dry_run", False)),
                github_token=req_dict.get("github_token") or None,
                sonar_token=req_dict.get("sonar_token") or None,
                run_build=bool(req_dict.get("run_build", False)),
                parallel_issues=bool(req_dict.get("parallel", False)),
                enable_rag=not req_dict.get("no_rag", False),
                enable_sonar_rescan=bool(req_dict.get("rescan", False)),
                cancel_check=cancel_check,
            )
            elapsed_ms = int((time.time() - t0) * 1000)

        # ── Terminal status — never clobber a run that was cancelled while
        # run_pipeline() was executing. Previously this unconditionally wrote
        # "done" here, silently erasing a "cancelled" status the cancel
        # endpoint had already written mid-run, which is why Stop appeared
        # not to work: the click succeeded, the worker just overwrote it
        # once the (uninterruptible, at the time) pipeline eventually
        # finished on its own. cancel_check()/PipelineCancelled (see
        # graph.py) now also make that finish happen promptly instead of
        # only after the whole multi-issue run completes.
        if cancel_check():
            logger.info(f"[Worker] Run {run_id} finished after being cancelled — "
                        f"leaving status as 'cancelled'")
            return

        doc   = _get_run(run_id) or {}
        steps = doc.get("steps", [])
        for s in steps:
            if s["status"] in ("running", "pending"):
                s["status"] = "done"

        results: list[dict] = final_state.get("pipeline_results", [])

        # ── Run-level token totals (summed across all LLM calls, incl. retries)
        usage_log: list[dict] = final_state.get("token_usage_log", [])
        token_usage = {
            "input_tokens":  sum(r.get("input_tokens", 0)  for r in usage_log),
            "output_tokens": sum(r.get("output_tokens", 0) for r in usage_log),
        }

        _update_run(run_id, {
            "status":      "done",
            "results":     results,
            "elapsed_ms":  elapsed_ms,
            "steps":       steps,
            "token_usage": token_usage,
        })
        logger.info(
            f"[Worker] Run {run_id} done in {elapsed_ms}ms — {len(results)} result(s), "
            f"tokens in={token_usage['input_tokens']} out={token_usage['output_tokens']}"
        )

        # Upload local escalation files → GCS
        try:
            from config import settings as _cfg
            esc_dir = Path(_cfg.escalation_dir)
            if esc_dir.exists():
                for md_file in esc_dir.glob("*.md"):
                    _gcs_upload(f"escalations/{md_file.name}", md_file.read_bytes(), "text/markdown")
                    logger.info(f"[Worker] Uploaded escalation {md_file.name} → GCS")
        except Exception as exc:
            logger.warning(f"[Worker] Escalation upload failed: {exc}")

    except Exception as exc:  # noqa: BLE001
        logger.exception(f"[Worker] Run {run_id} failed: {exc}")
        # Same clobber guard as the success path above.
        if cancel_check():
            logger.info(f"[Worker] Run {run_id} errored after being cancelled — "
                        f"leaving status as 'cancelled'")
            return
        doc   = _get_run(run_id) or {}
        steps = doc.get("steps", [])
        for s in steps:
            if s["status"] in ("running", "pending"):
                s["status"] = "error"
                s["detail"] = str(exc)
        _update_run(run_id, {"status": "error", "error": str(exc), "steps": steps})
    finally:
        with _last_detail_lock:
            _last_detail_write.pop(run_id, None)
        with _step_details_lock:
            _step_details.pop(run_id, None)


# ── Main loop ─────────────────────────────────────────────────────────────────
#
# There is intentionally no `if __name__ == "__main__":` entrypoint here.
# The worker only ever runs as a background thread started by api.py's
# FastAPI startup event — it must never be launched as its own process.

def run_loop(stop_event: threading.Event) -> None:
    """
    Poll jobs/pending/ until `stop_event` is set. Called by api.py on a
    daemon thread; api.py sets `stop_event` during FastAPI shutdown so this
    loop exits gracefully instead of being killed mid-job.

    Dispatches claimed jobs onto a bounded thread pool (see
    _MAX_CONCURRENT_RUNS) instead of running them inline, so several jobs
    can be in flight at once — this loop's only responsibility is claiming
    work and keeping the pool fed; it never blocks on a job finishing.
    """
    logger.info(f"[Worker] Polling gs://{os.environ.get('GCS_BUCKET', '(not set)')}/"
                f"{_GCS_JOBS_PFX} every {_POLL_INTERVAL_S}s "
                f"(in-process thread, max_concurrent_runs={_MAX_CONCURRENT_RUNS})")

    executor = _cf.ThreadPoolExecutor(
        max_workers=_MAX_CONCURRENT_RUNS, thread_name_prefix="pipeline-run"
    )
    in_flight: dict[_cf.Future, str] = {}

    try:
        while not stop_event.is_set():
            try:
                # Reap finished futures first so the slot count is accurate.
                for fut in [f for f in in_flight if f.done()]:
                    finished_run_id = in_flight.pop(fut)
                    exc = fut.exception()
                    if exc:
                        # _run_job already catches and records pipeline-level
                        # errors in the GCS run doc — a future exception here
                        # means something escaped that, e.g. a bug in the
                        # worker glue itself. Log it; don't crash the loop.
                        logger.error(
                            f"[Worker] Run {finished_run_id} thread raised "
                            f"unexpectedly: {exc}"
                        )

                if len(in_flight) >= _MAX_CONCURRENT_RUNS:
                    stop_event.wait(_POLL_INTERVAL_S)
                    continue

                job = _claim_next_job()
                if job is None:
                    stop_event.wait(_POLL_INTERVAL_S)
                    continue

                run_id = job.get("run_id", "?")
                logger.info(
                    f"[Worker] Claimed job run_id={run_id} — dispatching "
                    f"({len(in_flight) + 1}/{_MAX_CONCURRENT_RUNS} concurrent slots in use)"
                )
                future = executor.submit(_run_job, job)
                in_flight[future] = run_id
                # Loop again immediately (no wait) — there may be room for
                # another job right away instead of idling for a full
                # _POLL_INTERVAL_S between dispatches.
            except Exception as exc:
                logger.error(f"[Worker] Error in main loop: {exc} — retrying in 2 s")
                stop_event.wait(2)
    finally:
        # Let in-flight jobs keep running rather than killing threads
        # mid-write; api.py's shutdown handler only waits up to 10s on this
        # loop's own thread anyway, and these pool threads are not daemon
        # threads of their own, so shutdown(wait=False) just stops accepting
        # new work — it doesn't abandon a job that's mid-GCS-write.
        executor.shutdown(wait=False)

    logger.info("[Worker] Stop signal received — worker thread exiting")


def main() -> None:
    """
    Kept only as a thin alias for internal/manual invocation (e.g. a shell
    inside the API pod for debugging). Normal operation never calls this
    directly — api.py calls run_loop() on a background thread instead.
    """
    run_loop(threading.Event())