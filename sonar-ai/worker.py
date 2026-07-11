"""
SonarAI — Pipeline Worker  (GCS-only stateless edition)
========================================================
Runs as a separate Kubernetes Deployment. No Redis.

Job queue = GCS blobs under jobs/pending/. The worker polls that prefix,
picks the oldest job, and CLAIMS it atomically by deleting the blob with
an `if_generation_match` precondition — if two workers race, exactly one
delete succeeds and only that worker runs the job.

Every step event + the final result is written directly into the shared
GCS run document (runs/{run_id}.json) so any API pod can serve
GET /api/pipeline/status/{run_id}.

Escalation .md files produced locally during a run are uploaded to
GCS (escalations/ prefix) so the API escalation endpoints can list them.

Run:
    python worker.py

Same env vars as api.py:
    GCS_BUCKET  — GCS bucket name
    GCP_PROJECT — GCP project ID
    GITHUB_TOKEN, SONAR_TOKEN, VERTEX_MODEL, … (K8s Secret / ConfigMap)
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path

from google.api_core import exceptions as _gexc
from google.cloud import storage as _gcs_lib
from loguru import logger

# ── Client ────────────────────────────────────────────────────────────────────

_gcs = _gcs_lib.Client(project=os.environ.get("GCP_PROJECT"))

_GCS_RUNS_PFX = "runs/"
_GCS_JOBS_PFX = "jobs/pending/"
_GCS_CONFIG   = "state/config.json"

_POLL_INTERVAL_S = 3.0    # how often to poll jobs/pending/ when idle
_DETAIL_MIN_GAP_S = 1.2   # min seconds between "running" detail writes per run
                          # (GCS caps object writes at ~1/sec)


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


def _push_step(run_id: str, label: str, status: str, detail: str = "", ms: int = 0,
               throttle: bool = False) -> None:
    """
    Upsert a single pipeline step in the GCS run document.
    With throttle=True, high-frequency 'running' detail updates are rate-limited
    so we stay under GCS's ~1 write/sec/object cap. Status transitions
    (pending/done/error/cancelled) are never throttled.
    """
    if throttle:
        now  = time.monotonic()
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

    try:
        _sync_config_from_gcs()

        if req_dict.get("dry_run"):   os.environ["SONAR_AI_DRY_RUN"]   = "1"
        if req_dict.get("parallel"):  os.environ["PARALLEL_ISSUES"]     = "true"
        if req_dict.get("rescan"):    os.environ["ENABLE_SONAR_RESCAN"] = "true"
        if req_dict.get("no_rag"):    os.environ["ENABLE_RAG"]          = "false"

        if _is_cancelled(run_id):
            return

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            tf.write(_gcs_download_bytes(report_blob))
            local_report = tf.name

        from loguru import logger as _log
        _orig_info = _log.info
        _step_details: dict[str, list[str]] = {lbl: [] for lbl in _STEP_LABELS}

        def _clean(msg: str, prefix: str) -> str:
            cleaned = re.sub(r"^\[" + re.escape(prefix.strip("[]")) + r"\]\s*", "", msg).strip()
            return cleaned or msg.strip()

        def _push_detail(label: str, msg: str, tag: str) -> None:
            if _is_cancelled(run_id):
                return
            line = _clean(msg, tag)
            if line and (not _step_details[label] or _step_details[label][-1] != line):
                _step_details[label].append(line)
            # throttled: GCS allows ~1 write/sec per object
            _push_step(run_id, label, "running",
                       " · ".join(_step_details[label][-3:]), throttle=True)

        def _intercepting_info(msg: str, *a, **kw):  # type: ignore[misc]
            _orig_info(msg, *a, **kw)
            m = str(msg)
            if   "[Ingest]"    in m: _push_detail("Ingest",     m, "[Ingest]")
            elif "[LoadRepo]"  in m: _push_detail("Load Repo",  m, "[LoadRepo]")
            elif "[RAG]"       in m: _push_detail("RAG Fetch",  m, "[RAG]")
            elif "[RuleFetch]" in m: _push_detail("Rule Fetch", m, "[RuleFetch]")
            elif "[Planner]"   in m: _push_detail("Planner",    m, "[Planner]")
            elif "[Generator]" in m: _push_detail("Generator",  m, "[Generator]")
            elif "[Critic]"    in m: _push_detail("Critic",     m, "[Critic]")
            elif "[Validator]" in m: _push_detail("Validate",   m, "[Validator]")
            elif "[Deliver]"   in m: _push_detail("Deliver",    m, "[Deliver]")

        _log.info = _intercepting_info  # type: ignore[method-assign]

        # Resolve HEAD commit SHA
        commit_sha = req_dict.get("commit_sha", "").strip()
        if not commit_sha or commit_sha.upper() in ("HEAD", "LATEST", ""):
            try:
                from config import settings as _cfg
                from repo_loader import _inject_token, _repo_name_from_url
                _auth_url   = _inject_token(req_dict["repo_url"], _cfg.github_token)
                _repo_name  = _repo_name_from_url(req_dict["repo_url"])
                _local_path = Path(_cfg.clone_dir) / _repo_name
                if _local_path.exists():
                    import git as _git
                    commit_sha = _git.Repo(_local_path).head.commit.hexsha
                else:
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

        if _is_cancelled(run_id):
            return

        t0 = time.time()
        from graph import run_pipeline
        final_state = run_pipeline(
            sonar_report_path=local_report,
            repo_url=req_dict["repo_url"],
            commit_sha=commit_sha,
            max_issues=req_dict.get("max_issues", 0),
            severities=req_dict.get("severities", "BLOCKER,CRITICAL,MAJOR,MINOR,INFO"),
        )
        elapsed_ms = int((time.time() - t0) * 1000)
        _log.info = _orig_info

        doc   = _get_run(run_id) or {}
        steps = doc.get("steps", [])
        for s in steps:
            if s["status"] in ("running", "pending"):
                s["status"] = "done"

        results: list[dict] = final_state.get("pipeline_results", [])
        _update_run(run_id, {
            "status":     "done",
            "results":    results,
            "elapsed_ms": elapsed_ms,
            "steps":      steps,
        })
        logger.info(f"[Worker] Run {run_id} done in {elapsed_ms}ms — {len(results)} result(s)")

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
        doc   = _get_run(run_id) or {}
        steps = doc.get("steps", [])
        for s in steps:
            if s["status"] in ("running", "pending"):
                s["status"] = "error"
                s["detail"] = str(exc)
        _update_run(run_id, {"status": "error", "error": str(exc), "steps": steps})
    finally:
        _last_detail_write.pop(run_id, None)


# ── Main loop ─────────────────────────────────────────────────────────────────

def main() -> None:
    logger.info(f"[Worker] Polling gs://{os.environ.get('GCS_BUCKET', '(not set)')}/"
                f"{_GCS_JOBS_PFX} every {_POLL_INTERVAL_S}s")
    while True:
        try:
            job = _claim_next_job()
            if job is None:
                time.sleep(_POLL_INTERVAL_S)
                continue
            logger.info(f"[Worker] Claimed job run_id={job.get('run_id')}")
            _run_job(job)
        except Exception as exc:
            logger.error(f"[Worker] Error in main loop: {exc} — retrying in 2 s")
            time.sleep(2)


if __name__ == "__main__":
    main()