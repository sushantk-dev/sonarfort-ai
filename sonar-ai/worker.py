"""
SonarAI — Pipeline Worker  (GCS + Memorystore Redis stateless edition)
=======================================================================
Runs as a separate Kubernetes Deployment.
Blocks on BRPOP sonar:jobs, downloads the sonar report from GCS,
executes the pipeline, and writes every step event + the final result
directly into the shared Redis run document so any API pod can serve
GET /api/pipeline/status/{run_id}.

Escalation .md files produced locally during a run are uploaded to
GCS (escalations/ prefix) so the API escalation endpoints can list them.

Run:
    python worker.py

Same env vars as api.py:
    REDIS_URL   — redis://<Memorystore-IP>:6379
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

import redis as _redis_lib
from google.cloud import storage as _gcs_lib
from loguru import logger

# ── Clients ───────────────────────────────────────────────────────────────────

_r   = _redis_lib.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379"),
                            decode_responses=True)
_gcs = _gcs_lib.Client(project=os.environ.get("GCP_PROJECT"))

_KEY_JOBS   = "sonar:jobs"
_KEY_CONFIG = "sonar:config"
_RUN_TTL    = 60 * 60 * 24 * 7


# ── Redis helpers ─────────────────────────────────────────────────────────────

def _run_key(run_id: str) -> str:
    return f"run:{run_id}"


def _get_run(run_id: str) -> dict | None:
    raw = _r.hget(_run_key(run_id), "data")
    return json.loads(raw) if raw else None


def _update_run(run_id: str, updates: dict) -> None:
    raw = _r.hget(_run_key(run_id), "data")
    doc = json.loads(raw) if raw else {}
    doc.update(updates)
    _r.hset(_run_key(run_id), "data", json.dumps(doc))
    _r.expire(_run_key(run_id), _RUN_TTL)


def _push_step(run_id: str, label: str, status: str, detail: str = "", ms: int = 0) -> None:
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


# ── GCS helpers ───────────────────────────────────────────────────────────────

def _gcs_download_bytes(blob_name: str) -> bytes:
    return _gcs.bucket(os.environ["GCS_BUCKET"]).blob(blob_name).download_as_bytes()


def _gcs_upload(blob_name: str, data: bytes, content_type: str = "text/markdown") -> None:
    _gcs.bucket(os.environ["GCS_BUCKET"]).blob(blob_name).upload_from_string(
        data, content_type=content_type
    )


# ── Sync Redis config overrides into this process env ────────────────────────

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


def _sync_config_from_redis() -> None:
    overrides = _r.hgetall(_KEY_CONFIG)
    for cfg_key, env_key in _ENV_MAP.items():
        if cfg_key in overrides:
            os.environ[env_key] = overrides[cfg_key]


# ── Pipeline step labels ──────────────────────────────────────────────────────

_STEP_LABELS = ["Ingest", "Load Repo", "RAG Fetch", "Rule Fetch",
                "Planner", "Generator", "Critic", "Validate", "Deliver"]


# ── Job handler ───────────────────────────────────────────────────────────────

def _run_job(job: dict) -> None:
    run_id      = job["run_id"]
    req_dict    = job["req"]
    report_blob = job["report_blob"]

    logger.info(f"[Worker] Starting run {run_id}")

    for label in _STEP_LABELS:
        _push_step(run_id, label, "pending")
    _update_run(run_id, {"status": "running"})

    try:
        _sync_config_from_redis()

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
            _push_step(run_id, label, "running", " · ".join(_step_details[label][-3:]))

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


# ── Main loop ─────────────────────────────────────────────────────────────────

def main() -> None:
    logger.info(f"[Worker] Listening on {os.environ.get('REDIS_URL', 'redis://localhost:6379')} "
                f"key={_KEY_JOBS}")
    while True:
        try:
            result = _r.brpop(_KEY_JOBS, timeout=5)
            if result is None:
                continue
            _, raw_job = result
            job = json.loads(raw_job)
            logger.info(f"[Worker] Dequeued job run_id={job.get('run_id')}")
            _run_job(job)
        except Exception as exc:
            logger.error(f"[Worker] Error in main loop: {exc} — retrying in 2 s")
            time.sleep(2)


if __name__ == "__main__":
    main()
