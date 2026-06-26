"""
SonarAI — FastAPI Bridge Server  (GCS + Memorystore Redis — Stateless)
=======================================================================
All mutable state is moved out of the process so any number of Kubernetes
pod replicas can serve any request without sticky sessions.

  Was stateful                →  Replaced by
  ────────────────────────────────────────────────────────────────────
  _runs / _processes dicts    →  Redis Hash  key: run:{run_id}
  multiprocessing.Process     →  Redis List  key: sonar:jobs  (LPUSH)
  multiprocessing.Queue       →    worker.py does BRPOP + writes Redis
  _last_report_issues list    →  Redis String key: sonar:issues (JSON)
  local uploads/*.json        →  GCS bucket  blob: reports/sonar-ai-last-report.json
  local escalations/*.md      →  GCS bucket  prefix: escalations/
  os.environ config mutation  →  Redis Hash  key: sonar:config

Required env vars (K8s ConfigMap / Secret):
  REDIS_URL   — redis://<memorystore-ip>:6379
  GCS_BUCKET  — GCS bucket name
  GCP_PROJECT — GCP project ID

Run API:
    uvicorn api:app --host 0.0.0.0 --port 8080
Run Worker (separate Deployment):
    python worker.py

Endpoints (unchanged from v2):
    POST /api/pipeline/run          — enqueue a pipeline run
    POST /api/pipeline/cancel/{id}  — mark run cancelled in Redis
    GET  /api/pipeline/status/{id}  — poll run status (reads Redis)
    GET  /api/issues                — list issues (reads Redis)
    DELETE /api/issues/{key}        — remove one issue (Redis + GCS)
    POST /api/report/upload         — upload sonar-report.json → GCS + Redis
    POST /api/sonar/fetch           — live-fetch issues from SonarQube API
    GET  /api/sonar/report          — structured summary of loaded issues
    GET  /api/config                — read current settings
    POST /api/config                — persist settings to Redis (all pods updated)
"""

from __future__ import annotations

import json
import os
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Optional

import redis as _redis_lib
from google.cloud import storage as _gcs_lib
from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger
from pydantic import BaseModel

app = FastAPI(title="SonarAI API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:4200", "http://localhost:4201"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── GCS + Redis singletons ────────────────────────────────────────────────────

_redis_client: _redis_lib.Redis | None = None
_gcs_client:   _gcs_lib.Client | None = None


def _redis() -> _redis_lib.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = _redis_lib.from_url(
            os.environ.get("REDIS_URL", "redis://localhost:6379"),
            decode_responses=True,
        )
    return _redis_client


def _gcs() -> _gcs_lib.Client:
    global _gcs_client
    if _gcs_client is None:
        _gcs_client = _gcs_lib.Client(project=os.environ.get("GCP_PROJECT"))
    return _gcs_client


def _bucket() -> str:
    return os.environ["GCS_BUCKET"]


# ── Redis key schema ──────────────────────────────────────────────────────────
# run:{run_id}   HASH  "data" field → JSON run document
# sonar:jobs     LIST  job payloads (LPUSH enqueue / worker BRPOP)
# sonar:issues   STRING  JSON list of current issues
# sonar:config   HASH  config override key/value pairs (non-token fields)
# sonar:run_ids  LIST  run IDs newest-first (capped at 200)

_KEY_JOBS    = "sonar:jobs"
_KEY_ISSUES  = "sonar:issues"
_KEY_CONFIG  = "sonar:config"
_KEY_RUN_IDS = "sonar:run_ids"
_RUN_TTL     = 60 * 60 * 24 * 7   # 7 days

# ── GCS blob paths ────────────────────────────────────────────────────────────
_GCS_REPORT    = "reports/sonar-ai-last-report.json"
_GCS_ESC_PFX   = "escalations/"


def _run_key(run_id: str) -> str:
    return f"run:{run_id}"


# ── Redis run helpers ─────────────────────────────────────────────────────────

def _get_run(run_id: str) -> dict | None:
    raw = _redis().hget(_run_key(run_id), "data")
    return json.loads(raw) if raw else None


def _set_run(run_id: str, data: dict) -> None:
    r = _redis()
    r.hset(_run_key(run_id), "data", json.dumps(data))
    r.expire(_run_key(run_id), _RUN_TTL)


def _update_run(run_id: str, updates: dict) -> None:
    """Merge updates into the existing Redis run document."""
    r   = _redis()
    raw = r.hget(_run_key(run_id), "data")
    doc = json.loads(raw) if raw else {}
    doc.update(updates)
    r.hset(_run_key(run_id), "data", json.dumps(doc))
    r.expire(_run_key(run_id), _RUN_TTL)


# ── Issues helpers ────────────────────────────────────────────────────────────

def _get_issues() -> list[dict]:
    raw = _redis().get(_KEY_ISSUES)
    return json.loads(raw) if raw else []


def _set_issues(issues: list[dict]) -> None:
    _redis().set(_KEY_ISSUES, json.dumps(issues))


# ── Config helpers ────────────────────────────────────────────────────────────

def _redis_cfg_get(key: str) -> str:
    """Read a single non-token config value from the Redis sonar:config hash."""
    try:
        return _redis().hget(_KEY_CONFIG, key) or ""
    except Exception:
        return ""


# ── GCS helpers ───────────────────────────────────────────────────────────────

def _gcs_upload(blob: str, data: bytes, ct: str = "application/octet-stream") -> None:
    _gcs().bucket(_bucket()).blob(blob).upload_from_string(data, content_type=ct)


def _gcs_download_bytes(blob: str) -> bytes:
    return _gcs().bucket(_bucket()).blob(blob).download_as_bytes()


def _gcs_download_text(blob: str) -> str:
    return _gcs_download_bytes(blob).decode("utf-8")


def _gcs_exists(blob: str) -> bool:
    return _gcs().bucket(_bucket()).blob(blob).exists()


def _gcs_delete(blob: str) -> None:
    _gcs().bucket(_bucket()).blob(blob).delete()


def _gcs_list(prefix: str) -> list[str]:
    return [b.name for b in _gcs().bucket(_bucket()).list_blobs(prefix=prefix)]


# ── Pydantic models ───────────────────────────────────────────────────────────

class PipelineRunRequest(BaseModel):
    repo_url:   str
    commit_sha: str
    max_issues: int  = 0
    parallel:   bool = False
    rescan:     bool = False
    no_rag:     bool = False
    dry_run:    bool = False
    severities: str  = "BLOCKER,CRITICAL,MAJOR,MINOR,INFO"   # ← NEW


class ConfigUpdateRequest(BaseModel):
    gcp_project:                 Optional[str]   = None
    vertex_model:                Optional[str]   = None
    max_issues:                  Optional[int]   = None
    max_tokens:                  Optional[int]   = None
    confidence_high_threshold:   Optional[float] = None
    confidence_medium_threshold: Optional[float] = None
    github_token:                Optional[str]   = None   # empty string = clear token
    sonar_token:                 Optional[str]   = None   # empty string = clear token
    sonar_host_url:              Optional[str]   = None
    sonar_org:                   Optional[str]   = None
    planner_temp:                Optional[float] = None
    generator_temp:              Optional[float] = None
    max_critic_retries:          Optional[int]   = None
    chroma_persist_dir:          Optional[str]   = None
    embedding_model:             Optional[str]   = None
    rag_top_k:                   Optional[int]   = None
    langsmith_api_key:           Optional[str]   = None
    langsmith_project:           Optional[str]   = None
    langchain_tracing:           Optional[bool]  = None


class SonarFetchRequest(BaseModel):
    component_keys: str
    severities:     str  = "BLOCKER,CRITICAL,MAJOR,MINOR,INFO"
    resolved:       bool = False
    ps:             int  = 500


# ── Pipeline step helper (called by worker.py via Redis) ─────────────────────
# The API no longer spawns child processes. It enqueues a JSON job onto
# sonar:jobs. A separate worker pod (worker.py) BRPOPs that list, runs the
# pipeline, and calls _push_step to update the shared Redis run document so
# any API pod can serve GET /api/pipeline/status/{run_id}.

def _push_step(run_id: str, label: str, status: str, detail: str = "", ms: int = 0) -> None:
    """Upsert a single pipeline step in the Redis run document."""
    try:
        doc   = _get_run(run_id) or {}
        steps: list[dict] = doc.get("steps", [])
        for s in steps:
            if s["label"] == label:
                s["status"] = status
                if detail: s["detail"] = detail
                if ms:     s["ms"]     = ms
                break
        else:
            steps.append({"label": label, "status": status, "detail": detail, "ms": ms})
        _update_run(run_id, {"steps": steps})
    except Exception as exc:
        logger.warning(f"[API] _push_step failed for run {run_id}: {exc}")


# ── SonarQube issue normaliser ────────────────────────────────────────────────

def _normalize_sonar_issue(raw: dict) -> dict:
    """Map a raw SonarQube API issue object to the internal schema."""
    text_range = raw.get("textRange", {})
    return {
        "key":       raw.get("key", ""),
        "rule_key":  raw.get("rule", ""),
        "severity":  raw.get("severity", "INFO"),
        "component": raw.get("component", ""),
        "project":   raw.get("project", ""),
        "line":      raw.get("line") or text_range.get("startLine", 0),
        "message":   raw.get("message", ""),
        "effort":    raw.get("effort", ""),
        "status":    raw.get("status", "OPEN"),
        "hash":      raw.get("hash", ""),
        "text_range": {
            "start_line":   text_range.get("startLine", 0),
            "end_line":     text_range.get("endLine", 0),
            "start_offset": text_range.get("startOffset", 0),
            "end_offset":   text_range.get("endOffset", 0),
        },
        "tags":  raw.get("tags", []),
        "type":  raw.get("type", ""),
        "debt":  raw.get("debt", ""),
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health() -> dict:
    try:
        _redis().ping()
        redis_ok = True
    except Exception:
        redis_ok = False
    return {"status": "ok", "version": "2.0.0", "redis": redis_ok}


# ── Report upload ─────────────────────────────────────────────────────────────

@app.post("/api/report/upload")
async def upload_report(file: UploadFile = File(...)) -> dict:
    if not file.filename or not file.filename.endswith(".json"):
        raise HTTPException(400, "Only .json files are accepted")

    content = await file.read()
    try:
        json.loads(content)  # validate JSON
    except json.JSONDecodeError as exc:
        raise HTTPException(400, f"Invalid JSON: {exc}") from exc

    # ── GCS: durable store shared across all pods ─────────────────────────
    _gcs_upload(_GCS_REPORT, content, "application/json")

    # ── Parse issues and cache in Redis for fast reads ────────────────────
    from parser import parse_sonar_report
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        tf.write(content)
        local_path = tf.name

    issues = parse_sonar_report(local_path)
    issues_list = [dict(i) for i in issues]
    _set_issues(issues_list)

    return {
        "message":     f"Uploaded {file.filename}",
        "issue_count": len(issues_list),
        "path":        f"gs://{_bucket()}/{_GCS_REPORT}",
    }


# ── Issues CRUD ───────────────────────────────────────────────────────────────

@app.get("/api/issues")
def get_issues() -> dict:
    issues = _get_issues()   # reads from Redis
    return {"issues": issues, "total": len(issues)}


@app.delete("/api/issues/{key}")
def delete_issue(key: str) -> dict:
    """Remove an issue from the Redis cache and patch the GCS report blob."""
    issues = _get_issues()
    before = len(issues)
    issues = [i for i in issues if i.get("key") != key]
    after  = len(issues)

    if before == after:
        raise HTTPException(404, f"Issue {key} not found")

    _set_issues(issues)

    # Patch GCS blob so it stays in sync with Redis
    try:
        existing = json.loads(_gcs_download_text(_GCS_REPORT))
        if isinstance(existing, dict) and "issues" in existing:
            existing["issues"] = [i for i in existing["issues"] if i.get("key") != key]
            _gcs_upload(_GCS_REPORT, json.dumps(existing, indent=2).encode(), "application/json")
        elif isinstance(existing, list):
            filtered = [i for i in existing if i.get("key") != key]
            _gcs_upload(_GCS_REPORT, json.dumps(filtered, indent=2).encode(), "application/json")
        logger.info(f"[Delete] Removed issue {key} — {after} issues remain")
    except Exception as exc:
        logger.warning(f"[Delete] Could not patch GCS report: {exc}")

    return {"message": f"Issue {key} deleted", "remaining": after}


# ── Live SonarQube fetch ──────────────────────────────────────────────────────

@app.get("/api/sonar/rule/{rule_key:path}")
def get_sonar_rule(rule_key: str) -> dict:
    """
    Proxy a GET /api/rules/show call to SonarQube for a single rule key.
    Returns structured rule metadata including name, description, fix guidance,
    remediation effort, type, severity, and tags.

    Example: GET /api/sonar/rule/java:S1128
    """
    import requests as _requests
    import html as _html
    import re as _re
    from config import settings as s

    # Redis config overlay takes priority over env-var defaults
    sonar_token    = _redis_cfg_get("sonar_token")    or s.sonar_token
    sonar_host_url = _redis_cfg_get("sonar_host_url") or s.sonar_host_url

    if not sonar_token:
        raise HTTPException(400, "SONAR_TOKEN is not configured. Add it in Settings.")
    if not sonar_host_url:
        raise HTTPException(400, "SONAR_HOST_URL is not configured. Add it in Settings.")

    base_url = sonar_host_url.rstrip("/")
    try:
        resp = _requests.get(
            f"{base_url}/api/rules/show",
            auth=(sonar_token, ""),
            params={"key": rule_key},
	    verify=False,
            timeout=15,
        )
    except Exception as exc:
        raise HTTPException(502, f"Could not reach SonarQube: {exc}") from exc

    if resp.status_code == 401:
        raise HTTPException(401, "SonarQube authentication failed — check SONAR_TOKEN")
    if resp.status_code == 404:
        raise HTTPException(404, f"Rule '{rule_key}' not found in SonarQube")
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, f"SonarQube error: {resp.text[:300]}")

    body = resp.json()
    rule = body.get("rule", {})

    # Build plain-text description by stripping HTML
    html_desc = rule.get("htmlDesc", "") or rule.get("mdDesc", "")
    plain_desc = _html.unescape(_re.sub(r"<[^>]+>", " ", html_desc))
    plain_desc = _re.sub(r"\s{2,}", " ", plain_desc).strip()

    # Try to extract compliant/fix section
    fix_summary = ""
    for pat in [
        r"(?:Compliant[^<]*Solution|How to[^<]*[Ff]ix|Recommended[^<]*Practice)(.*?)(?=<h\d|$)",
    ]:
        m = _re.search(pat, html_desc, _re.DOTALL | _re.IGNORECASE)
        if m:
            snippet = _html.unescape(_re.sub(r"<[^>]+>", " ", m.group(0)))
            snippet = _re.sub(r"\s{2,}", " ", snippet).strip()
            if len(snippet) > 30:
                fix_summary = snippet[:800]
                break
    if not fix_summary:
        fix_summary = plain_desc[:600]

    logger.info(f"[API] Served rule detail for {rule_key}: {rule.get('name', '')}")

    return {
        "rule_key":           rule_key,
        "name":               rule.get("name", ""),
        "html_desc":          html_desc,
        "plain_desc":         plain_desc[:2000],
        "fix_summary":        fix_summary,
        "severity":           rule.get("severity", ""),
        "type":               rule.get("type", ""),
        "status":             rule.get("status", ""),
        "lang":               rule.get("lang", ""),
        "lang_name":          rule.get("langName", ""),
        "tags":               rule.get("tags", []),
        "sys_tags":           rule.get("sysTags", []),
        "rem_fn_type":        rule.get("remFnType", ""),
        "rem_fn_base_effort": rule.get("remFnBaseEffort", ""),
        "is_template":        rule.get("isTemplate", False),
        "created_at":         rule.get("createdAt", ""),
    }


@app.post("/api/sonar/fetch")
def fetch_sonar_issues(req: SonarFetchRequest) -> dict:
    """
    Proxy a live SonarQube /api/issues/search call using the configured
    SONAR_TOKEN and SONAR_HOST_URL, then store results in Redis (fast reads)
    and GCS (durable across Redis restarts).
    """
    import requests as _requests
    from config import settings as s

    sonar_token    = _redis_cfg_get("sonar_token")    or s.sonar_token
    sonar_host_url = _redis_cfg_get("sonar_host_url") or s.sonar_host_url

    if not sonar_token:
        raise HTTPException(400, "SONAR_TOKEN is not configured. Add it in Settings.")
    if not sonar_host_url:
        raise HTTPException(400, "SONAR_HOST_URL is not configured. Add it in Settings.")

    base_url = sonar_host_url.rstrip("/")
    url      = f"{base_url}/api/issues/search"
    params: dict = {
        "componentKeys": req.component_keys,
        "resolved":      "false" if not req.resolved else "true",
        "severities":    req.severities,
        "ps":            req.ps,
        "p":             1,
    }

    all_issues:  list[dict] = []
    effort_total = 0
    total_sonar  = 0

    try:
        while True:
            resp = _requests.get(
                url,
                auth=(sonar_token, ""),
                params=params,
		verify=False,
                timeout=30,
            )
            if resp.status_code == 401:
                raise HTTPException(401, "SonarQube authentication failed — check SONAR_TOKEN")
            if resp.status_code != 200:
                raise HTTPException(
                    resp.status_code,
                    f"SonarQube returned HTTP {resp.status_code}: {resp.text[:200]}",
                )

            body         = resp.json()
            total_sonar  = body.get("total", 0)
            effort_total = body.get("effortTotal", effort_total)
            raw_issues   = body.get("issues", [])
            all_issues  += [_normalize_sonar_issue(i) for i in raw_issues]

            # Pagination — stop when all pages fetched
            page_index = body.get("p", params["p"])
            page_size  = body.get("ps", req.ps)
            if page_index * page_size >= total_sonar:
                break
            params["p"] = page_index + 1

    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"[SonarFetch] Error: {exc}")
        raise HTTPException(500, f"Failed to reach SonarQube: {exc}") from exc

    # ── Store in Redis (fast) and GCS (durable across Redis restarts) ─────
    _set_issues(all_issues)
    try:
        report_data = {
            "source":       "sonarqube_live_fetch",
            "component":    req.component_keys,
            "fetched_at":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total":        total_sonar,
            "effort_total": effort_total,
            "issues":       all_issues,
        }
        _gcs_upload(_GCS_REPORT, json.dumps(report_data, indent=2).encode(), "application/json")
        logger.info(f"[SonarFetch] Saved {len(all_issues)} issues to GCS")
    except Exception as exc:
        logger.warning(f"[SonarFetch] Could not save report to GCS: {exc}")

    logger.info(
        f"[SonarFetch] Fetched {len(all_issues)} issues "
        f"from {req.component_keys} (total={total_sonar})"
    )

    return {
        "message":      f"Fetched {len(all_issues)} issues from SonarQube",
        "issue_count":  len(all_issues),
        "total":        total_sonar,
        "effort_total": effort_total,
        "component":    req.component_keys,
    }


@app.get("/api/sonar/report")
def get_structured_report() -> dict:
    """
    Return a structured summary of the currently loaded issues,
    grouped by severity and rule, ready to download as a JSON report.
    """
    issues = _get_issues()   # reads from Redis

    if not issues:
        return {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total":        0,
            "effort_total": "0min",
            "by_severity":  {},
            "by_rule":      {},
            "issues":       [],
        }

    sev_order   = ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"]
    by_severity: dict[str, list] = {s: [] for s in sev_order}
    by_rule:     dict[str, dict] = {}

    for iss in issues:
        sev  = iss.get("severity", "INFO")
        rule = iss.get("rule_key", "unknown")
        by_severity.setdefault(sev, []).append(iss)

        if rule not in by_rule:
            by_rule[rule] = {"rule_key": rule, "severity": sev, "count": 0, "files": []}
        by_rule[rule]["count"] += 1
        comp = iss.get("component", "")
        if comp and comp not in by_rule[rule]["files"]:
            by_rule[rule]["files"].append(comp)

    severity_summary = {
        sev: {"count": len(lst), "issues": lst}
        for sev, lst in by_severity.items()
        if lst
    }

    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total":        len(issues),
        "by_severity":  severity_summary,
        "by_rule":      dict(sorted(by_rule.items(), key=lambda x: -x[1]["count"])),
        "issues":       issues,
    }


# ── Pipeline ──────────────────────────────────────────────────────────────────

@app.post("/api/pipeline/run")
def start_run(req: PipelineRunRequest) -> dict:
    if not _gcs_exists(_GCS_REPORT):
        raise HTTPException(400, "No sonar report uploaded yet.")

    run_id = str(uuid.uuid4())

    # Initialise run document in Redis
    _set_run(run_id, {
        "id":         run_id,
        "status":     "queued",
        "steps":      [],
        "results":    [],
        "error":      None,
        "request":    req.model_dump(),
        "created_at": time.time(),
    })

    # Track insertion order (newest first), capped at 200
    _redis().lpush(_KEY_RUN_IDS, run_id)
    _redis().ltrim(_KEY_RUN_IDS, 0, 199)

    # Enqueue job — worker pod picks it up via BRPOP sonar:jobs
    _redis().lpush(_KEY_JOBS, json.dumps({
        "run_id":      run_id,
        "req":         req.model_dump(),
        "report_blob": _GCS_REPORT,
    }))

    logger.info(f"[API] Enqueued pipeline job run_id={run_id} sev={req.severities}")
    return {"run_id": run_id, "status": "queued"}


@app.get("/api/pipeline/status/{run_id}")
def get_run_status(run_id: str) -> dict:
    run = _get_run(run_id)
    if run is None:
        raise HTTPException(404, f"Run {run_id} not found")
    # Worker writes step updates directly to Redis — no draining needed here
    return run


@app.post("/api/pipeline/cancel/{run_id}")
def cancel_run(run_id: str) -> dict:
    """
    Mark the run as cancelled in Redis. The worker pod checks the run status
    between pipeline steps and exits cleanly when it sees 'cancelled'.
    """
    run = _get_run(run_id)
    if run is None:
        raise HTTPException(404, f"Run {run_id} not found")

    steps = run.get("steps", [])
    for s in steps:
        if s["status"] in ("running", "pending"):
            was_running = s["status"] == "running"
            s["status"] = "cancelled"
            if was_running:
                s["detail"] = "Cancelled by user"

    _update_run(run_id, {
        "status": "cancelled",
        "error":  "Cancelled by user",
        "steps":  steps,
    })
    logger.info(f"[API] Marked run {run_id} as cancelled in Redis")
    return {"message": f"Run {run_id} cancelled", "run_id": run_id}


@app.get("/api/pipeline/runs")
def list_runs() -> dict:
    """
    Return full run data for every run so the Angular UI can rehydrate its
    pipeline history after a page reload. Reads from Redis — newest first.
    """
    run_ids  = _redis().lrange(_KEY_RUN_IDS, 0, 99)
    runs_out = [run for rid in run_ids if (run := _get_run(rid))]
    return {"runs": runs_out}


@app.delete("/api/pipeline/runs/{run_id}")
def delete_run(run_id: str) -> dict:
    """
    Remove a finished run from Redis so it won't reappear after the UI reloads.
    Returns 409 if the run is still active.
    """
    run = _get_run(run_id)
    if run is None:
        raise HTTPException(404, f"Run {run_id} not found")
    if run.get("status") == "running":
        raise HTTPException(409, f"Run {run_id} is still active — cancel it first")

    _redis().delete(_run_key(run_id))
    _redis().lrem(_KEY_RUN_IDS, 0, run_id)
    logger.info(f"[API] Deleted run {run_id} from Redis")
    return {"message": f"Run {run_id} deleted"}


# ── Escalations ───────────────────────────────────────────────────────────────

@app.get("/api/escalations")
def list_escalations() -> dict:
    """List all escalation markdown files from GCS."""
    blobs = _gcs_list(_GCS_ESC_PFX)
    items = []

    for blob_name in sorted(blobs, reverse=True):
        if not blob_name.endswith(".md"):
            continue
        filename  = blob_name[len(_GCS_ESC_PFX):]
        name      = Path(filename).stem
        parts     = name.split("_", 1)
        issue_key  = parts[0] if parts else name
        rule_short = parts[1] if len(parts) > 1 else ""

        try:
            content   = _gcs_download_text(blob_name)
            severity  = "UNKNOWN"
            file_name = ""
            rule_key  = ""
            for line in content.splitlines():
                if "| Severity |" in line:
                    severity = line.split("|")[2].strip().strip("`")
                if "| File |" in line:
                    file_name = line.split("|")[2].strip().strip("`")
                if "| Rule |" in line:
                    rule_key = line.split("|")[2].strip().strip("`")
                if severity != "UNKNOWN" and file_name and rule_key:
                    break

            items.append({
                "filename":  filename,
                "issue_key": issue_key,
                "rule_key":  rule_key or rule_short,
                "severity":  severity,
                "file_name": file_name,
            })
        except Exception as exc:
            logger.warning(f"[Escalations] Could not read {blob_name}: {exc}")

    return {"escalations": items, "total": len(items)}


@app.get("/api/escalations/{filename}")
def get_escalation(filename: str) -> dict:
    """Return the full markdown content of one escalation file from GCS."""
    if not filename.endswith(".md") or "/" in filename or ".." in filename:
        raise HTTPException(400, "Invalid filename")

    blob_name = f"{_GCS_ESC_PFX}{filename}"
    if not _gcs_exists(blob_name):
        raise HTTPException(404, f"Escalation {filename} not found")

    return {
        "filename": filename,
        "content":  _gcs_download_text(blob_name),
    }


@app.delete("/api/escalations/{filename}")
def delete_escalation(filename: str) -> dict:
    """Delete an escalation file from GCS."""
    if not filename.endswith(".md") or "/" in filename or ".." in filename:
        raise HTTPException(400, "Invalid filename")

    blob_name = f"{_GCS_ESC_PFX}{filename}"
    if not _gcs_exists(blob_name):
        raise HTTPException(404, f"Escalation {filename} not found")

    _gcs_delete(blob_name)
    logger.info(f"[API] Deleted escalation from GCS: {filename}")
    return {"message": f"Deleted {filename}"}


# ── Config ────────────────────────────────────────────────────────────────────

@app.get("/api/config")
def get_config() -> dict:
    from config import settings as s

    def mask(v: str) -> str:
        return "***" if v else ""

    # Redis config hash overrides env-var defaults (non-token fields only)
    def _ov(key: str, default: Any) -> Any:
        v = _redis_cfg_get(key)
        return v if v != "" else default

    return {
        "gcp_project":                 _ov("gcp_project",                 s.gcp_project),
        "vertex_model":                _ov("vertex_model",                 s.vertex_model),
        "max_issues":                  int(_ov("max_issues",               s.max_issues)),
        "max_tokens":                  int(_ov("max_tokens",               s.max_tokens)),
        "confidence_high_threshold":   float(_ov("confidence_high_threshold",   s.confidence_high_threshold)),
        "confidence_medium_threshold": float(_ov("confidence_medium_threshold", s.confidence_medium_threshold)),
        "github_token":                mask(s.github_token),
        "sonar_token":                 mask(s.sonar_token),
        "sonar_host_url":              _ov("sonar_host_url",               s.sonar_host_url),
        "planner_temperature":          float(_ov("planner_temperature",    s.planner_temperature)),
        "generator_temperature":        float(_ov("generator_temperature",  s.generator_temperature)),
        "max_critic_retries":          int(_ov("max_critic_retries",        s.max_critic_retries)),
        "chroma_persist_dir":          s.chroma_persist_dir,
        "embedding_model":             _ov("embedding_model",               s.embedding_model),
        "rag_top_k":                   int(_ov("rag_top_k",                 s.rag_top_k)),
        "enable_rag":                  s.enable_rag,
        "parallel_issues":             s.parallel_issues,
        "enable_sonar_rescan":         s.enable_sonar_rescan,
    }


@app.post("/api/reload")
def reload_config() -> dict:
    """
    No-op in stateless mode: every request reads live config from Redis.
    Kept for UI compatibility — the Angular settings page calls this after saving.
    """
    from config import settings as s
    return {
        "message":         "Stateless mode — config is read live from Redis on every request.",
        "sonar_host_url":  _redis_cfg_get("sonar_host_url") or s.sonar_host_url,
        "sonar_token_set": bool(s.sonar_token or _redis_cfg_get("sonar_token")),
    }


@app.post("/api/config")
def update_config(req: ConfigUpdateRequest) -> dict:
    """
    Persist settings changes to Redis Hash (sonar:config) so every pod sees
    the change immediately without a restart.

    Token fields (github_token, sonar_token) are NOT stored in Redis —
    set them as K8s Secret env vars for persistence across pod restarts.
    They can still be updated here; the change applies to this pod's
    os.environ for the current session.
    """
    from config import settings as s

    token_fields = {"github_token", "sonar_token"}

    mapping = {
        k: v for k, v in req.model_dump().items()
        if v is not None or (k in token_fields and v == "")
    }

    env_key_map = {
        "gcp_project":                 "GCP_PROJECT",
        "vertex_model":                "VERTEX_MODEL",
        "max_issues":                  "MAX_ISSUES",
        "max_tokens":                  "MAX_TOKENS",
        "confidence_high_threshold":   "CONFIDENCE_HIGH_THRESHOLD",
        "confidence_medium_threshold": "CONFIDENCE_MEDIUM_THRESHOLD",
        "github_token":                "GITHUB_TOKEN",
        "sonar_token":                 "SONAR_TOKEN",
        "sonar_host_url":              "SONAR_HOST_URL",
        "planner_temp":                "PLANNER_TEMPERATURE",
        "generator_temp":              "GENERATOR_TEMPERATURE",
        "max_critic_retries":          "MAX_CRITIC_RETRIES",
        "chroma_persist_dir":          "CHROMA_PERSIST_DIR",
        "embedding_model":             "EMBEDDING_MODEL",
        "rag_top_k":                   "RAG_TOP_K",
    }

    settings_attr_map = {
        "planner_temp":  "planner_temperature",
        "generator_temp": "generator_temperature",
    }

    updated: list[str] = []
    redis_updates: dict[str, str] = {}

    for field, env_key in env_key_map.items():
        if field not in mapping:
            continue

        value   = mapping[field]
        val_str = ("true" if value is True else "false" if value is False else str(value))
        attr    = settings_attr_map.get(field, field)

        # Always keep local env + settings singleton in sync
        os.environ[env_key] = val_str
        if hasattr(s, attr):
            setattr(s, attr, value)

        if field in token_fields:
            # Tokens: local env only — never written to Redis
            pass
        else:
            # Non-secret: persist to Redis so all pods see the change
            redis_updates[attr] = val_str

        updated.append(field)

    if redis_updates:
        _redis().hset(_KEY_CONFIG, mapping=redis_updates)

    logger.info(f"[Config] Redis-persisted: {list(redis_updates)}, "
                f"env-only (tokens): {[f for f in updated if f in token_fields]}")
    return {
        "message":        "Config updated — non-token fields persisted to Redis (all pods updated instantly)",
        "updated_fields": updated,
    }


# ── Startup / shutdown ────────────────────────────────────────────────────────

@app.on_event("startup")
def _startup() -> None:
    logger.info("[Startup] SonarAI API — GCS + Memorystore Redis stateless mode")
    logger.info(f"[Startup] REDIS_URL  : {os.environ.get('REDIS_URL', 'redis://localhost:6379')}")
    logger.info(f"[Startup] GCS_BUCKET : {os.environ.get('GCS_BUCKET', '(not set)')}")

    # Warm Redis connection
    try:
        _redis().ping()
        logger.info("[Startup] Redis connection OK")
    except Exception as exc:
        logger.error(f"[Startup] Redis connection FAILED: {exc}")

    # Warm GCS connection
    try:
        _gcs()
        logger.info("[Startup] GCS client ready")
    except Exception as exc:
        logger.warning(f"[Startup] GCS init warning: {exc}")

    # Re-hydrate issues cache from GCS if Redis was restarted cold
    if not _redis().exists(_KEY_ISSUES):
        try:
            raw    = json.loads(_gcs_download_text(_GCS_REPORT))
            issues = raw.get("issues", raw) if isinstance(raw, dict) else raw
            _set_issues(issues)
            logger.info(f"[Startup] Re-hydrated {len(issues)} issues from GCS into Redis")
        except Exception as exc:
            logger.info(f"[Startup] No GCS report to re-hydrate ({exc})")


@app.on_event("shutdown")
def _shutdown() -> None:
    """Nothing to clean up — all state lives in Redis and GCS."""
    logger.info("[Shutdown] SonarAI API stopping — no child processes to terminate")