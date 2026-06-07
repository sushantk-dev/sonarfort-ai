"""
SonarAI — FastAPI Bridge Server
Exposes the pipeline as an HTTP API for the Angular UI.

Run:
    uvicorn api:app --reload --port 8000

Endpoints:
    POST /api/pipeline/run          — start a pipeline run
    POST /api/pipeline/cancel/{id}  — hard-kill a running run
    GET  /api/pipeline/status/{id}  — poll run status + live step events
    GET  /api/issues                — list issues from the last loaded report
    DELETE /api/issues/{key}        — remove one issue
    POST /api/report/upload         — upload a sonar-report.json
    POST /api/sonar/fetch           — live-fetch issues from SonarQube API
    GET  /api/sonar/report          — structured summary report of loaded issues
    GET  /api/config                — read current settings
    POST /api/config                — update settings (writes .env)
"""

from __future__ import annotations

import json
import multiprocessing
import os
import queue
import signal
import tempfile
import time
import uuid
from multiprocessing import Process, Queue
from pathlib import Path
from typing import Any, Optional

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

# ── In-memory stores ──────────────────────────────────────────────────────────
_runs:                dict[str, dict[str, Any]] = {}
_processes:           dict[str, Process]        = {}   # run_id → live Process
_last_report_issues:  list[dict]                = []


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
    github_repo:                 Optional[str]   = None
    sonar_token:                 Optional[str]   = None   # empty string = clear token
    sonar_host_url:              Optional[str]   = None
    sonar_org:                   Optional[str]   = None
    fortify_api_token:               Optional[str]   = None   # empty string = clear token
    fortify_host_url:            Optional[str]   = None
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


# ── Worker process function ───────────────────────────────────────────────────
# Runs in a SEPARATE PROCESS — can be hard-killed via process.terminate()

def _pipeline_worker(
    run_id: str,
    req_dict: dict,
    report_path: str,
    event_queue: Queue,  # type: ignore[type-arg]
) -> None:
    """
    Runs inside a child process. Sends step events through a Queue so the
    parent process can update _runs without shared memory.
    """

    def push(label: str, status: str, detail: str = "", ms: int = 0) -> None:
        event_queue.put({"type": "step", "label": label,
                         "status": status, "detail": detail, "ms": ms})

    def set_status(status: str, error: str = "") -> None:
        event_queue.put({"type": "status", "status": status, "error": error})

    step_labels = ["Ingest","Load Repo","RAG Fetch","Rule Fetch",
                   "Planner","Generator","Critic","Validate","Deliver"]
    for label in step_labels:
        push(label, "pending")

    try:
        # Apply env overrides
        if req_dict.get("dry_run"):
            os.environ["SONAR_AI_DRY_RUN"] = "1"
        if req_dict.get("parallel"):
            os.environ["PARALLEL_ISSUES"] = "true"
        if req_dict.get("rescan"):
            os.environ["ENABLE_SONAR_RESCAN"] = "true"
        if req_dict.get("no_rag"):
            os.environ["ENABLE_RAG"] = "false"

        from graph import run_pipeline
        from loguru import logger as _log

        # Intercept loguru INFO to drive step state
        _orig_info = _log.info

        # Per-step detail accumulator — appends lines instead of overwriting
        _step_details: dict[str, list[str]] = {label: [] for label in step_labels}

        def _clean(msg: str, prefix: str) -> str:
            """Strip the [Tag] prefix and leading whitespace to get human-readable detail."""
            import re as _re
            # Remove leading [Tag] bracket token
            cleaned = _re.sub(r"^\[" + _re.escape(prefix.strip("[]")) + r"\]\s*", "", msg).strip()
            return cleaned or msg.strip()

        def _push_detail(label: str, msg: str, tag: str) -> None:
            """Accumulate detail lines for a step and push the joined result."""
            line = _clean(msg, tag)
            if line and (not _step_details[label] or _step_details[label][-1] != line):
                _step_details[label].append(line)
            # Keep only last 3 lines to avoid overflow
            detail = " · ".join(_step_details[label][-3:])
            push(label, "running", detail)

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

        # Resolve HEAD / empty commit_sha to the actual SHA
        commit_sha = req_dict.get("commit_sha", "").strip()
        if not commit_sha or commit_sha.upper() in ("HEAD", "LATEST", ""):
            try:
                import subprocess, tempfile as _tmp
                from config import settings as _cfg
                from repo_loader import _inject_token, _repo_name_from_url
                _auth_url   = _inject_token(req_dict["repo_url"], _cfg.github_token)
                _repo_name  = _repo_name_from_url(req_dict["repo_url"])
                _local_path = Path(_cfg.clone_dir) / _repo_name
                if _local_path.exists():
                    import git as _git
                    _repo      = _git.Repo(_local_path)
                    commit_sha = _repo.head.commit.hexsha
                else:
                    result = subprocess.run(
                        ["git", "ls-remote", _auth_url, "HEAD"],
                        capture_output=True, text=True, timeout=30
                    )
                    if result.returncode == 0 and result.stdout:
                        commit_sha = result.stdout.split()[0]
                    else:
                        commit_sha = "HEAD"
                logger.info(f"[API] Resolved HEAD → {commit_sha[:12]}")
            except Exception as _exc:
                logger.warning(f"[API] Could not resolve HEAD SHA: {_exc} — using HEAD")
                commit_sha = "HEAD"

        t0 = time.time()
        final_state = run_pipeline(
            sonar_report_path=report_path,
            repo_url=req_dict["repo_url"],
            commit_sha=commit_sha,
            max_issues=req_dict.get("max_issues", 0),
            severities=req_dict.get("severities", "BLOCKER,CRITICAL,MAJOR,MINOR,INFO"),  # ← NEW
        )
        elapsed_ms = int((time.time() - t0) * 1000)

        _log.info = _orig_info

        results: list[dict] = final_state.get("pipeline_results", [])
        event_queue.put({
            "type":       "done",
            "results":    results,
            "elapsed_ms": elapsed_ms,
        })

    except Exception as exc:  # noqa: BLE001
        event_queue.put({
            "type":   "error",
            "error":  str(exc),
        })


# ── Event queue drainer (runs in parent, called on each status poll) ──────────

def _drain_queue(run_id: str, q: Queue) -> None:  # type: ignore[type-arg]
    """Pull all pending events from the child queue and apply to _runs."""
    run = _runs.get(run_id)
    if not run:
        return

    steps: list[dict] = run.setdefault("steps", [])

    try:
        while True:
            event = q.get_nowait()

            if event["type"] == "step":
                label, status = event["label"], event["status"]
                detail, ms = event.get("detail", ""), event.get("ms", 0)
                matched = False
                for s in steps:
                    if s["label"] == label:
                        s["status"] = status
                        if detail: s["detail"] = detail
                        if ms:     s["ms"]     = ms
                        matched = True
                        break
                if not matched:
                    steps.append({"label": label, "status": status,
                                  "detail": detail, "ms": ms})

            elif event["type"] == "done":
                run["status"]     = "done"
                run["results"]    = event.get("results", [])
                run["elapsed_ms"] = event.get("elapsed_ms", 0)
                for s in steps:
                    if s["status"] == "running":
                        s["status"] = "done"
                _processes.pop(run_id, None)

            elif event["type"] == "error":
                run["status"] = "error"
                run["error"]  = event.get("error", "Unknown error")
                for s in steps:
                    if s["status"] == "running":
                        s["status"] = "error"
                        s["detail"] = run["error"]
                _processes.pop(run_id, None)

    except queue.Empty:
        pass


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
    return {"status": "ok", "version": "2.0.0"}


# ── Report upload ─────────────────────────────────────────────────────────────

@app.post("/api/report/upload")
async def upload_report(file: UploadFile = File(...)) -> dict:
    global _last_report_issues

    if not file.filename or not file.filename.endswith(".json"):
        raise HTTPException(400, "Only .json files are accepted")

    content = await file.read()
    try:
        json.loads(content)  # validate JSON
    except json.JSONDecodeError as exc:
        raise HTTPException(400, f"Invalid JSON: {exc}") from exc

    uploads_dir = Path(__file__).parent / "uploads"
    uploads_dir.mkdir(exist_ok=True)
    report_path = uploads_dir / "sonar-ai-last-report.json"
    report_path.write_bytes(content)

    from parser import parse_sonar_report
    issues = parse_sonar_report(str(report_path))
    _last_report_issues = [dict(i) for i in issues]

    return {
        "message":     f"Uploaded {file.filename}",
        "issue_count": len(issues),
        "path":        str(report_path),
    }


# ── Issues CRUD ───────────────────────────────────────────────────────────────

@app.get("/api/issues")
def get_issues() -> dict:
    return {"issues": _last_report_issues, "total": len(_last_report_issues)}


@app.delete("/api/issues/{key}")
def delete_issue(key: str) -> dict:
    """Remove an issue from memory and rewrite the saved report file."""
    global _last_report_issues

    before = len(_last_report_issues)
    _last_report_issues = [i for i in _last_report_issues if i.get("key") != key]
    after  = len(_last_report_issues)

    if before == after:
        raise HTTPException(404, f"Issue {key} not found")

    report_path = Path(__file__).parent / "uploads" / "sonar-ai-last-report.json"
    if report_path.exists():
        try:
            existing = json.loads(report_path.read_text())
            if isinstance(existing, dict) and "issues" in existing:
                existing["issues"] = [i for i in existing["issues"] if i.get("key") != key]
                report_path.write_text(json.dumps(existing, indent=2))
            elif isinstance(existing, list):
                filtered = [i for i in existing if i.get("key") != key]
                report_path.write_text(json.dumps(filtered, indent=2))
            logger.info(f"[Delete] Removed issue {key} — {after} issues remain in file")
        except Exception as exc:
            logger.warning(f"[Delete] Could not rewrite report file: {exc}")

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

    if not s.sonar_token:
        raise HTTPException(400, "SONAR_TOKEN is not configured. Add it in Settings.")
    if not s.sonar_host_url:
        raise HTTPException(400, "SONAR_HOST_URL is not configured. Add it in Settings.")

    base_url = s.sonar_host_url.rstrip("/")
    try:
        resp = _requests.get(
            f"{base_url}/api/rules/show",
            auth=(s.sonar_token, ""),
            params={"key": rule_key},
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
    SONAR_TOKEN and SONAR_HOST_URL, then store results in the shared
    _last_report_issues store so the issues table and pipeline can use them.
    """
    global _last_report_issues

    import requests as _requests
    from config import settings as s

    if not s.sonar_token:
        raise HTTPException(400, "SONAR_TOKEN is not configured. Add it in Settings.")
    if not s.sonar_host_url:
        raise HTTPException(400, "SONAR_HOST_URL is not configured. Add it in Settings.")

    base_url = s.sonar_host_url.rstrip("/")
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
                auth=(s.sonar_token, ""),
                params=params,
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

    _last_report_issues = all_issues

    # Persist fetched issues to disk — survives backend restart,
    # available to the pipeline exactly like an uploaded report
    try:
        uploads_dir = Path(__file__).parent / "uploads"
        uploads_dir.mkdir(exist_ok=True)
        report_path = uploads_dir / "sonar-ai-last-report.json"
        report_data = {
            "source":       "sonarqube_live_fetch",
            "component":    req.component_keys,
            "fetched_at":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total":        total_sonar,
            "effort_total": effort_total,
            "issues":       all_issues,
        }
        report_path.write_text(json.dumps(report_data, indent=2))
        logger.info(f"[SonarFetch] Saved {len(all_issues)} issues to {report_path}")
    except Exception as exc:
        logger.warning(f"[SonarFetch] Could not save report to disk: {exc}")

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
    issues = _last_report_issues

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
    report_path = str(Path(__file__).parent / "uploads" / "sonar-ai-last-report.json")
    if not Path(report_path).exists():
        raise HTTPException(400, "No sonar report uploaded yet.")

    run_id = str(uuid.uuid4())
    _runs[run_id] = {
        "id":      run_id,
        "status":  "queued",
        "steps":   [],
        "results": [],
        "error":   None,
        "request": req.model_dump(),
    }

    q: Queue = multiprocessing.Queue()  # type: ignore[type-arg]

    proc = Process(
        target=_pipeline_worker,
        args=(run_id, req.model_dump(), report_path, q),
        daemon=True,
    )
    proc.start()

    _processes[run_id]      = proc
    _runs[run_id]["_queue"] = q
    _runs[run_id]["status"] = "running"

    logger.info(
        f"[API] Started pipeline worker PID={proc.pid} run_id={run_id} "
        f"sev={req.severities}"
    )
    return {"run_id": run_id, "status": "running"}


@app.get("/api/pipeline/status/{run_id}")
def get_run_status(run_id: str) -> dict:
    if run_id not in _runs:
        raise HTTPException(404, f"Run {run_id} not found")

    q = _runs[run_id].get("_queue")
    if q:
        _drain_queue(run_id, q)

    proc = _processes.get(run_id)
    if proc and not proc.is_alive() and _runs[run_id]["status"] == "running":
        exit_code = proc.exitcode
        if exit_code and exit_code < 0:
            _runs[run_id]["status"] = "cancelled"
        else:
            _runs[run_id]["status"] = "error"
            _runs[run_id]["error"]  = f"Worker exited unexpectedly (code {exit_code})"
        _processes.pop(run_id, None)

    return {k: v for k, v in _runs[run_id].items() if k != "_queue"}


@app.post("/api/pipeline/cancel/{run_id}")
def cancel_run(run_id: str) -> dict:
    """Hard-kill the pipeline worker process immediately."""
    if run_id not in _runs:
        raise HTTPException(404, f"Run {run_id} not found")

    proc = _processes.get(run_id)

    if proc and proc.is_alive():
        logger.warning(f"[API] Terminating pipeline PID={proc.pid} run_id={run_id}")
        proc.terminate()
        proc.join(timeout=3)
        if proc.is_alive():
            proc.kill()
            proc.join(timeout=2)
        _processes.pop(run_id, None)
        logger.warning(f"[API] Pipeline PID={proc.pid} terminated")
    else:
        logger.info(f"[API] Cancel called but run {run_id} is not running")

    if run_id in _runs:
        run = _runs[run_id]
        run["status"] = "cancelled"
        run["error"]  = "Cancelled by user"
        for s in run.get("steps", []):
            if s["status"] in ("running", "pending"):
                was_running = s["status"] == "running"
                s["status"] = "cancelled"
                if was_running:
                    s["detail"] = "Cancelled by user"

    return {"message": f"Run {run_id} cancelled", "run_id": run_id}


@app.get("/api/pipeline/runs")
def list_runs() -> dict:
    """
    Return full run data for every run in memory so the Angular UI can
    rehydrate its pipeline history after a page reload.
    Each entry mirrors GET /api/pipeline/status/{run_id} (minus _queue).
    Most-recent runs are returned first.
    """
    runs_out = []
    for run_id, run in _runs.items():
        # Drain any pending queue events so the snapshot is as fresh as possible
        q = run.get("_queue")
        if q:
            _drain_queue(run_id, q)
        runs_out.append({k: v for k, v in run.items() if k != "_queue"})

    runs_out.reverse()   # newest first (dict preserves insertion order in Py 3.7+)
    return {"runs": runs_out}


@app.delete("/api/pipeline/runs/{run_id}")
def delete_run(run_id: str) -> dict:
    """
    Remove a finished run from the in-memory store so it won't reappear
    after the UI reloads. Returns 409 if the run is still active.
    """
    if run_id not in _runs:
        raise HTTPException(404, f"Run {run_id} not found")

    proc = _processes.get(run_id)
    if proc and proc.is_alive():
        raise HTTPException(409, f"Run {run_id} is still active — cancel it first")

    _runs.pop(run_id, None)
    _processes.pop(run_id, None)
    logger.info(f"[API] Deleted run {run_id}")
    return {"message": f"Run {run_id} deleted"}


# ── Escalations ───────────────────────────────────────────────────────────────

@app.get("/api/escalations")
def list_escalations() -> dict:
    """List all escalation markdown files from the escalations/ directory."""
    from config import settings as s
    esc_dir = Path(s.escalation_dir)
    if not esc_dir.exists():
        return {"escalations": [], "total": 0}

    items = []
    for md_file in sorted(esc_dir.glob("*.md"), key=lambda f: f.stat().st_mtime, reverse=True):
        stat = md_file.stat()
        name  = md_file.stem
        parts = name.split("_", 1)
        issue_key  = parts[0] if parts else name
        rule_short = parts[1] if len(parts) > 1 else ""

        content   = md_file.read_text(encoding="utf-8", errors="replace")
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
            "filename":    md_file.name,
            "issue_key":   issue_key,
            "rule_key":    rule_key or rule_short,
            "severity":    severity,
            "file_name":   file_name,
            "size_bytes":  stat.st_size,
            "modified_at": stat.st_mtime,
        })

    return {"escalations": items, "total": len(items)}


@app.get("/api/escalations/{filename}")
def get_escalation(filename: str) -> dict:
    """Return the full markdown content of one escalation file."""
    from config import settings as s
    if not filename.endswith(".md") or "/" in filename or ".." in filename:
        raise HTTPException(400, "Invalid filename")

    esc_path = Path(s.escalation_dir) / filename
    if not esc_path.exists():
        raise HTTPException(404, f"Escalation {filename} not found")

    return {
        "filename":    filename,
        "content":     esc_path.read_text(encoding="utf-8", errors="replace"),
        "modified_at": esc_path.stat().st_mtime,
    }


@app.delete("/api/escalations/{filename}")
def delete_escalation(filename: str) -> dict:
    """Delete an escalation file."""
    from config import settings as s
    if not filename.endswith(".md") or "/" in filename or ".." in filename:
        raise HTTPException(400, "Invalid filename")

    esc_path = Path(s.escalation_dir) / filename
    if not esc_path.exists():
        raise HTTPException(404, f"Escalation {filename} not found")

    esc_path.unlink()
    logger.info(f"[API] Deleted escalation: {filename}")
    return {"message": f"Deleted {filename}"}


# ── Config ────────────────────────────────────────────────────────────────────

@app.get("/api/config")
def get_config() -> dict:
    from config import settings as s

    def mask(v: str) -> str:
        return "***" if v else ""

    return {
        "gcp_project":                 s.gcp_project,
        "vertex_model":                s.vertex_model,
        "max_issues":                  s.max_issues,
        "max_tokens":                  s.max_tokens,
        "confidence_high_threshold":   s.confidence_high_threshold,
        "confidence_medium_threshold": s.confidence_medium_threshold,
        "github_token":                mask(s.github_token),
        "github_repo":                 "",
        "sonar_token":                 mask(s.sonar_token),
        "sonar_host_url":              s.sonar_host_url,
        "fortify_api_token":               mask(s.fortify_api_token),
        "fortify_host_url":            s.fortify_host_url,
        "planner_temperature":          s.planner_temperature,
        "generator_temperature":        s.generator_temperature,
        "max_critic_retries":          s.max_critic_retries,
        "chroma_persist_dir":          s.chroma_persist_dir,
        "embedding_model":             s.embedding_model,
        "rag_top_k":                   s.rag_top_k,
        "enable_rag":                  s.enable_rag,
        "parallel_issues":             s.parallel_issues,
        "enable_sonar_rescan":         s.enable_sonar_rescan,
    }


@app.post("/api/reload")
def reload_config() -> dict:
    """
    Re-import the config module so updated .env values are picked up
    without restarting uvicorn. Called automatically by the UI after
    saving settings.
    """
    import importlib
    try:
        import config as _config_module
        importlib.reload(_config_module)
        # Reassign the module-level singleton so all subsequent imports see the new values
        _config_module.settings = _config_module.Settings()
        logger.info("[Reload] Config reloaded from .env")
        return {
            "message":       "Config reloaded successfully",
            "sonar_host_url": _config_module.settings.sonar_host_url,
            "sonar_token_set": bool(_config_module.settings.sonar_token),
        }
    except Exception as exc:
        logger.error(f"[Reload] Failed to reload config: {exc}")
        raise HTTPException(500, f"Config reload failed: {exc}") from exc


@app.post("/api/config")
def update_config(req: ConfigUpdateRequest) -> dict:
    env_path = Path(".env")
    lines: list[str] = env_path.read_text().splitlines() if env_path.exists() else []

    token_fields = {"github_token", "sonar_token", "fortify_api_token"}

    # Include non-None values; also include token fields even if empty string (explicit clear)
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
        "fortify_api_token":               "FORTIFY_TOKEN",
        "fortify_host_url":            "FORTIFY_HOST_URL",
        "planner_temp":                "PLANNER_TEMPERATURE",
        "generator_temp":              "GENERATOR_TEMPERATURE",
        "max_critic_retries":          "MAX_CRITIC_RETRIES",
        "chroma_persist_dir":          "CHROMA_PERSIST_DIR",
        "embedding_model":             "EMBEDDING_MODEL",
        "rag_top_k":                   "RAG_TOP_K",
    }

    updated:   set[str]   = set()
    new_lines: list[str]  = []

    for line in lines:
        written = False
        for field, env_key in env_key_map.items():
            if field in mapping and line.startswith(f"{env_key}="):
                val = ("true"  if mapping[field] is True  else
                       "false" if mapping[field] is False else
                       str(mapping[field]))
                new_lines.append(f"{env_key}={val}")
                updated.add(field)
                written = True
                break
        if not written:
            new_lines.append(line)

    # Append any keys not already present in the file
    for field, env_key in env_key_map.items():
        if field in mapping and field not in updated:
            val = ("true"  if mapping[field] is True  else
                   "false" if mapping[field] is False else
                   str(mapping[field]))
            new_lines.append(f"{env_key}={val}")

    env_path.write_text("\n".join(new_lines) + "\n")
    return {"message": "Config saved", "updated_fields": list(mapping.keys())}


# ── Startup / shutdown ────────────────────────────────────────────────────────

@app.on_event("startup")
def _startup() -> None:
    global _last_report_issues
    multiprocessing.set_start_method("spawn", force=True)

    report_path = Path(__file__).parent / "uploads" / "sonar-ai-last-report.json"
    if report_path.exists():
        try:
            from parser import parse_sonar_report
            issues = parse_sonar_report(str(report_path))
            _last_report_issues = [dict(i) for i in issues]
            logger.info(f"[Startup] Loaded {len(_last_report_issues)} issues from {report_path}")
        except Exception as exc:
            logger.warning(f"[Startup] Could not load saved report: {exc}")


@app.on_event("shutdown")
def _shutdown() -> None:
    """Kill all child processes when uvicorn stops."""
    for run_id, proc in list(_processes.items()):
        if proc.is_alive():
            logger.warning(f"[API] Shutdown: terminating PID={proc.pid}")
            proc.terminate()
            proc.join(timeout=2)