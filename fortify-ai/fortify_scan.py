"""
FortifyAI — Fortify Scan (ScanCentral packaging + FoD SAST submission)
------------------------------------------------------------------------
Drives *triggering a new static scan*, as opposed to fortify_client.py,
which only reads vulnerabilities off an already-existing release.

Two external CLIs are shelled out to:

  scancentral   — packages a Maven project into a payload zip:
                    scancentral package -bt mvn -exclude <patterns>
                        -bf <pom.xml> -o <output.zip>

  fcli          — Fortify CLI; used here for the FoD ("Fortify on
                  Demand") session + SAST scan lifecycle:
                    fcli fod session login ...
                    fcli fod sast-scan start ...
                    fcli fod sast-scan wait-for ...

Both are assumed to be on PATH (confirmed for this deployment).
``config.scancentral_exe`` / ``config.fcli_jar_path`` exist as override
knobs if that ever changes for a given environment.

Known unknowns — verify before relying on this in production
--------------------------------------------------------------
fcli's `--output=json` field names for `sast-scan start` / `wait-for`
were not available to reproduce exactly (only the human-readable table
output was observed). ``_extract_scan_id`` / ``_extract_status`` try a
few plausible key names, but should be checked against a real
`--output=json` response for your fcli/FoD version and adjusted if the
actual keys differ. Additionally, no dedicated "get single scan status"
fcli subcommand was confirmed to exist for this version, so ``poll_scan``
repeatedly re-invokes the confirmed ``wait-for`` command with a bounded
per-call timeout instead — see its docstring.

Session handling
-----------------
fcli's FoD auth is a *login session* cached to local state on the
machine running fcli (not a bearer token handed back to us), and it
expires (~6h observed). ``ensure_fod_session`` mirrors fortify_auth.py's
``ensure_token`` check-then-refresh pattern, guarded by a process-level
lock so concurrent scan requests on the same pod never race to log in
twice. This does NOT coordinate across pods — fcli's session store is
local per-machine, so each pod maintains (and pays for) its own session.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from loguru import logger

from config import FortifyAIConfig


# ── Exceptions ───────────────────────────────────────────────────────────────

class ScanCentralError(Exception):
    """scancentral package invocation failed, timed out, or produced no zip."""


class FcliError(Exception):
    """An fcli invocation (session login, sast-scan start/wait-for) failed."""


# ── Subprocess helper ──────────────────────────────────────────────────────────

def _safe_cmd(cmd: list[str], redact: Optional[str]) -> list[str]:
    if not redact:
        return cmd
    return ["***" if part == redact else part for part in cmd]


def _run(
    cmd: list[str],
    timeout: int,
    redact: Optional[str] = None,
    env: Optional[dict] = None,
) -> subprocess.CompletedProcess:
    """
    subprocess wrapper with consistent timeout/not-found handling that
    streams output line-by-line to the log as it arrives, instead of
    buffering it all silently until the command finishes.

    ``timeout`` is an **idle/inactivity timeout**, not a total wall-clock
    cap: it resets every time a line of output is read, and only fires
    if the child goes completely silent for that long. A slow-but-active
    upload that keeps printing progress can run indefinitely without
    being killed; a genuinely wedged process (no output at all) still
    gets killed after ``timeout`` seconds either way. This matters for
    calls like fcli's chunked FoD upload, which can legitimately take
    much longer than any single fixed cap while still actively working —
    a plain wall-clock timeout would kill a slow-but-healthy upload for
    no good reason.

    Whether you actually see incremental progress lines at all still
    depends on the child process itself emitting something — if fcli
    only prints a final JSON block with nothing in between, the idle
    clock is effectively counting from process start to that single
    burst of output, same as a wall-clock timeout would in that case.

    ``redact`` — a literal value (e.g. a password) to scrub from any
    logged line or exception message so it never ends up in logs or a
    failed job's stored error string.

    ``env`` — full environment dict for the subprocess (e.g. from
    ``_maven_env`` to cap JVM heap for scancentral's own Maven build
    tool integration). ``None`` inherits the parent process's
    environment unchanged, same as plain ``subprocess.run``.

    stdin is always explicitly closed (DEVNULL) — none of these CLIs
    (scancentral, fcli) should ever need interactive input from this
    server process. Without this, a CLI that unexpectedly prompts (an
    MFA/security-code prompt, a certificate-trust confirmation, etc.)
    blocks reading from whatever stdin this process inherited.
    """
    logger.info(f"[FortifyScan] Running: {' '.join(_safe_cmd(cmd, redact))}")

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, env=env, stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError as exc:
        raise FcliError(f"Executable not found on PATH: {cmd[0]!r}") from exc

    timed_out = threading.Event()
    stop_watchdog = threading.Event()
    activity_lock = threading.Lock()
    last_activity = time.time()

    def _watchdog() -> None:
        # Polls rather than using a single Timer, because the timer needs
        # to be able to keep getting pushed back on every line of output
        # instead of firing on a fixed schedule from process start.
        while not stop_watchdog.wait(1):
            with activity_lock:
                idle_for = time.time() - last_activity
            if idle_for > timeout:
                timed_out.set()
                proc.kill()
                return

    watchdog_thread = threading.Thread(target=_watchdog, daemon=True)
    watchdog_thread.start()

    output_lines: list[str] = []
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            with activity_lock:
                last_activity = time.time()
            output_lines.append(line)
            logged = _safe_cmd([line.rstrip()], redact)[0]
            logger.info(f"[FortifyScan]   {logged}")
        proc.wait()
    finally:
        stop_watchdog.set()
        watchdog_thread.join(timeout=2)

    if timed_out.is_set():
        raise FcliError(
            f"Command produced no output for {timeout}s and was killed "
            f"(idle timeout, not a total-time cap): {' '.join(_safe_cmd(cmd, redact))}"
        )

    return subprocess.CompletedProcess(
        cmd, proc.returncode, stdout="".join(output_lines), stderr="",
    )


# Fixed JVM heap cap for scancentral's own Maven build-tool integration —
# hardcoded rather than driven by config.maven_heap_mb, since scancentral
# packaging routinely needs more headroom than build_validation's mvn
# build heap default (512MB) to resolve a large reactor without OOMing.
# Change this constant directly if a different cap is needed; an operator
# -set MAVEN_OPTS in the real environment still overrides it (see
# _maven_env below).
_SCANCENTRAL_MAVEN_HEAP_MB = 4096


def _maven_env(maven_heap_mb: Optional[int]) -> dict:
    """
    Build a subprocess environment that caps the JVM heap scancentral's
    own Maven integration uses, via MAVEN_OPTS — same precedence rule as
    adr_fortify.py's ``_build_subprocess_env``: an MAVEN_OPTS already set
    in the inherited environment (an explicit operator override) always
    wins, and a falsy ``maven_heap_mb`` disables the cap entirely,
    leaving the JVM's own default heap sizing in place.
    """
    env = os.environ.copy()
    if maven_heap_mb and not env.get("MAVEN_OPTS", "").strip():
        env["MAVEN_OPTS"] = f"-Xmx{maven_heap_mb}m"
    return env


# ── ScanCentral packaging ─────────────────────────────────────────────────────

def package_project(
    project_path: str,
    output_zip: str,
    cfg: FortifyAIConfig,
    timeout: int = 900,
) -> str:
    """
    Package a Maven project for Fortify scanning:

        scancentral package -bt <build_tool> -exclude <patterns>
            -bf <project_path>/pom.xml -o <output_zip>

    scancentral's own Maven build-tool integration inherits the process
    environment, so a fixed heap cap (_SCANCENTRAL_MAVEN_HEAP_MB) is
    applied here via MAVEN_OPTS to avoid an uncapped mvn JVM getting
    OOM-killed on a memory-limited pod. An operator-set MAVEN_OPTS in
    the real environment always overrides this (see _maven_env).

    Returns ``output_zip`` on success.

    Raises:
        ScanCentralError — missing root pom.xml, non-zero exit, timeout,
                            scancentral not found, or no zip produced.
    """
    pom_path = Path(project_path) / "pom.xml"
    if not pom_path.exists():
        raise ScanCentralError(
            f"No root pom.xml found at '{pom_path}' — scancentral packaging "
            "requires a Maven project with a pom.xml at the repo root."
        )

    exclude = ":".join(cfg.get_scancentral_exclude_patterns())

    cmd = [
        cfg.scancentral_exe, "package",
        "-bt", cfg.scancentral_build_tool,
        "-exclude", exclude,
        "-bf", str(pom_path),
        "-o", output_zip,
    ]

    try:
        result = _run(cmd, timeout=timeout, env=_maven_env(_SCANCENTRAL_MAVEN_HEAP_MB))
    except FcliError as exc:
        # _run raises FcliError generically; re-wrap as ScanCentralError so
        # callers can tell packaging failures apart from fcli/FoD failures.
        raise ScanCentralError(str(exc)) from exc

    if result.returncode != 0:
        raise ScanCentralError(
            f"scancentral package failed (exit {result.returncode}):\n"
            f"{(result.stderr or result.stdout)[-2000:]}"
        )
    if not Path(output_zip).exists():
        raise ScanCentralError(
            "scancentral package reported success but no output zip was "
            f"produced at '{output_zip}'."
        )

    logger.info(f"[FortifyScan] Packaged '{project_path}' -> '{output_zip}'")
    return output_zip


# ── fcli FoD session ───────────────────────────────────────────────────────────

_session_lock = threading.RLock()  # reentrant: ensure_fod_session holds this
                                    # while calling _session_is_fresh, which
                                    # also acquires it — a plain Lock() here
                                    # deadlocks the thread against itself.
_session_expiry: dict[tuple[str, str, str], float] = {}   # (url, tenant, user) -> epoch
_SESSION_EXPIRY_BUFFER_SECS = 60


def _fcli_base_cmd(cfg: FortifyAIConfig) -> list[str]:
    return ["java", "--enable-native-access=ALL-UNNAMED", "-jar", cfg.fcli_jar_path]


def _session_key(cfg: FortifyAIConfig) -> tuple[str, str, str]:
    # Use the same stripped form fcli actually logs in with, so
    # 'equifax\\jdoe' and 'jdoe' hit the same cache entry instead of each
    # triggering their own separate login.
    return (cfg.fortify_base_url.rstrip("/"), cfg.fod_tenant, _strip_domain_prefix(cfg.fortify_username))


def _session_is_fresh(cfg: FortifyAIConfig) -> bool:
    with _session_lock:
        expires_at = _session_expiry.get(_session_key(cfg))
    return bool(expires_at and time.time() < expires_at - _SESSION_EXPIRY_BUFFER_SECS)


def _strip_domain_prefix(username: str) -> str:
    """
    Strip a Windows-style 'domain\\user' prefix (e.g. 'equifax\\jdoe' ->
    'jdoe') for fcli's FoD login specifically.

    FoD's `fcli fod session login` takes a bare username and the org
    separately via --tenant (confirmed against a working manual CLI
    test: `-u "sushant.kumar" --tenant="equifax"`) — unlike Fortify SSC's
    OAuth endpoint, which does expect the domain-qualified form (see
    fortify_auth.py). Both flows currently read the same
    `cfg.fortify_username`, so rather than require the caller to send a
    different value for each, this strips the prefix only at the point
    fcli is actually invoked — cfg.fortify_username itself, and any SSC
    OAuth call made elsewhere from the same config, are left untouched.
    """
    return username.split("\\", 1)[-1] if "\\" in username else username


def ensure_fod_session(cfg: FortifyAIConfig, timeout: int = 60) -> None:
    """
    Guarantee a valid fcli FoD session named ``cfg.fod_session_name``
    exists before any ``fcli fod ...`` command runs.

    Cheap in-process check first (mirrors fortify_auth.ensure_token) —
    only shells out to `fcli fod session login` when the cached expiry
    is missing or within the buffer window.
    """
    logger.info(
        f"[FortifyScan] ensure_fod_session entered "
        f"(thread={threading.current_thread().name}) — checking cached session freshness."
    )
    if _session_is_fresh(cfg):
        logger.info("[FortifyScan] Cached FoD session still fresh — skipping login.")
        return

    logger.info("[FortifyScan] No fresh cached session — acquiring session lock (may wait if another thread is logging in)...")
    with _session_lock:
        logger.info("[FortifyScan] Session lock acquired.")
        # Re-check after acquiring the lock: another thread on this pod
        # may have just refreshed it while we were waiting.
        if _session_is_fresh(cfg):
            logger.info("[FortifyScan] Session became fresh while waiting for the lock — skipping login.")
            return

        missing = [
            name for name, val in (
                ("fortify_base_url", cfg.fortify_base_url),
                ("fod_tenant", cfg.fod_tenant),
                ("fortify_username", cfg.fortify_username),
                ("fortify_password", cfg.fortify_password),
            ) if not val
        ]
        if missing:
            raise FcliError(
                f"FoD session login requires {', '.join(missing)} to be set."
            )

        cmd = _fcli_base_cmd(cfg) + [
            "fod", "session", "login",
            "--url", cfg.fortify_base_url,
            "-u", _strip_domain_prefix(cfg.fortify_username),
            "-p", cfg.fortify_password,
            "--tenant", cfg.fod_tenant,
            "--session", cfg.fod_session_name,
            "--output=json",
        ]
        result = _run(cmd, timeout=timeout, redact=cfg.fortify_password)
        if result.returncode != 0:
            raise FcliError(
                f"fcli fod session login failed (exit {result.returncode}):\n"
                f"{(result.stderr or result.stdout)[-1000:]}"
            )

        # fcli's session-login output isn't reliably parseable for an exact
        # expiry across versions, so rather than trust a field that may not
        # exist, cache for a conservative window (fod_session_ttl_seconds,
        # default well under the ~6h expiry observed) and let this
        # check-then-refresh cycle renew it before it actually lapses.
        _session_expiry[_session_key(cfg)] = time.time() + cfg.fod_session_ttl_seconds
        logger.info(
            f"[FortifyScan] fcli FoD session '{cfg.fod_session_name}' established "
            f"for tenant '{cfg.fod_tenant}' (cached {cfg.fod_session_ttl_seconds}s)."
        )


def invalidate_fod_session(cfg: FortifyAIConfig) -> None:
    """Force the next ensure_fod_session call to re-login."""
    with _session_lock:
        _session_expiry.pop(_session_key(cfg), None)


# ── SAST scan submit + poll ───────────────────────────────────────────────────

def _extract_scan_id(stdout: str) -> Optional[str]:
    """
    Parse the scan id out of `fcli fod sast-scan start --output=json`.

    fcli's JSON output can be a single object or a list of one — handle
    both. Key name is a best guess ('id' / 'scanId' / 'Id') — VERIFY
    against real output for your fcli version; see module docstring.
    """
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    if isinstance(data, list):
        data = data[0] if data else {}
    if not isinstance(data, dict):
        return None
    value = data.get("id") or data.get("scanId") or data.get("Id")
    return str(value) if value else None


def start_scan(
    zip_path: str,
    release_id: int,
    cfg: FortifyAIConfig,
    timeout: int = 1800,
) -> str:
    """
    Upload the packaged zip and start a SAST scan against ``release_id``:

        fcli fod sast-scan start -f=<zip> --remediation-preference=...
            --notes= --release=<release_id> --output=json

    Returns the fcli-assigned scan id.

    Raises:
        ScanCentralError — ``zip_path`` doesn't exist at call time (distinct
                            from an upload timeout — see FcliError below).
        FcliError — non-zero exit, an unparseable response, or the upload
                    itself exceeding ``timeout`` (default 1800s — chunked
                    uploads of a large payload over a slow connection can
                    legitimately take a while; raise
                    config.fod_submit_timeout_seconds further if needed).
    """
    if not Path(zip_path).exists():
        raise ScanCentralError(
            f"Payload zip '{zip_path}' does not exist at submit time — it "
            "may have been cleaned up already, or scancentral wrote it "
            "somewhere else. Check the 'package' stage's output_summary "
            "for the actual zip_path it reported."
        )
    cmd = _fcli_base_cmd(cfg) + [
        "fod", "sast-scan", "start",
        f"-f={zip_path}",
        f"--remediation-preference={cfg.fod_remediation_preference}",
        "--notes=",
        f"--release={release_id}",
        "--output=json",
    ]
    result = _run(cmd, timeout=timeout)
    if result.returncode != 0:
        raise FcliError(
            f"fcli fod sast-scan start failed (exit {result.returncode}):\n"
            f"{(result.stderr or result.stdout)[-1000:]}"
        )

    scan_id = _extract_scan_id(result.stdout)
    if not scan_id:
        raise FcliError(
            "fcli fod sast-scan start returned no parseable scan id "
            f"(check _extract_scan_id's key names against this output):\n"
            f"{result.stdout[-1000:]}"
        )
    logger.info(f"[FortifyScan] SAST scan started — release={release_id} scan_id={scan_id}")
    return scan_id


_TERMINAL_STATUSES = {"Completed", "Canceled", "Cancelled", "Failed"}


def _extract_status(stdout: str) -> Optional[str]:
    """Best-guess status field extraction — see module docstring caveat."""
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    if isinstance(data, list):
        data = data[0] if data else {}
    if not isinstance(data, dict):
        return None
    return data.get("analysisStatusType") or data.get("status") or data.get("Analysis Status")


def poll_scan(
    release_id: int,
    scan_id: str,
    cfg: FortifyAIConfig,
    interval_seconds: int,
    timeout_seconds: int,
    on_progress: Optional[Callable[[dict], None]] = None,
) -> dict:
    """
    Block (from the calling worker thread) until the scan reaches a
    terminal status, or ``timeout_seconds`` elapses.

    Implementation note: no dedicated "get single scan status" fcli
    subcommand was confirmed for this version, so rather than guess one,
    this repeatedly invokes the confirmed ``fod sast-scan wait-for``
    command with a *short* per-call subprocess timeout. Each timeout just
    means "not done yet" (not a real failure) — the loop treats it as one
    heartbeat, calls ``on_progress``, and tries again, giving our own job
    store a progress tick roughly every ``interval_seconds`` instead of
    blocking silently for the whole scan duration. If your fcli version
    does expose a direct status/get subcommand, swap it in here — it would
    be cheaper than re-running wait-for.

    Raises FcliError if the overall timeout_seconds budget is exhausted,
    or wait-for itself exits non-zero.
    """
    deadline = time.time() + timeout_seconds
    attempt = 0
    last_output = ""

    cmd = _fcli_base_cmd(cfg) + [
        "fod", "sast-scan", "wait-for",
        f"--interval={interval_seconds}s",
        f"{release_id}:{scan_id}",
        "--output=json",
    ]

    while True:
        attempt += 1
        remaining = deadline - time.time()
        if remaining <= 0:
            raise FcliError(
                f"Scan {release_id}:{scan_id} did not reach a terminal status "
                f"within {timeout_seconds}s (last output: {last_output[-500:]})"
            )

        per_call_timeout = max(min(interval_seconds + 30, int(remaining)), 1)
        try:
            result = _run(cmd, timeout=per_call_timeout)
        except FcliError:
            # Our own bounded timeout tripped, not a real fcli failure —
            # treat as "still running" and loop again within budget.
            if on_progress:
                on_progress({"attempt": attempt, "status": "polling", "scan_id": scan_id})
            continue

        last_output = result.stdout or result.stderr or ""
        if result.returncode != 0:
            raise FcliError(
                f"fcli fod sast-scan wait-for failed (exit {result.returncode}):\n"
                f"{last_output[-1000:]}"
            )

        status = _extract_status(last_output)
        if on_progress:
            on_progress({"attempt": attempt, "status": status or "unknown", "scan_id": scan_id})

        # wait-for only exits 0 once the scan is terminal — so treat a
        # clean exit as done even if the JSON shape doesn't have the
        # field _extract_status expects (status will just be None/logged
        # as "Completed" rather than blocking further on a parse miss).
        return {"status": status or "Completed", "raw": last_output}