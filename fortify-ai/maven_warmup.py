"""
Background Maven cache warm-up
-------------------------------
Shared by fortifyai.py (CLI) and api_server.py (REST) so there's exactly one
implementation instead of two copies drifting apart.

Why this exists: adr_fortify.py's Phase 1b (mvn dependency:tree) tries an
offline resolution first and only falls back to a live remote fetch if the
local .m2 cache is incomplete — that remote fallback is what makes ADR runs
slow (silently, for up to 5 minutes, since it isn't streamed). By the time a
pipeline run reaches the adr-fix stage, triage / version-resolution / context
/ api-diff / ai-reasoning have already spent real wall-clock time doing
non-Maven work. Kicking off 'mvn dependency:go-offline' in a background
thread as early as project_path is known lets the .m2 cache warm up during
that window, so the offline attempt inside adr_fortify.py is far more likely
to succeed outright by the time it's actually needed.

This is strictly best-effort: failure or a slow/incomplete warm-up here is
never fatal — adr_fortify.py's own offline→online fallback logic still runs
exactly as before and handles a cold or partially-warmed cache correctly.
"""

from __future__ import annotations

import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable, Optional

# Stay under adr_fortify.py's own 300s online-fallback timeout so this can
# never itself become a new hang.
_GO_OFFLINE_TIMEOUT_SECONDS = 280


def warm_maven_cache(
    project_path: str,
    log_info: Callable[[str], None] = print,
    log_warning: Callable[[str], None] = print,
    log_debug: Callable[[str], None] = lambda _msg: None,
) -> None:
    """Run 'mvn dependency:go-offline' to pre-populate the local .m2 repository.

    Intended to run on a background thread (see start_maven_warmup) while
    earlier pipeline stages are doing non-Maven work. log_info/log_warning/
    log_debug let each caller use its own logging convention (loguru in
    fortifyai.py, plain print() in api_server.py) without this module taking
    a dependency on either.
    """
    try:
        pom = Path(project_path) / "pom.xml"
        if not pom.is_file():
            log_debug(f"[MavenWarm] No pom.xml at {project_path} — skipping warm-up")
            return

        mvn_exe = shutil.which("mvn")
        if not mvn_exe:
            log_debug("[MavenWarm] mvn not found on PATH — skipping warm-up")
            return

        log_info(f"[MavenWarm] Starting background 'mvn dependency:go-offline' on {pom} ...")
        t0 = time.time()
        result = subprocess.run(
            [mvn_exe, "dependency:go-offline", "-f", str(pom), "--no-transfer-progress"],
            capture_output=True, text=True,
            timeout=_GO_OFFLINE_TIMEOUT_SECONDS,
        )
        elapsed = time.time() - t0
        if result.returncode == 0:
            log_info(f"[MavenWarm] ✅ .m2 cache warmed in {elapsed:.0f}s — "
                      f"adr_fortify.py's offline dependency:tree should now succeed")
        else:
            log_warning(f"[MavenWarm] go-offline exited {result.returncode} after {elapsed:.0f}s "
                         f"— adr_fortify.py will fall back to its own online resolution as usual")
    except subprocess.TimeoutExpired:
        log_warning(f"[MavenWarm] go-offline timed out after {_GO_OFFLINE_TIMEOUT_SECONDS}s — "
                     f"proceeding; adr_fortify.py will still fall back to its own resolution")
    except Exception as exc:
        log_warning(f"[MavenWarm] skipped due to error: {exc}")


def start_maven_warmup(
    project_path: "Path | str",
    log_info: Callable[[str], None] = print,
    log_warning: Callable[[str], None] = print,
    log_debug: Callable[[str], None] = lambda _msg: None,
) -> Optional[threading.Thread]:
    """Kick off warm_maven_cache() on a daemon thread.

    Never joined/blocked on by the caller — it can only ever help (a warmer
    cache by the time adr-fix runs) and never slow anything down or hang the
    process on exit. Returns the thread (for an optional is_alive() status
    check later) or None if it couldn't be started.
    """
    try:
        thread = threading.Thread(
            target=warm_maven_cache,
            args=(str(project_path), log_info, log_warning, log_debug),
            name="maven-cache-warmup",
            daemon=True,
        )
        thread.start()
        return thread
    except Exception as exc:
        log_warning(f"[MavenWarm] could not start background warm-up: {exc}")
        return None


def log_warmup_status(
    thread: Optional[threading.Thread],
    log_info: Callable[[str], None] = print,
) -> None:
    """Call right before the adr-fix stage to report whether the background
    warm-up had already finished by the time it matters, instead of guessing
    at overlap from wall-clock timings alone."""
    if thread is None:
        return
    if thread.is_alive():
        log_info(
            "[MavenWarm] Still warming .m2 cache in the background — "
            "adr_fortify.py will use whatever is cached so far and fall "
            "back to its own online resolution for the rest"
        )
    else:
        log_info("[MavenWarm] ✅ Background .m2 warm-up already finished")
