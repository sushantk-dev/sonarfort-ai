"""
FortifyAI — Build Validation Agent (Iteration 8b)
----------------------------------------------------
Responsibility:
  Runs immediately after adr_fix in the graph. adr_fix now only edits
  pom.xml and creates a local git commit on a fresh feature branch
  (invoked with --skip-build) — this node owns everything that used to be
  baked into that single ADR subprocess call:

    1. Check out the branch adr_fix just committed.
    2. Run 'mvn clean install' (skip tests by default, matching ADR's old
       --skipTests default) directly against project_path, using the same
       JDK-registry resolution as ADR (required_jdk → FORTIFYAI_JDK_REGISTRY
       → PATH fallback) so the build runs under the same JDK ADR would have
       used.
    3. On success  → push the branch to origin. pr_agent only opens a PR
       for a group whose build_validation result is a *pushed* branch (this
       node overwrites state["_adr_results"]/state["adr_result"] in place
       with the merged outcome, since pr_agent_node downstream still reads
       those keys — see the "Merge" comment in build_validation_node).
    4. On failure  → roll the branch back: checkout base_branch, delete the
       feature branch (git branch -D) so the working tree is clean for the
       next attempt, and extract the Maven error for failure_analysis.

  Why split this out of adr_fix:
    - adr_fix and build_validation can now fail independently and are
      retried independently — a commit failure (e.g. dependency not found
      in any pom.xml) never needs a Maven build, and a build failure never
      needs to redo the pom.xml edit if we later want a "rebuild only"
      retry path.
    - The Maven build step is reusable for a future smoke-test / retry
      pass (Tech_Stack.md already documents a second `mvn test -pl
      <module> -Dtest=<generated_test>` invocation) without touching ADR.
    - Push no longer happens speculatively before the build is known to
      pass — nothing unbuildable reaches origin.

Console output (done-when):
  [Build Validation] Checking out feature/fortify-fix-1697672-c6266fa8
  [Build Validation] Running mvn clean install -DskipTests ...
  [Build Validation] ✅ Build passed (87s) — pushing branch
  [Build Validation] ✅ Pushed feature/fortify-fix-1697672-c6266fa8
"""

from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from typing import Callable, Optional

from loguru import logger

from state import AgentState, BuildValidationResult, PipelineCancelledError

try:  # flat layout (adr_fix.py at repo root, next to state.py)
    from adr_fix import _extract_maven_error
except ImportError:  # package layout
    from agents.adr_fix import _extract_maven_error  # type: ignore

# NOTE: deliberately does NOT import from adr_fortify.py. adr_path (and
# therefore wherever adr_fortify.py actually lives) is a runtime-configured,
# arbitrary filesystem path — see FortifyAIConfig.adr_path in config.py — the
# same category as japicmp_jar_path. adr_fix.py only ever invokes it via
# `subprocess.Popen([sys.executable, adr_path, ...])`, never as an importable
# module, precisely because it isn't guaranteed to be co-located with this
# package or even be the same script (different checkout, different version,
# a compiled/bundled tool, etc.). The JDK-registry resolution below is
# therefore duplicated in full (not imported) so this module stays correct
# regardless of what adr_path points at — see adr_fortify.py's
# _load_jdk_registry / _resolve_java_home / _build_subprocess_env for the
# canonical version this must stay behaviourally identical to.

_BUILD_TIMEOUT_SECONDS = 600

# How often the streaming loop checks cancel_check() / the overall timeout
# while waiting for mvn's stdout, and how long a SIGTERM'd mvn subprocess
# gets before we escalate to SIGKILL — mirrors adr_fix.py's invoke_adr().
_CANCEL_POLL_SECONDS = 0.5
_CANCEL_GRACE_SECONDS = 10.0


# ── JDK resolution (duplicated from adr_fortify.py — see note above) ───────────

def _load_jdk_registry() -> dict:
    """
    Load a {major_version: java_home_path} map from the FORTIFYAI_JDK_REGISTRY
    env var (a JSON object), e.g.:
        FORTIFYAI_JDK_REGISTRY='{"8":"/opt/jdks/jdk8","17":"/opt/jdks/jdk17"}'
    Returns {} if the env var is unset or not valid JSON.
    """
    raw = os.environ.get("FORTIFYAI_JDK_REGISTRY", "").strip()
    if not raw:
        return {}
    try:
        registry = json.loads(raw)
        if isinstance(registry, dict):
            return {str(k): str(v) for k, v in registry.items()}
    except (ValueError, TypeError):
        pass
    logger.warning("[Build Validation] FORTIFYAI_JDK_REGISTRY is set but not valid JSON — ignoring.")
    return {}


def _resolve_java_home(explicit_java_home: str, required_jdk: str) -> str:
    """
    Priority: explicit java_home wins; else required_jdk looked up in
    FORTIFYAI_JDK_REGISTRY; else "" (inherit whatever JDK is on PATH).
    """
    if explicit_java_home:
        return explicit_java_home
    if required_jdk:
        registry = _load_jdk_registry()
        match = registry.get(str(required_jdk))
        if match:
            return match
        logger.warning(
            f"[Build Validation] Project requires JDK {required_jdk} but no matching "
            f"entry found in FORTIFYAI_JDK_REGISTRY — using the JDK already on PATH."
        )
    return ""


def _build_subprocess_env(java_home: str) -> Optional[dict]:
    """
    Env dict pointing JAVA_HOME/PATH at a specific JDK, without discarding
    the rest of the inherited environment. None (inherit unchanged) when
    java_home is empty.
    """
    if not java_home:
        return None
    java_home = os.path.abspath(java_home)
    env = os.environ.copy()
    env["JAVA_HOME"] = java_home
    env["PATH"] = os.path.join(java_home, "bin") + os.pathsep + env.get("PATH", "")
    return env


# ── lock cleanup ──────────────────────────────────────────────────────────────
#
# Two independent lock sources can deadlock this node:
#   1. .git/index.lock — left behind if a previous git process in this same
#      project_path was killed (SIGKILL from the cancel/timeout path above,
#      a crashed prior run, etc.). Any subsequent `git` command just hangs/
#      errors ("Another git process seems to be running") instead of failing
#      fast, which is what actually looks like a "deadlock" from the caller's
#      side.
#   2. Maven local-repository resolver lock files (*.lock under the local
#      .m2 repo) — written by Maven's Aether resolver while it holds a file
#      lock on an artifact/metadata entry. If a previous `mvn` process was
#      SIGKILL'd (timeout/cancel paths in _run_maven_build) mid-resolution,
#      the lock file is never released and the next build blocks forever
#      waiting on it.
#
# Both are safe to remove pre-emptively immediately before we start our own
# git/mvn work: by construction nothing else should be concurrently using
# this checkout or this local repo at that point.

def _localrepo_from_settings_xml(settings_path: str) -> Optional[str]:
    """
    Parse <localRepository> out of a settings.xml, if present and set.
    Returns None on any parse failure or if the element is absent/empty —
    callers fall through to the next source in the priority chain.
    """
    if not os.path.isfile(settings_path):
        return None
    try:
        tree = ET.parse(settings_path)
        root = tree.getroot()
        # settings.xml is namespaced in modern POMs/schemas; strip it so
        # this works regardless of whether xmlns is declared.
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"
        elem = root.find(f"{ns}localRepository")
        if elem is None or not (elem.text or "").strip():
            return None
        value = elem.text.strip()
        # Only the common ${user.home} placeholder is expanded — settings.xml
        # can reference arbitrary properties/profiles, but resolving those
        # properly needs `mvn help:evaluate`, which is exactly the slow path
        # this helper exists to avoid.
        value = value.replace("${user.home}", os.path.expanduser("~"))
        return os.path.expanduser(value)
    except ET.ParseError as exc:
        logger.warning(f"[Build Validation] Could not parse {settings_path}: {exc}")
        return None
    except OSError as exc:
        logger.warning(f"[Build Validation] Could not read {settings_path}: {exc}")
        return None


def _resolve_maven_local_repo() -> str:
    """
    Best-effort local repo path, without shelling out to `mvn help:evaluate`
    (slow, and the whole point here is to unblock a build that's stuck).

    Priority (matches Maven's own precedence for this setting):
      1. MAVEN_REPO_LOCAL env var (this project's own override hook)
      2. -Dmaven.repo.local parsed out of MAVEN_OPTS
      3. <localRepository> in the user settings.xml (~/.m2/settings.xml,
         or $MAVEN_SETTINGS_PATH if set)
      4. <localRepository> in the global settings.xml
         ($M2_HOME/conf/settings.xml or $MAVEN_HOME/conf/settings.xml)
      5. default ~/.m2/repository
    """
    override = os.environ.get("MAVEN_REPO_LOCAL", "").strip()
    if override:
        return override

    for opt in os.environ.get("MAVEN_OPTS", "").split():
        if opt.startswith("-Dmaven.repo.local="):
            return opt.split("=", 1)[1]

    user_settings = os.environ.get(
        "MAVEN_SETTINGS_PATH", os.path.expanduser(os.path.join("~", ".m2", "settings.xml"))
    )
    from_user = _localrepo_from_settings_xml(user_settings)
    if from_user:
        return from_user

    maven_home = os.environ.get("M2_HOME") or os.environ.get("MAVEN_HOME")
    if maven_home:
        from_global = _localrepo_from_settings_xml(os.path.join(maven_home, "conf", "settings.xml"))
        if from_global:
            return from_global

    return os.path.expanduser(os.path.join("~", ".m2", "repository"))


def _clear_maven_repo_locks(local_repo: Optional[str] = None) -> int:
    """
    Remove stale *.lock and *.lastUpdated files under the Maven local
    repository. Returns the count removed. Never raises — a failed cleanup
    attempt shouldn't block the build any more than the lock itself would.

    *.lastUpdated files are Maven's own download-tracking markers, written
    while the resolver is fetching/checking an artifact. A build killed
    mid-resolution (timeout/cancel paths in _run_maven_build) can leave one
    behind; the next build then fails resolving that exact artifact with a
    FileNotFoundException/"Access is denied" on it (Windows) instead of
    just re-attempting the download — which is what actually showed up as
    the repeated "deadlock" here. Safe to delete: Maven regenerates them.
    """
    repo = local_repo or _resolve_maven_local_repo()
    if not repo or not os.path.isdir(repo):
        return 0
    removed = 0
    for root, _dirs, files in os.walk(repo):
        for name in files:
            if name.endswith(".lock") or name.endswith(".lastUpdated"):
                path = os.path.join(root, name)
                try:
                    os.remove(path)
                    removed += 1
                except OSError as exc:
                    logger.warning(f"[Build Validation] Could not remove {path}: {exc}")
    if removed:
        logger.info(f"[Build Validation] Removed {removed} stale Maven repository lock/marker file(s) under {repo}")
    return removed


def _clear_git_index_lock(project_path: str) -> bool:
    """Remove a stale .git/index.lock in project_path, if present."""
    lock_path = os.path.join(project_path, ".git", "index.lock")
    if os.path.exists(lock_path):
        try:
            os.remove(lock_path)
            logger.info(f"[Build Validation] Removed stale git lock: {lock_path}")
            return True
        except OSError as exc:
            logger.warning(f"[Build Validation] Could not remove git lock {lock_path}: {exc}")
    return False


def _clear_stale_locks(project_path: str, local_repo: Optional[str] = None) -> None:
    """Clear both lock sources up front — call before checkout + before mvn."""
    _clear_git_index_lock(project_path)
    _clear_maven_repo_locks(local_repo)


# ── git helpers ────────────────────────────────────────────────────────────────

def _run_git(cmd: list[str], project_path: str, desc: str) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            cmd, cwd=project_path, capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            err = (result.stderr or result.stdout or "").strip()
            logger.warning(f"[Build Validation] git {desc} failed: {err}")
            return False, err
        return True, ""
    except Exception as exc:
        logger.warning(f"[Build Validation] git {desc} raised: {exc}")
        return False, str(exc)


def _rollback_branch(project_path: str, branch_name: str, base_branch: Optional[str]) -> None:
    """Discard a feature branch whose build failed: checkout base, delete branch."""
    target = base_branch or "main"
    ok, _ = _run_git(["git", "checkout", target], project_path, f"checkout {target}")
    if not ok and target != "master":
        _run_git(["git", "checkout", "master"], project_path, "checkout master (fallback)")
    _run_git(["git", "branch", "-D", branch_name], project_path, f"delete {branch_name}")
    logger.warning(f"[Build Validation] ⚠️  Rolled back — deleted local branch {branch_name}")


# ── Maven build ────────────────────────────────────────────────────────────────

def _find_mvn(mvn_exe: str = "") -> str:
    if mvn_exe:
        return mvn_exe
    for candidate in ("mvn", "mvn.cmd"):
        found = shutil.which(candidate)
        if found:
            return found
    return "mvn"  # let subprocess raise FileNotFoundError if truly absent


def _kill_process_tree(proc: "subprocess.Popen", grace_seconds: float) -> None:
    """
    Terminate proc and any descendants it spawned, waiting up to
    grace_seconds for a clean exit before escalating to a hard kill.

    proc.terminate()/proc.kill() alone only ever signal the *direct* child.
    On Windows that direct child is cmd.exe running mvn.cmd, not the java.exe
    it launches — killing just the wrapper leaves the JVM running in the
    background, still holding open file handles into the local Maven repo
    (e.g. mid-write *.lastUpdated files). The next build then fails
    resolving that exact artifact with "Access is denied" instead of a
    normal retry, which is what actually presented as a repeated deadlock
    here. taskkill /T kills the whole process tree by PID, avoiding that.
    On POSIX, the process group started via start_new_session covers the
    same case (e.g. a forked mvn wrapper shell spawning the JVM).
    """
    if proc.poll() is not None:
        return  # already exited
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True, timeout=grace_seconds,
            )
        else:
            import signal
            try:
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=grace_seconds)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
    except Exception as exc:
        logger.warning(f"[Build Validation] Process-tree kill for pid={proc.pid} raised: {exc}")
    try:
        proc.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        pass


def _run_maven_build(
    project_path: str,
    mvn_exe: str = "",
    skip_tests: bool = True,
    java_home: str = "",
    build_threads: str = "1C",
    cancel_check: Optional[Callable[[], bool]] = None,
) -> tuple[bool, int, str, str]:
    """
    Returns (success, duration_seconds, stdout, stderr).
    java_home resolution (required_jdk → FORTIFYAI_JDK_REGISTRY → PATH) is
    the caller's job — see build_validation_node, which mirrors exactly how
    adr_fortify.py resolves it internally via _resolve_java_home.

    Streams Maven's output line-by-line via logger.info as it runs — a
    subprocess.run(capture_output=True) call here would silently buffer the
    entire build until it exits (no progress visible, and even then nothing
    gets printed unless the caller explicitly logs the returned text), which
    is exactly the "no console output" regression this replaced: the build
    used to be visible because adr_fortify.py's own _run_maven_build printed
    every line live. This restores that behaviour instead of just capturing
    text for post-hoc error extraction.

    cancel_check (optional): checked every _CANCEL_POLL_SECONDS while
    streaming. On a positive check the subprocess is SIGTERM'd, given
    _CANCEL_GRACE_SECONDS to exit, then SIGKILL'd, and
    PipelineCancelledError is raised — same pattern as adr_fix.py's
    invoke_adr().
    """
    exe = _find_mvn(mvn_exe)
    cmd = [exe, "clean", "install", "--no-transfer-progress"]
    if build_threads and build_threads != "1":
        cmd += ["-T", build_threads]
    if skip_tests:
        cmd.append("-DskipTests")

    env = _build_subprocess_env(java_home)  # None if java_home == "" → inherit parent env

    # Clear any stale locks left over from a killed prior build (timeout/
    # cancel paths below both SIGKILL the mvn subprocess) before starting a
    # new one — otherwise this run just blocks waiting on the old lock,
    # which is what actually shows up as a "deadlock" upstream.
    _clear_maven_repo_locks()

    logger.info(f"[Build Validation] Running {' '.join(cmd)} ...")
    t0 = time.time()
    proc = None
    output_lines: list[str] = []
    try:
        popen_kwargs: dict = {}
        if os.name == "nt":
            # New process group so a future taskkill /T targets this mvn
            # tree cleanly rather than whatever console group launched us.
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            # New session ⇒ new process group, so os.killpg below reaches
            # the whole tree (e.g. a shell wrapper spawning the JVM) and
            # not just this direct child.
            popen_kwargs["start_new_session"] = True

        proc = subprocess.Popen(
            cmd, cwd=project_path, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            **popen_kwargs,
        )

        line_queue: "queue.Queue[bytes | None]" = queue.Queue()

        def _reader() -> None:
            try:
                for raw in iter(proc.stdout.readline, b""):
                    line_queue.put(raw)
            finally:
                line_queue.put(None)  # EOF sentinel

        reader_thread = threading.Thread(target=_reader, daemon=True)
        reader_thread.start()

        cancelled = False
        timed_out = False
        while True:
            if cancel_check is not None and cancel_check():
                cancelled = True
                break
            if time.time() - t0 > _BUILD_TIMEOUT_SECONDS:
                timed_out = True
                break
            try:
                raw = line_queue.get(timeout=_CANCEL_POLL_SECONDS)
            except queue.Empty:
                continue
            if raw is None:   # EOF — subprocess closed stdout
                break
            line = raw.decode("utf-8", errors="replace").rstrip()
            output_lines.append(line)
            logger.info(f"[Build Validation]   {line}")   # streams live, matches adr_fortify.py's visibility

        if timed_out:
            logger.error(f"[Build Validation] Build timed out after {_BUILD_TIMEOUT_SECONDS}s — killing mvn")
            _kill_process_tree(proc, _CANCEL_GRACE_SECONDS)
            duration = int(time.time() - t0)
            return False, duration, "\n".join(output_lines), f"Timed out after {_BUILD_TIMEOUT_SECONDS}s"

        if cancelled:
            logger.warning(
                f"[Build Validation] Cancellation requested — terminating mvn "
                f"subprocess tree (pid={proc.pid})"
            )
            _kill_process_tree(proc, _CANCEL_GRACE_SECONDS)
            raise PipelineCancelledError(
                f"Cancelled by user while the Maven build was in progress "
                f"(pid={proc.pid}); partial output captured for the audit log."
            )

        proc.wait()   # reader hit EOF, so this returns immediately
        duration = int(time.time() - t0)
        combined = "\n".join(output_lines)
        return proc.returncode == 0, duration, combined, ""

    except PipelineCancelledError:
        raise
    except FileNotFoundError:
        duration = int(time.time() - t0)
        logger.error(f"[Build Validation] Maven executable not found ({exe})")
        return False, duration, "", f"Maven executable not found: {exe}"
    except Exception as exc:
        duration = int(time.time() - t0)
        logger.error(f"[Build Validation] Error running maven: {exc}")
        return False, duration, "\n".join(output_lines), str(exc)


# ── Per-group validation ──────────────────────────────────────────────────────

def validate_one(
    artifact_id: str,
    adr_result: dict,
    project_path: str,
    mvn_exe: str = "",
    java_home: str = "",
    required_jdk: Optional[str] = None,
    skip_tests: bool = True,
    build_threads: str = "1C",
    cancel_check: Optional[Callable[[], bool]] = None,
) -> BuildValidationResult:
    """
    Build-validate a single committed group. Assumes adr_result["success"]
    is True and a branch was actually created — callers should pass through
    a synthetic failed result for groups where adr_fix itself failed,
    without calling this (there's nothing to build).

    java_home / required_jdk: same semantics as adr_fortify.py's --java-home
    / --required-jdk — explicit java_home wins, otherwise required_jdk is
    looked up in FORTIFYAI_JDK_REGISTRY, otherwise inherit PATH. Resolving
    it the same way here keeps the build under the same JDK ADR would have
    used for this project.
    """
    branch_name = adr_result.get("branch_name")
    base_branch = adr_result.get("base_branch")

    if cancel_check is not None and cancel_check():
        raise PipelineCancelledError(
            f"Cancelled by user before build-validating {artifact_id}"
        )

    if not branch_name:
        return BuildValidationResult(
            success=False, branch_name=None, pushed=False,
            build_time_seconds=None,
            error_reason="No branch to validate (adr_fix did not create one).",
        )

    # Clear stale git index.lock / Maven repo locks (e.g. left behind by a
    # previous killed/timed-out run against this same project_path) before
    # touching git or mvn, so this attempt doesn't hang waiting on them.
    _clear_stale_locks(project_path)

    ok, err = _run_git(["git", "checkout", branch_name], project_path, f"checkout {branch_name}")
    if not ok:
        return BuildValidationResult(
            success=False, branch_name=branch_name, pushed=False,
            build_time_seconds=None,
            error_reason=f"Could not check out {branch_name} for build validation: {err}",
        )

    logger.info(f"[Build Validation] Checking out {branch_name}")
    resolved_java_home = _resolve_java_home(java_home or "", str(required_jdk) if required_jdk else "")
    success, duration, stdout, stderr = _run_maven_build(
        project_path, mvn_exe=mvn_exe, skip_tests=skip_tests,
        java_home=resolved_java_home, build_threads=build_threads,
        cancel_check=cancel_check,
    )

    if success:
        logger.info(f"[Build Validation] ✅ Build passed ({duration}s) — pushing branch")
        pushed, push_err = _run_git(
            ["git", "push", "-u", "origin", branch_name], project_path, "push branch",
        )
        if pushed:
            logger.info(f"[Build Validation] ✅ Pushed {branch_name}")
        else:
            logger.error(f"[Build Validation] ❌ Build passed but push failed: {push_err}")
        return BuildValidationResult(
            success=pushed,
            branch_name=branch_name,
            pushed=pushed,
            build_time_seconds=duration,
            error_reason=None if pushed else f"Build passed but push failed: {push_err}",
        )

    error_reason = _extract_maven_error(stdout, stderr)
    logger.error(f"[Build Validation] ❌ Build failed ({duration}s) — rolling back")
    logger.debug(f"[Build Validation] Error:\n{error_reason[:500]}")
    _rollback_branch(project_path, branch_name, base_branch)

    return BuildValidationResult(
        success=False,
        branch_name=None,   # branch was deleted — nothing downstream should reference it
        pushed=False,
        build_time_seconds=duration,
        error_reason=error_reason,
    )


# ── LangGraph node ────────────────────────────────────────────────────────────

def build_validation_node(
    state: AgentState,
    project_path: str,
    mvn_exe: str = "",
    java_home: str = "",
    skip_tests: bool = True,
    build_threads: str = "1C",
) -> AgentState:
    """
    LangGraph node: build_validation. Runs unconditionally after adr_fix.

    Reads:  state["_adr_results"]          list of {"artifact_id", "result": AdrResult}
            state["_cancel_check"]         optional zero-arg callable
            state["required_jdk"]          same field adr_fix_node reads — set by
                                            context_node; forwarded into the JDK
                                            registry lookup for this build, same as
                                            ADR would have done internally
    Writes: state["_build_validation_results"]  list of {"artifact_id", "result": BuildValidationResult}
            state["build_validation_result"]     result of the first group (for routing)
            state["last_build_error"]            overwritten with this node's error, if any
            state["audit_trail"]

    Raises: PipelineCancelledError if cancel_check() reports cancellation.
    """
    adr_results: list[dict] = state.get("_adr_results", [])  # type: ignore[attr-defined]
    cancel_check = state.get("_cancel_check")  # type: ignore[attr-defined]
    required_jdk = state.get("required_jdk")  # type: ignore[attr-defined] — set by context_node

    if not adr_results:
        logger.warning("[Build Validation] No ADR results in state — skipping")
        state["status"] = "skipped"
        state["skip_reason"] = "No committed groups to build-validate"
        state["audit_trail"].append({"node": "build_validation", "status": "skipped"})
        return state

    bv_results: list[dict] = []
    for entry in adr_results:
        artifact_id = entry["artifact_id"]
        adr_result = entry["result"]

        if not adr_result.get("success"):
            # adr_fix never committed anything for this group (no-op or commit
            # failure) — nothing to build. Pass the failure through unchanged
            # so routing/PR-gating still sees a coherent failed result.
            bv_result = BuildValidationResult(
                success=False, branch_name=None, pushed=False,
                build_time_seconds=None,
                error_reason=adr_result.get("error_reason") or "adr_fix did not commit — nothing to build",
            )
        else:
            bv_result = validate_one(
                artifact_id, adr_result, project_path,
                mvn_exe=mvn_exe, java_home=java_home, required_jdk=required_jdk,
                skip_tests=skip_tests, build_threads=build_threads,
                cancel_check=cancel_check,
            )

        bv_results.append({"artifact_id": artifact_id, "result": bv_result})

    first_result = bv_results[0]["result"] if bv_results else None
    state["build_validation_result"] = first_result  # type: ignore[typeddict-item]
    state["_build_validation_results"] = bv_results   # type: ignore[typeddict-unknown-key]

    # Merge the build outcome back into _adr_results / adr_result. pr_agent_node
    # (downstream in graph.py) reads state["_adr_results"] and gates PR creation
    # on result["success"] + result["branch_name"] — without this merge it would
    # still see adr_fix's "commit succeeded" result and try to open a PR against
    # a branch that build_validation just rolled back and deleted on failure.
    merged_adr_results: list[dict] = []
    for adr_entry, bv_entry in zip(adr_results, bv_results):
        ar = adr_entry["result"]
        br = bv_entry["result"]
        merged_adr_results.append({
            "artifact_id": adr_entry["artifact_id"],
            "result": {
                **ar,
                "success": br["success"],
                "branch_name": br["branch_name"],  # None if rolled back
                "build_time_seconds": br["build_time_seconds"],
                "error_reason": br["error_reason"] or ar.get("error_reason"),
            },
        })
    state["_adr_results"] = merged_adr_results  # type: ignore[typeddict-unknown-key]
    if merged_adr_results:
        state["adr_result"] = merged_adr_results[0]["result"]  # type: ignore[typeddict-item]

    state["audit_trail"].append({
        "node": "build_validation",
        "status": "ok",
        "passed": sum(1 for r in bv_results if r["result"]["success"]),
        "failed": sum(1 for r in bv_results if not r["result"]["success"]),
    })

    if first_result and not first_result["success"]:
        state["last_build_error"] = first_result["error_reason"]

    return state