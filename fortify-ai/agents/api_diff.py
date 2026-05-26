"""
FortifyAI — API Diff Agent (Iteration 6)
------------------------------------------
Responsibility:
  For each resolved dependency group, before touching any file:

  1. Download the current JAR and the candidate JAR from Maven Central
  2. Run japicmp via subprocess to detect breaking API changes
  3. Parse japicmp text output — extract removed/changed methods & classes
  4. AST-scan the calling Java files to cross-reference which changed APIs
     the codebase actually calls → produces affected_lines[]

  The result feeds Iteration 7 (AI Reasoning) so the LLM can judge upgrade
  safety with precise line-level context.

japicmp invocation:
  java -jar japicmp.jar \\
       --old <current.jar> --new <candidate.jar> \\
       --output-txt <diff.txt> \\
       --ignore-missing-classes

Maven Central JAR URL pattern:
  https://repo1.maven.org/maven2/{groupPath}/{artifactId}/{version}/{artifactId}-{version}.jar

Console output (done-when):
  [API Diff] spring-context 5.3.31 → 6.1.20
             Breaking changes: 12 removed methods
             Your code calls:  3 of them
             Affected:         Service.java:42, Config.java:88
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

import requests as http_requests
from loguru import logger

from state import AgentState, ApiDiffResult

# Maven Central base URL
_MAVEN_CENTRAL = "https://repo1.maven.org/maven2"

# japicmp output section markers
_BREAKING_MARKERS = (
    "METHOD REMOVED",
    "METHOD CHANGED",
    "CLASS REMOVED",
    "CLASS CHANGED",
    "FIELD REMOVED",
    "CONSTRUCTOR REMOVED",
    "CONSTRUCTOR CHANGED",
    "ANNOTATION REMOVED",
    "INTERFACE REMOVED",
)

# Lines that indicate a binary-incompatible (breaking) change
_INCOMPATIBLE_MARKERS = (
    "!!! BINARY INCOMPATIBLE",
    "(*) BINARY INCOMPATIBLE",
    "REMOVED",
)


# ── Maven Central JAR download ────────────────────────────────────────────────

def _jar_url(group_id: str, artifact_id: str, version: str) -> str:
    """Build the Maven Central URL for a JAR file."""
    group_path = group_id.replace(".", "/")
    return (
        f"{_MAVEN_CENTRAL}/{group_path}/{artifact_id}"
        f"/{version}/{artifact_id}-{version}.jar"
    )


def _download_jar(
    group_id: str,
    artifact_id: str,
    version: str,
    dest_dir: Path,
    timeout: int = 60,
) -> Optional[Path]:
    """
    Download a JAR from Maven Central into dest_dir.
    Returns the local path on success, None on failure.
    """
    url = _jar_url(group_id, artifact_id, version)
    dest = dest_dir / f"{artifact_id}-{version}.jar"

    if dest.exists():
        logger.debug(f"[API Diff] JAR already cached: {dest.name}")
        return dest

    logger.debug(f"[API Diff] Downloading {url}")
    try:
        resp = http_requests.get(url, timeout=timeout, stream=True)
        if resp.status_code == 404:
            logger.warning(f"[API Diff] JAR not found on Maven Central: {url}")
            return None
        resp.raise_for_status()

        with open(dest, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)

        logger.debug(f"[API Diff] Downloaded {dest.stat().st_size // 1024} KB → {dest.name}")
        return dest

    except Exception as exc:
        logger.warning(f"[API Diff] Download failed for {url}: {exc}")
        return None


# ── japicmp invocation ────────────────────────────────────────────────────────

def _run_japicmp(
    japicmp_jar: Path,
    old_jar: Path,
    new_jar: Path,
    timeout: int = 60,
) -> tuple[bool, str]:
    """
    Run japicmp (v0.26) and return its stdout as the diff text.
    japicmp 0.26 has no text file output flag — the diff is printed to stdout.
    Returns (success: bool, raw_output: str).
    """
    # japicmp 0.26: use -o/-n short flags; text diff goes to stdout (no file output flag)
    cmd = [
        "java", "-jar", str(japicmp_jar),
        "-o", str(old_jar),
        "-n", str(new_jar),
        "--ignore-missing-classes",
        "--only-incompatible",              # only show breaking changes
        "--report-only-filename",           # shorter class names in output
    ]

    logger.debug(f"[API Diff] Running japicmp: {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,         # keep stderr separate so it doesn't pollute the diff
            text=True,
        )

        stdout_lines: list[str] = []
        try:
            for line in proc.stdout:
                line = line.rstrip()
                logger.debug(f"[japicmp] {line}")
                stdout_lines.append(line)
        finally:
            stderr_out = proc.stderr.read()
            if stderr_out.strip():
                logger.debug(f"[japicmp stderr] {stderr_out.strip()}")
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                logger.warning("[API Diff] japicmp timed out")
                return False, "japicmp timed out"

        # Non-zero exit = bad arguments or hard crash
        if proc.returncode != 0:
            output = "\n".join(stdout_lines)
            if stderr_out.strip():
                output = stderr_out.strip() + "\n" + output
            logger.warning(
                f"[API Diff] japicmp exited {proc.returncode}.\n{output[:400]}"
            )
            return False, output

        raw = "\n".join(stdout_lines)
        return True, raw

    except FileNotFoundError:
        logger.warning("[API Diff] java not found — cannot run japicmp")
        return False, "java not on PATH"
    except Exception as exc:
        logger.warning(f"[API Diff] japicmp error: {exc}")
        return False, str(exc)


# ── japicmp output parser ─────────────────────────────────────────────────────

def _parse_japicmp_output(raw: str) -> tuple[int, list[str]]:
    """
    Parse japicmp text output.

    Returns:
      (breaking_count: int, changed_symbols: list[str])

    changed_symbols contains short method/class names that were removed or
    changed — used to cross-reference against calling code.
    """
    breaking_count = 0
    changed_symbols: list[str] = []

    for line in raw.splitlines():
        line = line.strip()

        # Count binary-incompatible entries
        if any(m in line for m in _INCOMPATIBLE_MARKERS):
            breaking_count += 1

        # Extract changed method / class names from lines like:
        #   REMOVED METHOD: public void setDisallowedFields(String[])
        #   REMOVED CLASS: org.springframework.web.bind.WebDataBinder
        m = re.search(
            r"(?:REMOVED|CHANGED)\s+(?:METHOD|CLASS|FIELD|CONSTRUCTOR):\s+(.+)",
            line,
            re.IGNORECASE,
        )
        if m:
            symbol = m.group(1).strip()
            # Extract the simple method/class name (last segment before '(')
            short = re.split(r"[\s(]", symbol)[-1] if "(" not in symbol else \
                    re.search(r"(\w+)\s*\(", symbol).group(1) if re.search(r"(\w+)\s*\(", symbol) else symbol
            if short and short not in changed_symbols:
                changed_symbols.append(short)

    return breaking_count, changed_symbols


# ── Calling-code cross-reference ──────────────────────────────────────────────

def _extract_calling_code_snippet(
    project_path: Path,
    calling_files: list[str],
    package_prefix: str,
    context_lines: int = 50,
) -> str:
    """
    Extract ±context_lines of code around each import of package_prefix
    across all calling files.  Used by AI Reasoning in Iteration 7.
    """
    snippets: list[str] = []

    for rel_path in calling_files[:5]:          # cap at 5 files for token budget
        full_path = project_path / rel_path
        if not full_path.exists():
            continue

        try:
            source_lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue

        for i, line in enumerate(source_lines):
            if package_prefix in line and "import" in line:
                start = max(0, i - 5)
                end = min(len(source_lines), i + context_lines)
                block = "\n".join(source_lines[start:end])
                snippets.append(f"// {rel_path}\n{block}")
                break  # one snippet per file

    return "\n\n".join(snippets) if snippets else ""


def _find_affected_lines(
    project_path: Path,
    calling_files: list[str],
    changed_symbols: list[str],
) -> list[str]:
    """
    Search calling Java files for usage of changed_symbols.
    Returns list of "File.java:line_number" strings.
    Primary:  javalang AST
    Fallback: grep
    """
    if not changed_symbols:
        return []

    affected: list[str] = []

    # Try javalang first for precise line numbers
    try:
        import javalang  # type: ignore

        for rel_path in calling_files:
            full_path = project_path / rel_path
            if not full_path.exists():
                continue

            try:
                source = full_path.read_text(encoding="utf-8", errors="replace")
                source_lines = source.splitlines()
            except OSError:
                continue

            # Quick pre-filter
            if not any(sym in source for sym in changed_symbols):
                continue

            try:
                tree = javalang.parse.parse(source)
                for path_nodes, node in tree:
                    if hasattr(node, "member") and node.member in changed_symbols:
                        if hasattr(node, "position") and node.position:
                            entry = f"{Path(rel_path).name}:{node.position.line}"
                            if entry not in affected:
                                affected.append(entry)
            except Exception:
                # Grep fallback for this file
                for sym in changed_symbols:
                    for i, line in enumerate(source_lines, 1):
                        if sym in line and "import" not in line:
                            entry = f"{Path(rel_path).name}:{i}"
                            if entry not in affected:
                                affected.append(entry)

    except ImportError:
        # javalang not installed — pure grep
        for rel_path in calling_files:
            full_path = project_path / rel_path
            if not full_path.exists():
                continue
            try:
                source_lines = full_path.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
            except OSError:
                continue

            for sym in changed_symbols:
                for i, line in enumerate(source_lines, 1):
                    if sym in line and "import" not in line:
                        entry = f"{Path(rel_path).name}:{i}"
                        if entry not in affected:
                            affected.append(entry)

    return affected


# ── No-japicmp fallback ───────────────────────────────────────────────────────

def _no_japicmp_result(
    artifact_id: str,
    current_version: str,
    candidate: str,
    reason: str,
) -> ApiDiffResult:
    """
    Return a safe-by-assumption ApiDiffResult when japicmp cannot run.
    The AI Reasoning agent will be told japicmp was unavailable.
    """
    logger.warning(
        f"[API Diff] {artifact_id}: japicmp unavailable ({reason}) — "
        "assuming no breaking changes; AI Reasoning will proceed with caution"
    )
    return ApiDiffResult(
        has_breaking_changes=False,
        breaking_count=0,
        affected_lines=[],
        raw_output=f"japicmp unavailable: {reason}",
    )


# ── Main diff function ────────────────────────────────────────────────────────

def run_api_diff(
    group: dict,
    candidate: str,
    project_path: Path,
    japicmp_jar_path: str,
) -> ApiDiffResult:
    """
    Run the full API diff pipeline for one dep + candidate version pair.

    Steps:
      1. Download current + candidate JARs from Maven Central
      2. Run japicmp
      3. Parse output → breaking_count + changed_symbols
      4. Cross-reference against calling files → affected_lines
      5. Log done-when console output
      6. Return ApiDiffResult
    """
    parsed = group["parsed"]
    group_id = parsed["group_id"]
    artifact_id = parsed["artifact_id"]
    current_version = parsed["current_version"]
    calling_files: list[str] = group.get("calling_files", [])

    japicmp_jar = Path(japicmp_jar_path)

    # ── Download JARs ─────────────────────────────────────────────────────────
    with tempfile.TemporaryDirectory(prefix="fortifyai_jars_") as tmp:
        tmp_path = Path(tmp)

        old_jar = _download_jar(group_id, artifact_id, current_version, tmp_path)
        new_jar = _download_jar(group_id, artifact_id, candidate, tmp_path)

        if old_jar is None or new_jar is None:
            missing = "current" if old_jar is None else "candidate"
            return _no_japicmp_result(
                artifact_id, current_version, candidate,
                f"{missing} JAR not on Maven Central"
            )

        # ── Run japicmp ───────────────────────────────────────────────────────
        if not japicmp_jar.exists():
            return _no_japicmp_result(
                artifact_id, current_version, candidate,
                f"japicmp JAR not found at {japicmp_jar_path}"
            )

        success, raw_output = _run_japicmp(japicmp_jar, old_jar, new_jar)

        if not success:
            return _no_japicmp_result(
                artifact_id, current_version, candidate, raw_output
            )

        # ── Parse output ──────────────────────────────────────────────────────
        breaking_count, changed_symbols = _parse_japicmp_output(raw_output)

        # ── Cross-reference with calling code ─────────────────────────────────
        from agents.context import _package_prefix_for_group
        pkg_prefix = _package_prefix_for_group(group_id) or group_id

        affected_lines = _find_affected_lines(
            project_path, calling_files, changed_symbols
        )

        # Extract calling code snippet for AI Reasoning
        group["_calling_code_snippet"] = _extract_calling_code_snippet(
            project_path, calling_files, pkg_prefix
        )

        # ── Console output ────────────────────────────────────────────────────
        logger.info(f"[API Diff] {artifact_id} {current_version} → {candidate}")
        logger.info(f"           Breaking changes: {breaking_count} removed/changed symbols")
        logger.info(f"           Your code calls:  {len(affected_lines)} of them")
        if affected_lines:
            logger.info(f"           Affected:         {', '.join(affected_lines[:5])}")
        else:
            logger.info("           Affected:         none detected")

        return ApiDiffResult(
            has_breaking_changes=breaking_count > 0,
            breaking_count=breaking_count,
            affected_lines=affected_lines,
            raw_output=raw_output[:8000],   # cap for state size
        )


def run_api_diff_all_groups(
    groups: list[dict],
    project_path: Path,
    japicmp_jar_path: str,
) -> list[dict]:
    """
    Run API diff for each group against its first candidate (next_safe).
    Enriches each group dict with 'api_diff' key.
    """
    enriched: list[dict] = []

    for group in groups:
        artifact_id = group["parsed"]["artifact_id"]
        candidates: list[str] = (
            group.get("version_candidates", {}).get("candidates", [])
        )

        if not candidates:
            logger.warning(
                f"[API Diff] {artifact_id}: no candidates — skipping diff"
            )
            group = dict(group)
            group["api_diff"] = ApiDiffResult(
                has_breaking_changes=False,
                breaking_count=0,
                affected_lines=[],
                raw_output="no candidates",
            )
            enriched.append(group)
            continue

        # Run diff against the first (next_safe) candidate
        candidate = candidates[0]
        api_diff = run_api_diff(group, candidate, project_path, japicmp_jar_path)

        group = dict(group)
        group["api_diff"] = api_diff
        enriched.append(group)

    return enriched


# ── LangGraph node ────────────────────────────────────────────────────────────

def api_diff_node(state: AgentState, project_path: str, japicmp_jar_path: str) -> AgentState:
    """
    LangGraph node: api_diff.

    Reads:  state["_context_groups"]
    Writes: state["_diff_groups"]   (groups enriched with api_diff)
            state["audit_trail"]
    """
    groups: list[dict] = state.get("_context_groups", [])  # type: ignore[attr-defined]

    if not groups:
        logger.warning("[API Diff] No context groups in state — skipping")
        state["status"] = "skipped"
        state["skip_reason"] = "No context groups for API diff"
        state["audit_trail"].append({"node": "api_diff", "status": "skipped"})
        return state

    enriched = run_api_diff_all_groups(groups, Path(project_path), japicmp_jar_path)

    state["_diff_groups"] = enriched  # type: ignore[typeddict-unknown-key]
    state["audit_trail"].append({
        "node": "api_diff",
        "status": "ok",
        "groups": len(enriched),
        "breaking": sum(
            1 for g in enriched
            if g.get("api_diff", {}).get("has_breaking_changes", False)
        ),
    })

    return state