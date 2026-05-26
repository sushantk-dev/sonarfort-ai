"""
SonarAI — Patch Validator  (Phase 04 — hardened)
Applies the generated unified diff and runs mvn compile + mvn test.
Compile/test failures are fed back into the LLM retry prompt via ValidationResult.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from loguru import logger

from config import settings
from state import AgentState, ValidationResult
from diff_repair import repair_diff, normalise_diff_paths

# Maximum characters of error output forwarded to the LLM retry prompt
_MAX_ERROR_CHARS = 2000


# ── Public entry point ────────────────────────────────────────────────────────

def validate(state: AgentState) -> AgentState:
    """
    LangGraph node — apply the diff and validate with Maven.

    All failures populate validation error fields so the Generator retry
    prompt can include them verbatim. Never raises — all exceptions are
    caught and surfaced as validation failures.
    """
    repo_path = state.get("repo_local_path", "")
    file_path = state.get("file_path", "")
    patch_hunks = state.get("generator_output", {}).get("patch_hunks", "")

    result: ValidationResult = {
        "diff_ok": False,
        "compile_ok": False,
        "tests_ok": False,
        "compiler_error": "",
        "test_error": "",
    }

    # ── Guard: empty patch ────────────────────────────────────────────────────
    if not patch_hunks or not patch_hunks.strip():
        msg = "Generator produced an empty patch — nothing to apply."
        logger.error(f"[Validator] {msg}")
        result["compiler_error"] = msg
        return {**state, "validation": result}

    # ── Guard: patch lacks any diff markers ──────────────────────────────────
    if "@@" not in patch_hunks and ("---" not in patch_hunks or "+++" not in patch_hunks):
        msg = (
            "Patch does not look like a valid unified diff "
            "(missing both @@ markers and --- / +++ headers). "
            "Regenerate with proper unified diff format."
        )
        logger.error(f"[Validator] {msg}")
        result["compiler_error"] = msg
        return {**state, "validation": result}

    # ── Step 1: Repair & normalise the diff ──────────────────────────────────
    # 1a. repair_diff: inject missing --- / +++ headers, fix @@ offsets
    # 1b. normalise_diff_paths: correct the path in --- / +++ to the real relative path
    # Order matters: inject headers first so normalise has something to rewrite.
    patch_hunks = repair_diff(patch_hunks, file_path)
    patch_hunks = normalise_diff_paths(patch_hunks, repo_path, file_path)

    # ── Step 2: Apply diff ────────────────────────────────────────────────────
    diff_ok, apply_error = _apply_diff(repo_path, patch_hunks, file_path)
    result["diff_ok"] = diff_ok

    if not diff_ok:
        logger.error(f"[Validator] Diff apply failed: {apply_error[:300]}")
        result["compiler_error"] = apply_error
        return {**state, "validation": result}

    logger.info("[Validator] Diff applied successfully")

    # ── Step 3: Maven compile ─────────────────────────────────────────────────
    module = _detect_maven_module(repo_path, file_path)
    if module:
        logger.info(f"[Validator] Maven module scoped to: {module}")
    compile_ok, compiler_error = _mvn_compile(repo_path, module)
    result["compile_ok"] = compile_ok
    result["compiler_error"] = _trim(compiler_error)

    if not compile_ok:
        logger.error(f"[Validator] Compile FAILED:\n{compiler_error[:400]}")
        # Revert the patch so the repo stays clean for a retry
        _revert_patch(repo_path, patch_hunks)
        return {**state, "validation": result}

    logger.info("[Validator] Maven compile ✅")

    # ── Step 4: Maven test ────────────────────────────────────────────────────
    class_name = _class_name_from_path(file_path)
    tests_ok, test_error = _mvn_test(repo_path, module, class_name)
    result["tests_ok"] = tests_ok
    result["test_error"] = _trim(test_error)

    if tests_ok:
        logger.info("[Validator] Maven tests ✅")
    else:
        logger.warning(f"[Validator] Tests FAILED:\n{test_error[:400]}")
        # Revert so retry starts from clean state
        _revert_patch(repo_path, patch_hunks)

    return {**state, "validation": result}


# ── Diff application ──────────────────────────────────────────────────────────

def _apply_diff(repo_path: str, patch_hunks: str, file_path: str = "") -> tuple[bool, str]:
    """
    Apply a unified diff using a pure-Python in-memory applier (primary path).
    Falls back to git apply if the Python applier fails.

    file_path: absolute path to the target file on disk (from state["file_path"]).
               Passed directly to the Python applier so it never has to guess the
               path from the diff header (which is always repo-relative).
    """
    # ── Primary: pure-Python in-memory apply ─────────────────────────────────
    ok, error = _apply_diff_python(patch_hunks, file_path)
    if ok:
        return True, ""

    logger.warning(f"[Validator] Python applier failed ({error[:120]}), trying git apply fallback")

    # ── Fallback: git apply (best-effort) ────────────────────────────────────
    return _apply_diff_git(repo_path, patch_hunks)


def _apply_diff_python(patch_hunks: str, file_path: str = "") -> tuple[bool, str]:
    """
    Pure-Python unified diff applier.

    Algorithm:
      1. Resolve the target file:
         a. Use ``file_path`` (absolute, from state) if provided and exists.
         b. Otherwise parse the +++ line from the patch and try:
            - as an absolute path
            - joined with cwd
         This multi-strategy resolution means the applier never fails just
         because the diff header contains a repo-relative path.
      2. Parse each @@ hunk into (old_start, removed_lines, added_lines).
      3. Load the file into a list of lines.
      4. For each hunk (in reverse order so earlier hunks don't shift later offsets):
         a. Fuzzy-locate the block of removed lines using strip()-based comparison
            (±FUZZ lines around the declared @@ start), tolerating indentation
            drift from the LLM.
         b. Fall back to a full-file scan with the same strip() comparison.
         c. Replace the matched block with the added lines.
      5. Write the result back atomically (temp file → rename).
    """
    import re as _re

    FUZZ = 10  # lines to search around the declared @@ start for fuzzy matching

    def _lines_match(file_block: list[str], patch_block: list[str], fuzzy: bool = False) -> bool:
        """
        Compare file lines to patch lines.
        - Default: strip()-based (tolerates indentation drift).
        - fuzzy=True: each patch line's stripped content must be a substring of
          the corresponding file line's stripped content, or vice-versa.
          This handles LLM hallucinations where the removed line content differs
          slightly from the actual file (different comment text, truncation, etc.).
        """
        if len(file_block) != len(patch_block):
            return False
        for f, p in zip(file_block, patch_block):
            fs, ps = f.strip(), p.strip()
            if fuzzy:
                if not ps:
                    if fs:
                        return False
                elif ps not in fs and fs not in ps:
                    return False
            else:
                if fs != ps:
                    return False
        return True

    # ── 1. Resolve the target file ───────────────────────────────────────────
    target: Optional[Path] = None

    # Strategy A: use the absolute path already known from state (preferred)
    if file_path:
        candidate = Path(file_path)
        if candidate.exists():
            target = candidate
        else:
            logger.warning(f"[Validator] state file_path does not exist: {file_path}")

    # Strategy B: parse from +++ line and try multiple resolutions
    if target is None:
        parsed_path: Optional[str] = None
        for line in patch_hunks.splitlines():
            if line.startswith("+++ "):
                raw = line[4:].strip()
                raw = _re.sub(r"^[ab]/", "", raw)  # strip b/ prefix
                parsed_path = raw
                break

        if not parsed_path:
            return False, "No +++ line found in patch and no file_path provided"

        for candidate_path in [
            Path(parsed_path),                    # as-is (works if absolute)
            Path.cwd() / parsed_path,             # relative to cwd
        ]:
            if candidate_path.exists():
                target = candidate_path
                logger.info(f"[Validator] Resolved +++ path → {target}")
                break

        if target is None:
            return False, (
                f"Target file does not exist: {parsed_path!r}. "
                "Ensure state['file_path'] is set to the absolute path on disk."
            )

    # ── 2. Parse hunks ────────────────────────────────────────────────────────
    HUNK_HDR = _re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")
    hunks: list[tuple[int, list[str], list[str]]] = []  # (old_start_1based, removed, added)

    current_removed: list[str] = []
    current_added: list[str] = []
    current_old_start: int = 0
    in_hunk = False

    for line in patch_hunks.splitlines():
        if line.startswith("--- ") or line.startswith("+++ "):
            if in_hunk:
                hunks.append((current_old_start, current_removed, current_added))
                in_hunk = False
            continue
        m = HUNK_HDR.match(line)
        if m:
            if in_hunk:
                hunks.append((current_old_start, current_removed, current_added))
            current_old_start = int(m.group(1))
            current_removed = []
            current_added = []
            in_hunk = True
            continue
        if in_hunk:
            if line.startswith("-"):
                current_removed.append(line[1:])
            elif line.startswith("+"):
                current_added.append(line[1:])
            elif line.startswith(" ") or line == "":
                # context line — counts as both removed and added
                ctx = line[1:] if line.startswith(" ") else ""
                current_removed.append(ctx)
                current_added.append(ctx)
            elif line.startswith("\\"):
                # "\ No newline at end of file" — ignore
                pass
            else:
                # No prefix at all — LLM forgot the leading space on a context line.
                # Treat as context (both removed and added) so the hunk still applies.
                logger.debug(f"[Validator] No-prefix context line treated as context: {line[:60]!r}")
                current_removed.append(line)
                current_added.append(line)

    if in_hunk:
        hunks.append((current_old_start, current_removed, current_added))

    if not hunks:
        return False, "No hunks parsed from patch"

    # ── 3. Load file ──────────────────────────────────────────────────────────
    try:
        original_text = target.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return False, f"Cannot read {file_path}: {exc}"

    # Preserve original line endings: detect CRLF vs LF
    crlf = "\r\n" in original_text
    file_lines: list[str] = original_text.splitlines()  # strips line endings

    # ── 4. Apply hunks in reverse order ──────────────────────────────────────
    for old_start, removed, added in reversed(hunks):
        n = len(removed)
        match_idx: Optional[int] = None  # 0-based index into file_lines

        if n == 0:
            # Pure-insertion hunk: anchor at declared line (adjusted to 0-based)
            match_idx = max(0, old_start - 1)
        else:
            # Pass 1: strip()-based fuzzy search ±FUZZ around declared offset
            search_start = max(0, old_start - 1)
            for delta in range(FUZZ + 1):
                for direction in ([0] if delta == 0 else [delta, -delta]):
                    idx = search_start + direction
                    if idx < 0 or idx + n > len(file_lines):
                        continue
                    if _lines_match(file_lines[idx : idx + n], removed):
                        match_idx = idx
                        break
                if match_idx is not None:
                    break

            # Pass 2: full-file scan with strip() — handles completely wrong offsets
            if match_idx is None:
                for idx in range(len(file_lines) - n + 1):
                    if _lines_match(file_lines[idx : idx + n], removed):
                        match_idx = idx
                        break

            # Pass 3: anchor-fuzzy — pick the longest non-blank removed line as
            # anchor, scan file for it, verify surrounding block.
            # Prevents short tokens like <!-- from matching the wrong line.
            if match_idx is None:
                def _fuzz(f: str, p: str) -> bool:
                    fs2, ps2 = f.strip(), p.strip()
                    if not ps2:
                        return True
                    return ps2 in fs2 or fs2 in ps2

                anchor_j = max(range(n), key=lambda j: len(removed[j].strip()))
                anchor_p = removed[anchor_j].strip()
                if anchor_p:
                    for i in range(len(file_lines)):
                        if not _fuzz(file_lines[i], removed[anchor_j]):
                            continue
                        block_start = i - anchor_j
                        if block_start < 0 or block_start + n > len(file_lines):
                            continue
                        if all(_fuzz(file_lines[block_start + j], removed[j]) for j in range(n)):
                            logger.info(
                                f"[Validator] Pass 3 anchor-fuzzy match at line "
                                f"{block_start + 1} (anchor={anchor_p[:40]!r})"
                            )
                            match_idx = block_start
                            break

            # Pass 4: similarity score — absolute last resort.
            # Finds the window in the file whose stripped text most resembles
            # the removed block. Handles fully-stripped indentation, truncated
            # comments, and XML tokens that nothing else can match.
            if match_idx is None:
                import difflib as _dl
                non_blank_r = [r.strip() for r in removed if r.strip()]
                if non_blank_r:
                    needle_text = "\n".join(r.strip() for r in removed)
                    best_score = 0.0
                    best_pos2: Optional[int] = None
                    for i in range(len(file_lines) - n + 1):
                        window = "\n".join(f.strip() for f in file_lines[i : i + n])
                        score = _dl.SequenceMatcher(
                            None, needle_text, window, autojunk=False
                        ).ratio()
                        if score > best_score:
                            best_score = score
                            best_pos2 = i
                    if best_score >= 0.4 and best_pos2 is not None:
                        logger.info(
                            f"[Validator] Pass 4 similarity match at line "
                            f"{best_pos2 + 1} (score={best_score:.2f})"
                        )
                        match_idx = best_pos2

        if match_idx is None and n > 0:
            return False, (
                f"Cannot locate hunk at line {old_start} "
                f"(no match found in file even with indentation-tolerant scan). "
                f"First removed line: {removed[0][:80]!r}"
            )

        if match_idx is None:
            match_idx = max(0, old_start - 1)

        # Replace matched block with added lines
        replace_count = n if n > 0 else 0
        file_lines[match_idx : match_idx + replace_count] = added

    # ── 5. Write back atomically ──────────────────────────────────────────────
    eol = "\r\n" if crlf else "\n"
    new_text = eol.join(file_lines)
    if original_text.endswith("\n") or original_text.endswith("\r\n"):
        new_text += eol

    try:
        # Write to a sibling temp file then replace — atomic on all OSes
        tmp_path = target.with_suffix(target.suffix + ".sonarai_tmp")
        tmp_path.write_text(new_text, encoding="utf-8")
        tmp_path.replace(target)
    except OSError as exc:
        return False, f"Cannot write patched file {file_path}: {exc}"

    logger.info(f"[Validator] Python applier: patched {target.name} ({len(hunks)} hunk(s))")
    return True, ""


def _apply_diff_git(repo_path: str, patch_hunks: str) -> tuple[bool, str]:
    """git apply fallback — used only when the Python applier fails."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".patch", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(patch_hunks)
        patch_file = tmp.name

    try:
        dry = subprocess.run(
            ["git", "apply", "--check", "--whitespace=nowarn", patch_file],
            cwd=repo_path, capture_output=True, text=True, timeout=30,
        )
        if dry.returncode != 0:
            hint = _diff_apply_hint(dry.stderr)
            return False, f"git apply --check failed:\n{dry.stderr.strip()}\n{hint}"

        apply = subprocess.run(
            ["git", "apply", "--whitespace=nowarn", patch_file],
            cwd=repo_path, capture_output=True, text=True, timeout=30,
        )
        if apply.returncode != 0:
            return False, f"git apply failed:\n{apply.stderr.strip()}"

        return True, ""

    except subprocess.TimeoutExpired:
        return False, "git apply timed out after 30s"
    except FileNotFoundError:
        return False, "git not found"
    finally:
        try:
            os.unlink(patch_file)
        except OSError:
            pass


def _revert_patch(repo_path: str, patch_hunks: str) -> None:
    """
    Revert an applied patch.
    Primary: git checkout -- <file> (reads from +++ line).
    Fallback: git apply -R.
    """
    import re as _re

    # Try to extract the patched file path and restore it via git checkout
    file_path: Optional[str] = None
    for line in patch_hunks.splitlines():
        if line.startswith("+++ "):
            raw = line[4:].strip()
            raw = _re.sub(r"^[ab]/", "", raw)
            file_path = raw
            break

    if file_path:
        try:
            result = subprocess.run(
                ["git", "checkout", "--", file_path],
                cwd=repo_path, capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0:
                logger.info(f"[Validator] Reverted {file_path} via git checkout")
                return
        except Exception:
            pass

    # Fallback: git apply -R
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".patch", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(patch_hunks)
        patch_file = tmp.name
    try:
        result = subprocess.run(
            ["git", "apply", "-R", "--whitespace=nowarn", patch_file],
            cwd=repo_path, capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            logger.info("[Validator] Patch reverted via git apply -R")
        else:
            logger.warning(
                f"[Validator] Could not auto-revert patch: {result.stderr.strip()[:200]}. "
                "Run 'git checkout .' manually if needed."
            )
    except Exception as exc:
        logger.warning(f"[Validator] Revert exception: {exc}")
    finally:
        try:
            os.unlink(patch_file)
        except OSError:
            pass


def _diff_apply_hint(stderr: str) -> str:
    """Return a human-readable hint for common git apply failure patterns."""
    s = stderr.lower()
    if "does not exist in index" in s:
        return "HINT: The file path in the diff header does not match the repo. Check --- / +++ paths."
    if "already exists in index" in s:
        return "HINT: The file already contains these changes. The diff may be a duplicate."
    if "patch does not apply" in s or "hunk" in s:
        return (
            "HINT: Hunk offset mismatch — the @@ line numbers don't match the current file. "
            "Re-read the method context line numbers and regenerate the diff."
        )
    return ""


# ── Maven helpers ─────────────────────────────────────────────────────────────

def _mvn_compile(repo_path: str, module: Optional[str]) -> tuple[bool, str]:
    """Run mvn compile -q, scoped to module if found. Skips gracefully if mvn absent."""
    cmd = ["mvn", "compile", "-q", "--no-transfer-progress"]
    if module:
        cmd += ["-pl", module, "--also-make"]

    try:
        result = subprocess.run(
            cmd,
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=settings.compile_timeout,
        )
        if result.returncode == 0:
            return True, ""
        # Extract only ERROR lines for a tighter LLM prompt
        error_lines = _extract_error_lines(result.stdout + result.stderr)
        return False, error_lines or (result.stdout + result.stderr)[-_MAX_ERROR_CHARS:]
    except FileNotFoundError:
        logger.warning("[Validator] mvn not found — compile step skipped (mark as passed)")
        return True, ""
    except subprocess.TimeoutExpired:
        return False, f"mvn compile timed out after {settings.compile_timeout}s"


def _mvn_test(
    repo_path: str, module: Optional[str], class_name: Optional[str]
) -> tuple[bool, str]:
    """Run mvn test, scoped to the affected class when possible."""
    cmd = ["mvn", "test", "--no-transfer-progress"]
    if module:
        cmd += ["-pl", module, "--also-make"]
    if class_name:
        # Try both <ClassName>Test and <ClassName>Tests naming conventions
        cmd += [f"-Dtest={class_name}Test,{class_name}Tests"]

    try:
        result = subprocess.run(
            cmd,
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=settings.test_timeout,
        )
        if result.returncode == 0:
            return True, ""

        surefire_error = _parse_surefire_results(repo_path)
        error_text = surefire_error or _extract_error_lines(result.stdout + result.stderr)
        return False, error_text or (result.stdout + result.stderr)[-_MAX_ERROR_CHARS:]

    except FileNotFoundError:
        logger.warning("[Validator] mvn not found — test step skipped (mark as passed)")
        return True, ""
    except subprocess.TimeoutExpired:
        return False, f"mvn test timed out after {settings.test_timeout}s"


def _parse_surefire_results(repo_path: str) -> Optional[str]:
    """
    Parse surefire XML reports. Returns formatted failure summary or None.
    Handles both target/surefire-reports and nested module paths.
    """
    surefire_dirs = list(Path(repo_path).rglob("surefire-reports"))
    if not surefire_dirs:
        return None

    failures: list[str] = []
    for report_dir in surefire_dirs:
        for xml_file in sorted(report_dir.glob("TEST-*.xml")):
            try:
                tree = ET.parse(xml_file)
                root = tree.getroot()
                for testcase in root.findall(".//testcase"):
                    failure = testcase.find("failure")
                    error = testcase.find("error")
                    node = failure if failure is not None else error
                    if node is not None:
                        class_name = testcase.get("classname", "")
                        method_name = testcase.get("name", "")
                        msg = node.get("message", "")
                        # Trim stack trace to first 15 lines
                        stack = "\n".join((node.text or "").splitlines()[:15])
                        failures.append(
                            f"FAILED: {class_name}.{method_name}\n"
                            f"Message: {msg}\n"
                            f"{stack}"
                        )
            except ET.ParseError as exc:
                logger.debug(f"[Validator] surefire XML parse error in {xml_file}: {exc}")
                continue

    if not failures:
        return None
    return "\n\n".join(failures[:5])  # Cap at first 5 failures


def _extract_error_lines(output: str) -> str:
    """
    Extract [ERROR] lines from Maven output — these are what matter for LLM feedback.
    Returns up to _MAX_ERROR_CHARS characters.
    """
    error_lines = [
        line for line in output.splitlines()
        if line.startswith("[ERROR]") or "error:" in line.lower()
    ]
    return _trim("\n".join(error_lines))


# ── Path helpers ──────────────────────────────────────────────────────────────

def _detect_maven_module(repo_path: str, file_path: str) -> Optional[str]:
    """
    Walk up from the .java file to the nearest pom.xml.
    Returns the module path relative to repo root, or None for root pom / no pom.
    """
    if not file_path:
        return None
    current = Path(file_path).parent
    repo_root = Path(repo_path)

    while current != repo_root and current != current.parent:
        if (current / "pom.xml").exists():
            try:
                rel = current.relative_to(repo_root)
                return str(rel) if str(rel) != "." else None
            except ValueError:
                return None
        current = current.parent

    return None


def _class_name_from_path(file_path: str) -> Optional[str]:
    """Extract Java class name (file stem) from path."""
    if not file_path:
        return None
    name = Path(file_path).stem
    return name or None


def _trim(text: str) -> str:
    """Trim error text to _MAX_ERROR_CHARS from the end (most relevant part)."""
    if len(text) > _MAX_ERROR_CHARS:
        return "...(trimmed)...\n" + text[-_MAX_ERROR_CHARS:]
    return text