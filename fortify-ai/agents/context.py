"""
FortifyAI — Context Agent (Iteration 5)
-----------------------------------------
Responsibility:
  For each resolved dependency group, locate it in the codebase:

  1. Find all pom.xml files via pathlib.rglob
  2. Parse each pom.xml with ElementTree to locate the dep by groupId:artifactId
       Direct:     dep declared with <version> or ${property} in a pom
       Transitive: dep not declared in any pom — pulled in indirectly
  3. If direct and version is a ${property}, find which pom declares that property
  4. Scan Java source files for import / usage of the dep's package prefix
       Primary:  javalang AST — precise method-level call site extraction
       Fallback: grep — used when javalang raises JavaSyntaxError (Java 17+)
  5. Emit the done-when console lines and return a PomLocation + calling_files list

Console output (done-when):
  [Context] spring-context → api/pom.xml (direct, ${spring.version})
  [Context] spring-core    → transitive via spring-boot-starter
  [Context] jetty-http     → transitive via spring-boot-starter-web
  [Context] 3 calling files found for spring-context
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional
from xml.etree import ElementTree as ET

from loguru import logger

from state import AgentState, PomLocation

# Default per-JVM heap cap for the (single, sequential) Maven subprocess
# calls in this module — see _build_mvn_env below for rationale.
_DEFAULT_MAVEN_HEAP_MB = 512


def _build_mvn_env(maven_heap_mb: int = _DEFAULT_MAVEN_HEAP_MB) -> dict:
    """
    Environment for the mvn subprocess calls in this module, with a capped
    JVM heap via MAVEN_OPTS (unless MAVEN_OPTS is already set — an explicit
    operator override always wins, and maven_heap_mb=0 disables the cap).

    These calls run one at a time (never concurrently within this module),
    so this isn't about speed — it's about not letting an uncapped JVM add
    to memory pressure if this process shares a pod with other concurrent
    Maven subprocesses (see adr_fortify.py's Phase 1, which is where an
    uncapped multi-JVM heap actually caused a pod-level OOM kill).
    """
    env = os.environ.copy()
    if maven_heap_mb and not env.get("MAVEN_OPTS", "").strip():
        env["MAVEN_OPTS"] = f"-Xmx{maven_heap_mb}m"
    return env

# Maven XML namespace used in pom.xml files
_MVN_NS = "http://maven.apache.org/POM/4.0.0"

# Namespace map for ElementTree XPath queries
_NS = {"m": _MVN_NS}

# Group-ID prefix → Java package prefix mapping for import scanning
# Extend as needed for other ecosystems
_GROUP_TO_PACKAGE: dict[str, str] = {
    "org.springframework":          "org.springframework",
    "org.springframework.boot":     "org.springframework",
    "org.eclipse.jetty":            "org.eclipse.jetty",
    "com.fasterxml.jackson.core":   "com.fasterxml.jackson",
    "com.fasterxml.jackson":        "com.fasterxml.jackson",
    "org.apache.logging.log4j":     "org.apache.logging.log4j",
    "ch.qos.logback":               "ch.qos.logback",
    "org.apache.commons":           "org.apache.commons",
    "com.google.guava":             "com.google.common",
    "io.netty":                     "io.netty",
    "org.hibernate":                "org.hibernate",
    "javax.servlet":                "javax.servlet",
    "jakarta.servlet":              "jakarta.servlet",
}


# ── pom.xml parsing ───────────────────────────────────────────────────────────

def _strip_ns(tag: str) -> str:
    """Remove the Maven XML namespace prefix from an element tag."""
    return tag.replace(f"{{{_MVN_NS}}}", "")


def _parse_pom(pom_path: Path) -> ET.Element | None:
    """Parse a pom.xml, return root element or None on error."""
    try:
        tree = ET.parse(pom_path)
        return tree.getroot()
    except ET.ParseError as exc:
        logger.debug(f"[Context] XML parse error in {pom_path}: {exc}")
        return None


def _resolve_property(prop_ref: str, root: ET.Element) -> Optional[str]:
    """
    Resolve a Maven property reference like ${spring.version} → '5.3.31'.
    Looks inside <properties> of the given pom root element.
    Returns None if not found.
    """
    m = re.match(r"\$\{(.+)\}", prop_ref)
    if not m:
        return prop_ref  # not a property reference — literal value

    prop_name = m.group(1)
    # Search with and without namespace
    for ns_prefix in [f"{{{_MVN_NS}}}", ""]:
        elem = root.find(f".//{ns_prefix}properties/{ns_prefix}{prop_name}")
        if elem is not None and elem.text:
            return elem.text.strip()
    return None


def _find_dep_in_pom(
    pom_path: Path,
    group_id: str,
    artifact_id: str,
) -> Optional[dict]:
    """
    Search one pom.xml for a direct <dependency> matching group_id:artifact_id.

    Returns a dict with:
      pom_file, line_number, version_raw (may be ${prop}), version_property,
      resolved_version, property_defined_in (None — resolved separately)
    Or None if not found.
    """
    root = _parse_pom(pom_path)
    if root is None:
        return None

    # Try with Maven namespace first, then without
    for ns in [_MVN_NS, ""]:
        gid_tag = f"{{{ns}}}groupId" if ns else "groupId"
        aid_tag = f"{{{ns}}}artifactId" if ns else "artifactId"
        ver_tag = f"{{{ns}}}version" if ns else "version"
        dep_tag = f"{{{ns}}}dependency" if ns else "dependency"

        for dep in root.iter(dep_tag):
            gid_elem = dep.find(gid_tag)
            aid_elem = dep.find(aid_tag)

            if gid_elem is None or aid_elem is None:
                continue

            if gid_elem.text == group_id and aid_elem.text == artifact_id:
                ver_elem = dep.find(ver_tag)
                version_raw = ver_elem.text.strip() if ver_elem is not None and ver_elem.text else None

                is_property = bool(version_raw and version_raw.startswith("${"))
                resolved = _resolve_property(version_raw, root) if version_raw else None

                return {
                    "pom_file": str(pom_path),
                    "line_number": None,          # ET doesn't expose line numbers easily
                    "version_raw": version_raw,
                    "version_property": version_raw if is_property else None,
                    "resolved_version": resolved,
                    "property_defined_in": None,  # filled below if needed
                }

    return None


def _find_property_pom(
    all_poms: list[Path],
    prop_ref: str,
    project_path: Path,
) -> Optional[str]:
    """
    Search all pom files to find which one declares a given ${property}.

    Returns the pom path **relative to project_path** (matching pom_file's
    convention), or None if not found.

    Why relative matters: this value is persisted verbatim into
    PomLocation.property_defined_in and can be checkpointed by the API
    server's pipeline resume support (see api_server._run_full_pipeline).
    A resumed run re-clones the repo into a NEW temp directory — an
    absolute path captured against the original clone would point at a
    directory that no longer exists by the time a downstream stage (e.g.
    adr-fix, if resume re-enters before it has run) tries to open it.
    Returning a relative path lets it resolve correctly against whichever
    clone directory the pipeline is currently using.
    """
    m = re.match(r"\$\{(.+)\}", prop_ref)
    if not m:
        return None
    prop_name = m.group(1)

    for pom_path in all_poms:
        root = _parse_pom(pom_path)
        if root is None:
            continue
        for ns in [_MVN_NS, ""]:
            ns_prefix = f"{{{ns}}}" if ns else ""
            elem = root.find(f".//{ns_prefix}properties/{ns_prefix}{prop_name}")
            if elem is not None:
                try:
                    return str(pom_path.relative_to(project_path))
                except ValueError:
                    return str(pom_path)
    return None


# ── Required-JDK detection ─────────────────────────────────────────────────────

# Properties checked, in priority order — <release> implies both source and
# target and is what modern (Java 9+) projects should use, so it wins if present.
_JDK_PROPERTY_NAMES = [
    "maven.compiler.release",
    "maven.compiler.target",
    "maven.compiler.source",
    "java.version",
]


def _normalize_jdk_version(raw: str) -> Optional[str]:
    """
    Normalize a Java version string to a bare major-version number.
    '1.8' -> '8', '17' -> '17', '11.0.2' -> '11'. Returns None if unparsable.
    """
    raw = raw.strip()
    m = re.match(r"1\.(\d+)", raw)          # legacy '1.8' style
    if m:
        return m.group(1)
    m = re.match(r"(\d+)", raw)             # '17', '11.0.2', etc.
    if m:
        return m.group(1)
    return None


def _find_compiler_plugin_release(root: ET.Element) -> Optional[str]:
    """
    Check <build><plugins><plugin> for maven-compiler-plugin's
    <configuration><release>/<source>/<target>, in case the version isn't
    declared via a <properties> entry.
    """
    for ns in [_MVN_NS, ""]:
        p = f"{{{ns}}}" if ns else ""
        for plugin in root.iter(f"{p}plugin"):
            aid = plugin.find(f"{p}artifactId")
            if aid is None or aid.text != "maven-compiler-plugin":
                continue
            config = plugin.find(f"{p}configuration")
            if config is None:
                continue
            for tag in ("release", "target", "source"):
                elem = config.find(f"{p}{tag}")
                if elem is not None and elem.text:
                    return elem.text.strip()
    return None


def _check_root_for_jdk(root: ET.Element, source_label: str) -> Optional[str]:
    """
    Check one already-parsed pom <project> root element for a JDK version
    signal — properties first (in _JDK_PROPERTY_NAMES priority order), then
    maven-compiler-plugin configuration. Shared by both the literal-file scan
    in detect_required_jdk() and the effective-pom fallback below, so both
    paths recognise the exact same set of signals.

    source_label: used only for the debug log line (e.g. a filename, or
        "effective POM").
    """
    for prop_name in _JDK_PROPERTY_NAMES:
        for ns_prefix in [f"{{{_MVN_NS}}}", ""]:
            elem = root.find(f".//{ns_prefix}properties/{ns_prefix}{prop_name}")
            if elem is not None and elem.text:
                normalized = _normalize_jdk_version(elem.text)
                if normalized:
                    logger.info(
                        f"[Context] JDK {normalized} detected via "
                        f"{prop_name}='{elem.text.strip()}' in {source_label}"
                    )
                    return normalized

    plugin_version = _find_compiler_plugin_release(root)
    if plugin_version:
        normalized = _normalize_jdk_version(plugin_version)
        if normalized:
            logger.info(
                f"[Context] JDK {normalized} detected via "
                f"maven-compiler-plugin release='{plugin_version}' in {source_label}"
            )
            return normalized

    return None


def _detect_required_jdk_via_effective_pom(
    project_path: Path,
    mvn_exe: str = "",
    timeout: int = 90,
    maven_heap_mb: int = _DEFAULT_MAVEN_HEAP_MB,
) -> Optional[str]:
    """
    Fallback used when NO local pom.xml in the project tree contains a
    literal JDK signal (detect_required_jdk()'s static scan returns None).

    This happens routinely for Spring Boot projects (and other org-internal
    parent-BOM setups) that inherit their Java version from a remote parent
    POM — e.g. <parent>spring-boot-starter-parent</parent> — resolved out of
    the local .m2 cache / Maven Central rather than declared anywhere inside
    this checked-out repo. A static project_path.rglob("pom.xml") scan can
    only ever see files physically on disk in this repo, so it's blind to
    values that only exist once Maven actually resolves the parent chain.

    Resolves this by running `mvn help:effective-pom` on the project's root
    pom.xml, which fully expands the parent inheritance chain (and BOM
    imports) into a single self-contained XML document, then checks that
    resolved document with the same _check_root_for_jdk() logic used for
    literal files.

    Scope/limitation: only the ROOT pom's effective view is resolved (one
    subprocess call, kept fast) — this covers the common case where the
    Java version is inherited project-wide from a parent. It does NOT catch
    a child module overriding the version upward on its own (that case is
    already handled by detect_required_jdk()'s literal multi-pom max-scan,
    since an override like that is, by definition, written explicitly in
    that child's own pom.xml and so is visible to the static scan).

    Returns None if mvn is unavailable, the project can't be resolved, or
    the effective POM has no JDK signal either.

    maven_heap_mb: per-JVM heap cap applied via MAVEN_OPTS (see
        _build_mvn_env); 0 disables the cap.
    """
    root_pom = project_path if project_path.is_file() else project_path / "pom.xml"
    if not root_pom.is_file():
        return None

    if not mvn_exe:
        mvn_exe = shutil.which("mvn") or shutil.which("mvn.cmd") or ""
    if not mvn_exe:
        logger.warning(
            "[Context] mvn not on PATH for this process — cannot resolve "
            "effective POM for JDK detection; project's required JDK will "
            "be reported as unknown"
        )
        return None

    cwd = str(root_pom.parent)
    out_file = root_pom.parent / ".fortifyai_effective_pom_tmp.xml"
    logger.info(f"[Context] Running: {mvn_exe} help:effective-pom -f {root_pom}")

    try:
        proc = subprocess.run(
            [
                mvn_exe, "help:effective-pom",
                f"-Doutput={out_file}",
                "-f", str(root_pom),
                "--no-transfer-progress",
                "-q",
            ],
            cwd=cwd,
            capture_output=True,
            timeout=timeout,
            env=_build_mvn_env(maven_heap_mb),
            start_new_session=True,  # isolate into its own process group so
                                      # a timeout kill can't reach the parent
                                      # process, and any grandchild JVM it
                                      # spawns is reachable for cleanup
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.warning(f"[Context] mvn help:effective-pom failed to run: {exc}")
        return None

    try:
        if proc.returncode != 0 or not out_file.is_file():
            stderr_tail = (proc.stderr or b"").decode(errors="replace")[-500:]
            logger.warning(
                f"[Context] mvn help:effective-pom exited {proc.returncode} "
                f"or produced no output — cannot resolve inherited JDK version. "
                f"stderr tail: {stderr_tail}"
            )
            return None

        try:
            tree = ET.parse(out_file)
            root_elem = tree.getroot()
        except ET.ParseError as exc:
            logger.warning(f"[Context] Could not parse effective POM XML: {exc}")
            return None
    finally:
        try:
            if out_file.is_file():
                out_file.unlink()
        except OSError:
            pass

    result = _check_root_for_jdk(root_elem, "effective POM (resolved parent chain)")
    if result:
        logger.info(
            f"[Context] Required JDK {result} resolved via effective POM — "
            "inherited from a parent POM not present locally in this repo"
        )
    else:
        logger.warning(
            "[Context] Effective POM resolved successfully but contained no "
            "recognized JDK property or maven-compiler-plugin release either"
        )
    return result


def detect_required_jdk(project_path: Path) -> Optional[str]:
    """
    Determine which JDK major version this Maven project needs to build,
    by inspecting pom.xml <properties> and the maven-compiler-plugin config
    across EVERY pom.xml in the tree, and returning the highest version
    found.

    Why "highest" and not "first found": a Maven reactor build (multi-module
    repo) runs every module under a single JVM. A parent/aggregator pom
    commonly declares a baseline compiler version (e.g.
    maven.compiler.source=11) that individual child modules can — and often
    do — override to a higher version via their own maven-compiler-plugin
    <configuration><release> (e.g. a module using newer language features
    needs release 17). A JDK N install can always compile --release <=N, but
    never --release >N, so the JVM selected for the whole build must satisfy
    the highest release any module requests — picking the first pom's value
    (which is often the parent's lower baseline) causes builds to fail with
    "release version X not supported" on any module that overrides upward,
    even though the registry/JAVA_HOME selection appeared correct for the
    (wrong) version that got detected.

    Returns a normalized major-version string (e.g. "17"), or None if no
    version signal could be found anywhere in the project (including via
    the effective-pom fallback described below).
    """
    all_poms = sorted(project_path.rglob("pom.xml"))
    if not all_poms:
        logger.warning(
            f"[Context] No pom.xml files found under {project_path} — "
            "cannot detect required JDK"
        )
        return None

    logger.info(
        f"[Context] Scanning {len(all_poms)} pom.xml file(s) under "
        f"{project_path} for required JDK version..."
    )

    highest: Optional[int] = None
    highest_str: Optional[str] = None

    for pom_path in all_poms:
        root = _parse_pom(pom_path)
        if root is None:
            continue

        found_in_pom = _check_root_for_jdk(root, pom_path.name)

        if found_in_pom:
            try:
                found_int = int(found_in_pom)
            except ValueError:
                continue
            if highest is None or found_int > highest:
                highest = found_int
                highest_str = found_in_pom

    if highest_str:
        logger.info(
            f"[Context] Required JDK for reactor build: {highest_str} "
            f"(highest across {len(all_poms)} pom.xml file(s))"
        )
        return highest_str

    # Nothing declared literally in any pom.xml on disk — this is the common
    # case for Spring Boot (and similar) projects that inherit their Java
    # version from a remote/.m2-cached parent POM instead of declaring it
    # locally. Resolve the effective (fully-inherited) POM via Maven itself
    # rather than reporting the project's JDK as unknown.
    logger.info(
        f"[Context] No literal JDK signal found in any of the {len(all_poms)} "
        "local pom.xml file(s) — trying effective-pom resolution "
        "(handles versions inherited from a remote/.m2-cached parent POM)..."
    )
    effective = _detect_required_jdk_via_effective_pom(project_path)
    if effective:
        return effective

    logger.warning(
        "[Context] Could not determine required JDK — no signal found in "
        "any local pom.xml, and effective-pom resolution found none either. "
        "required_jdk will be None for this run."
    )
    return None


# ── Transitive detection via mvn dependency:tree ──────────────────────────────

def _find_transitive_introducer(
    project_path: Path,
    group_id: str,
    artifact_id: str,
    maven_heap_mb: int = _DEFAULT_MAVEN_HEAP_MB,
) -> Optional[str]:
    """
    Run `mvn dependency:tree` to find which direct dependency pulls in
    the transitive dep. Returns the introducer artifact ID or None.
    Uses offline mode first (fast), falls back to online (slow).
    maven_heap_mb: per-JVM heap cap applied via MAVEN_OPTS (see
        _build_mvn_env); 0 disables the cap.
    """
    ga = f"{group_id}:{artifact_id}"

    for extra_args in [["--offline"], []]:
        try:
            result = subprocess.run(
                ["mvn", "dependency:tree", "-Dverbose", "-DincludeArtifactIds=" + artifact_id]
                + extra_args,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(project_path),
                env=_build_mvn_env(maven_heap_mb),
                start_new_session=True,  # isolate into its own process group
                                          # (see _detect_required_jdk_via_effective_pom)
            )
            output = result.stdout

            # Parse lines like:
            # [INFO] +- org.springframework.boot:spring-boot-starter:jar:3.2.5:compile
            # [INFO] |  \- org.springframework:spring-context:jar:5.3.31:compile
            lines = output.splitlines()
            for i, line in enumerate(lines):
                if artifact_id in line and ga not in line:
                    # Walk back up the tree to find the direct parent
                    indent = len(line) - len(line.lstrip())
                    for prev in reversed(lines[:i]):
                        prev_indent = len(prev) - len(prev.lstrip())
                        if prev_indent < indent:
                            # Extract artifact ID from the tree line
                            m = re.search(r"[\+\\|]\-\s+[\w\.\-]+:([\w\.\-]+):", prev)
                            if m:
                                return m.group(1)
                            break
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    return None


# ── Java source scanning ──────────────────────────────────────────────────────

def _package_prefix_for_group(group_id: str) -> Optional[str]:
    """Return the Java package prefix to search for, given a Maven group ID."""
    # Exact match first
    if group_id in _GROUP_TO_PACKAGE:
        return _GROUP_TO_PACKAGE[group_id]
    # Prefix match
    for key, pkg in _GROUP_TO_PACKAGE.items():
        if group_id.startswith(key):
            return pkg
    # Fallback: use group_id itself as package prefix (works for many libs)
    return group_id.replace("-", ".")


def _scan_java_files_javalang(
    project_path: Path,
    package_prefix: str,
    max_files: int = 20,
) -> list[str]:
    """
    Use javalang AST parser to find .java files that import from package_prefix.
    Returns relative paths from project_path.
    Falls back to grep on JavaSyntaxError.
    """
    try:
        import javalang  # type: ignore
    except ImportError:
        logger.debug("[Context] javalang not installed — using grep fallback")
        return _scan_java_files_grep(project_path, package_prefix, max_files)

    matches: list[str] = []

    for java_file in project_path.rglob("*.java"):
        if len(matches) >= max_files:
            break
        # Skip test files to keep context focused on production code
        if "/test/" in str(java_file) or "\\test\\" in str(java_file):
            continue

        try:
            source = java_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # Fast pre-filter before parsing
        if package_prefix not in source:
            continue

        try:
            tree = javalang.parse.parse(source)
            for _, node in tree:
                if isinstance(node, javalang.tree.Import):
                    if node.path and node.path.startswith(package_prefix):
                        rel = str(java_file.relative_to(project_path))
                        if rel not in matches:
                            matches.append(rel)
                        break
        except Exception:
            # javalang fails on Java 17+ syntax (records, sealed classes, etc.)
            # Fall back to grep for this file
            if re.search(rf"import\s+{re.escape(package_prefix)}", source):
                rel = str(java_file.relative_to(project_path))
                if rel not in matches:
                    matches.append(rel)

    return matches


def _scan_java_files_grep(
    project_path: Path,
    package_prefix: str,
    max_files: int = 20,
) -> list[str]:
    """
    Grep fallback: find .java files containing `import <package_prefix>`.
    """
    try:
        result = subprocess.run(
            ["grep", "-rl", "--include=*.java",
             f"import {package_prefix}", str(project_path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        paths = result.stdout.strip().splitlines()
        # Filter out test files
        paths = [p for p in paths if "/test/" not in p and "\\test\\" not in p]
        return [
            str(Path(p).relative_to(project_path))
            for p in paths[:max_files]
            if Path(p).is_file()
        ]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


# ── Calling code snippet builder ───────────────────────────────────────────────

def _build_calling_code_snippet(
    project_path: Path,
    calling_files: list[str],
    max_chars: int = 2000,
) -> str:
    """
    Read the calling Java files and concatenate their content into a single
    snippet for the AI Reasoning prompt.

    Each file is prefixed with a header showing its relative path so Claude
    knows which file it is looking at. Total output is capped at max_chars
    so we never blow the context window.

    Format:
      // --- src/main/java/com/example/Service.java ---
      <file content>
    """
    if not calling_files:
        return ""

    parts: list[str] = []
    total = 0

    for rel_path in calling_files:
        if total >= max_chars:
            break

        file_path = project_path / rel_path
        if not file_path.exists():
            # rglob fallback — relative path may be platform-mismatched
            matches = list(project_path.rglob(Path(rel_path).name))
            if not matches:
                continue
            file_path = matches[0]

        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        header = f"// --- {rel_path} ---\n"
        remaining = max_chars - total
        trimmed = source[: remaining - len(header)]
        if len(source) > len(trimmed):
            trimmed += "\n// ... (truncated)"

        block = header + trimmed
        parts.append(block)
        total += len(block)

    return "\n\n".join(parts)


# ── Main context resolution ───────────────────────────────────────────────────

def locate_dependency(
    project_path: Path,
    group_id: str,
    artifact_id: str,
    current_version: str,
) -> tuple[PomLocation, list[str]]:
    """
    Locate a dependency in the project and find its calling Java files.

    Returns:
      (PomLocation, list_of_calling_file_paths_relative_to_project_root)
    """
    all_poms = sorted(project_path.rglob("pom.xml"))
    logger.debug(f"[Context] Found {len(all_poms)} pom.xml file(s)")

    # ── Step 1: search all poms for a direct declaration ─────────────────────
    direct_match: Optional[dict] = None

    for pom_path in all_poms:
        match = _find_dep_in_pom(pom_path, group_id, artifact_id)
        if match:
            # Resolve which pom declares the property if version is ${prop}
            if match["version_property"]:
                prop_pom = _find_property_pom(all_poms, match["version_property"], project_path)
                match["property_defined_in"] = prop_pom

            # Make path relative to project root
            try:
                rel_pom = str(pom_path.relative_to(project_path))
            except ValueError:
                rel_pom = str(pom_path)
            match["pom_file"] = rel_pom

            direct_match = match
            break  # stop at first pom that declares it

    # ── Step 2: build PomLocation ─────────────────────────────────────────────
    if direct_match:
        version_label = direct_match["version_property"] or current_version
        pom_location = PomLocation(
            pom_file=direct_match["pom_file"],
            line_number=direct_match.get("line_number"),
            is_direct=True,
            version_property=direct_match["version_property"],
            property_defined_in=direct_match.get("property_defined_in"),
        )
        logger.info(
            f"[Context] {artifact_id} → {direct_match['pom_file']} "
            f"(direct, {version_label})"
        )
    else:
        # Transitive — not declared in any pom directly
        introducer = _find_transitive_introducer(project_path, group_id, artifact_id)
        via = f"via {introducer}" if introducer else "transitive (introducer unknown)"

        # Use root pom as the reference file for ADR's dependencyManagement pin
        root_pom = next(
            (str(p.relative_to(project_path)) for p in all_poms
             if p.parent == project_path),
            str(all_poms[0].relative_to(project_path)) if all_poms else "pom.xml",
        )
        pom_location = PomLocation(
            pom_file=root_pom,
            line_number=None,
            is_direct=False,
            version_property=None,
            property_defined_in=None,
        )
        logger.info(f"[Context] {artifact_id} → transitive {via}")

    # ── Step 3: find calling Java files ──────────────────────────────────────
    pkg_prefix = _package_prefix_for_group(group_id)
    calling_files: list[str] = []

    if pkg_prefix:
        calling_files = _scan_java_files_javalang(project_path, pkg_prefix)

    logger.info(
        f"[Context] {len(calling_files)} calling file(s) found for {artifact_id}"
    )

    return pom_location, calling_files


def locate_all_groups(
    project_path: Path,
    groups: list[dict],
) -> list[dict]:
    """
    Run context resolution for every resolved group.
    Enriches each group dict with 'pom_location' and 'calling_files'.
    """
    enriched: list[dict] = []

    for group in groups:
        parsed = group["parsed"]
        group_id = parsed["group_id"]
        artifact_id = parsed["artifact_id"]
        current_version = parsed["current_version"]

        try:
            pom_location, calling_files = locate_dependency(
                project_path, group_id, artifact_id, current_version
            )
        except Exception as exc:
            logger.warning(
                f"[Context] Failed to locate {artifact_id}: {exc} — using defaults"
            )
            pom_location = PomLocation(
                pom_file="pom.xml",
                line_number=None,
                is_direct=False,
                version_property=None,
                property_defined_in=None,
            )
            calling_files = []
            calling_code_snippet = ""  # no files found in fallback path

        # Build the actual source snippet for the AI Reasoning prompt.
        # _calling_code_snippet is what Claude reads — file paths alone are not enough.
        calling_code_snippet = _build_calling_code_snippet(project_path, calling_files)
        if calling_code_snippet:
            logger.debug(
                f"[Context] Built calling code snippet for {parsed['artifact_id']}: "
                f"{len(calling_code_snippet)} chars across {len(calling_files)} file(s)"
            )

        enriched_group = dict(group)
        enriched_group["pom_location"] = pom_location
        enriched_group["calling_files"] = calling_files
        enriched_group["_calling_code_snippet"] = calling_code_snippet
        enriched.append(enriched_group)

    return enriched


# ── LangGraph node ────────────────────────────────────────────────────────────

def context_node(state: AgentState, project_path: str) -> AgentState:
    """
    LangGraph node: context.

    Reads:  state["_resolved_groups"]
    Writes: state["_context_groups"]  (groups enriched with pom_location + calling_files)
            state["audit_trail"]
    """
    groups: list[dict] = state.get("_resolved_groups", [])  # type: ignore[attr-defined]

    if not groups:
        logger.warning("[Context] No resolved groups in state — nothing to locate")
        state["status"] = "skipped"
        state["skip_reason"] = "No resolved groups to locate"
        state["audit_trail"].append({"node": "context", "status": "skipped"})
        return state

    path = Path(project_path)
    enriched = locate_all_groups(path, groups)

    required_jdk = detect_required_jdk(path)
    state["required_jdk"] = required_jdk  # type: ignore[typeddict-item]
    if required_jdk:
        logger.info(f"[Context] Project requires JDK {required_jdk}")
    else:
        logger.warning(
            "[Context] required_jdk is None for this run — downstream agents "
            "(AI Reasoning, JDK registry selection) will treat this project's "
            "JDK as unknown"
        )

    state["_context_groups"] = enriched  # type: ignore[typeddict-unknown-key]
    state["audit_trail"].append({
        "node": "context",
        "status": "ok",
        "groups": len(enriched),
        "calling_files_total": sum(len(g.get("calling_files", [])) for g in enriched),
        "required_jdk": required_jdk,
    })

    return state