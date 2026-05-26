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

import re
import subprocess
from pathlib import Path
from typing import Optional
from xml.etree import ElementTree as ET

from loguru import logger

from state import AgentState, PomLocation

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
) -> Optional[str]:
    """
    Search all pom files to find which one declares a given ${property}.
    Returns the pom path string or None.
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
                return str(pom_path)
    return None


# ── Transitive detection via mvn dependency:tree ──────────────────────────────

def _find_transitive_introducer(
    project_path: Path,
    group_id: str,
    artifact_id: str,
) -> Optional[str]:
    """
    Run `mvn dependency:tree` to find which direct dependency pulls in
    the transitive dep. Returns the introducer artifact ID or None.
    Uses offline mode first (fast), falls back to online (slow).
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
                prop_pom = _find_property_pom(all_poms, match["version_property"])
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

    state["_context_groups"] = enriched  # type: ignore[typeddict-unknown-key]
    state["audit_trail"].append({
        "node": "context",
        "status": "ok",
        "groups": len(enriched),
        "calling_files_total": sum(len(g.get("calling_files", [])) for g in enriched),
    })

    return state