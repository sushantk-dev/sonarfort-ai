#!/usr/bin/env python3
"""
================================================================================
  Application: ADR — Automated Dependency Remediation (Fortify Edition)
  Process    : Maven pom.xml CVE Scanner, Auto-Fixer, and Git Committer
                 Tailored for the FortifyAI pipeline — invoked by adr_fix.py
  Version    : 8.4-fortify
================================================================================

HOW IT WORKS
  Phase 1   PARSE         Extract every direct dependency from each pom.xml.
                          Uses 'mvn help:effective-pom' when Maven is available
                          to fully resolve parent-POM properties and BOM-managed
                          versions (matches what Fortify SCA actually scans).
                          Falls back to raw pom.xml parsing if Maven unavailable.
  Phase 1b  TRANSITIVE    Run 'mvn dependency:tree' once on the root pom to
                          collect the full resolved dependency tree across all
                          modules (test/provided/system scopes excluded by
                          default; use --include-scopes to override).
  Phase 3   REPORT        Colour-coded vulnerability report with per-CVE cards
                          and PDF output.
                          NOTE: CVE detection and safe-version resolution are
                          handled upstream by Fortify SCA + the FortifyAI
                          pipeline (triage → version_resolver). ADR receives
                          findings with pre-resolved safe versions — no
                          additional CVE scanning is performed here.
  Phase 5   FIX           Auto-upgrade vulnerable direct deps in each module
                          pom.xml. Transitive deps are pinned via
                          <dependencyManagement> in the root pom. A
                          timestamped backup is created before any write.
  Phase 5b  BUILD CHECK   Validate changes by running 'mvn clean install
                          -DskipTests'. Automatically reverts all pom.xml
                          files from backups if the build fails.
  Phase 5c  GIT COMMIT    Create a feature branch (feature/<FORTIFY-ID>_fortify_fix
                          _<date>), stage all modified pom files, and commit
                          with a structured message. Optionally push with --push.

FORTIFY INTEGRATION
  This script is invoked by adr_fix.py in the FortifyAI pipeline:
    python adr_fortify.py <project_path> \\
        --commit FORTIFY-<vuln_id_8chars> \\
        --push \\
        --target-versions '{"groupId:artifactId": {"safe_version": "x.y.z", ...}}'

  Branch naming: feature/FORTIFY-<id>_fortify_fix_<YYYYMMDD>
  Exit 0  → fix applied, build passed, branch pushed
  Non-zero → build failed; ADR rolls back all pom.xml changes automatically

USAGE
  python adr_fortify.py <path>            (directory or single pom.xml)

  Modes (one required):
    --scan                               Scan & report only — no files modified
    --fix                                Apply fixes + Maven build (no git)
    --commit FORTIFY-<id>                Apply fixes + Maven build + git commit
    --commit FORTIFY-<id> --push         As above, then push the feature branch

  Options:
    --mvn /path/to/mvn                   Path to mvn executable (auto-detected if omitted)
    --skip spring-core,spring-boot       Artifact IDs to exclude from auto-fix
    --include-scopes test,provided       Include additional scopes in scanning
    --target-versions JSON               JSON map of {groupId:artifactId: {safe_version,...}}
                                         injected automatically by adr_fix.py
    --skipTests true|false               Skip Maven tests during build verification
                                         (default: false — tests run by default)

REQUIREMENTS
  Python 3.6+  --  no third-party packages needed
  Maven (mvn)  --  required for transitive dependency scanning
================================================================================
"""

import re
import os
import sys
import json
import time
import shutil
import signal
import ctypes
import getpass
import argparse
import subprocess
from datetime import datetime
from xml.etree import ElementTree as ET
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed

# ──────────────────────────────────────────────────────────────────────────────
# ANSI COLOURS  (auto-disabled if terminal does not support VT sequences)
# ──────────────────────│───────────────────────────────────────────────────────
def _ansi_supported() -> bool:
    """Returns True only when the terminal actively supports ANSI VT sequences."""
    if sys.platform == "win32":
        try:
            handle = ctypes.windll.kernel32.GetStdHandle(-11)
            mode   = ctypes.c_ulong(0)
            if not ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                return False
            if mode.value & 0x0004:
                return True
            # Try to enable it
            ctypes.windll.kernel32.SetConsoleMode(handle, mode.value | 0x0004)
            return True
        except Exception:
            return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


_USE_COLOR = _ansi_supported()


class C:
    RED     = "\033[91m"  if _USE_COLOR else ""
    YELLOW  = "\033[93m"  if _USE_COLOR else ""
    CYAN    = "\033[96m"  if _USE_COLOR else ""
    GREEN   = "\033[92m"  if _USE_COLOR else ""
    WHITE   = "\033[97m"  if _USE_COLOR else ""
    GRAY    = "\033[90m"  if _USE_COLOR else ""
    BOLD    = "\033[1m"   if _USE_COLOR else ""
    RESET   = "\033[0m"   if _USE_COLOR else ""


SEV_RANK = {"CRITICAL": 5, "HIGH": 4, "MODERATE": 3, "MEDIUM": 3, "LOW": 2, "INFO": 1}

VERSION          = "8.4-fortify"

# NOTE: OSV/NVD/GHSA/OSS scanning removed — CVE detection is handled upstream
# by Fortify SCA. ADR's role here is pom.xml patching and Maven build validation.

PROPERTY_REF_RE   = re.compile(r"\$\{([^}]+)\}")
# Matches dependency lines in 'mvn dependency:tree -Dverbose' output, e.g.:
#   [INFO] +- log4j:log4j:jar:1.2.17:compile
#   [INFO] |  \- io.netty:netty-handler:jar:4.1.100.Final:compile
#   [INFO] +- org.apache.hive:hive-exec:jar:core:4.0.1:compile  (with classifier)
# Format: groupId:artifactId:type[:classifier]:version:scope
# Classifiers start with a letter; versions start with a digit — used to distinguish them.
# Scopes excluded from scanning — matches Fortify SCA default behaviour:
#   test     : never deployed to production
#   provided : managed by container/runtime, not bundled in artifact
#   system   : resolved from local filesystem, not Maven Central
EXCLUDED_SCOPES = {"test", "provided", "system"}

# ── Version comparison utility ────────────────────────────────────────────────
# Used by apply_transitive_fixes and the report to compare version strings.
# Kept as a standalone utility after Phase 3 (min-safe-version lookup) was
# removed — the function itself has no external dependencies.
@lru_cache(maxsize=16384)
def _version_tuple(v: str):
    """Converts a version string to a comparable tuple of ints, e.g. '2.17.3' -> (2,17,3)."""
    return tuple(int(x) for x in re.findall(r"\d+", v))


# ── Vendor Bundle Expansion ───────────────────────────────────────────────────
# Some libraries ship "vendor" JARs that re-bundle a third-party dependency at
# a fixed version.  CVEs are published against the underlying library, not the
# wrapper, so OSV/NVD return no hits when queried with the bundle coordinates.
# Each entry: (regex on artifactId capturing version segments, groupId, [artifactIds])
_VENDOR_BUNDLE_EXPANSIONS = [
    (
        re.compile(r'^beam-vendor-grpc-(\d+)_(\d+)_(\d+)$'),
        "io.grpc",
        ["grpc-core", "grpc-netty-shaded", "grpc-stub", "grpc-protobuf"],
    ),
]


def _expand_vendor_bundles(deps: list) -> list:
    """Return additional dep entries for known vendor-bundle artifacts.

    Expands each matched bundle into its underlying library coordinates so
    OSV/NVD can find CVEs against the real package.  Each added dep carries a
    ``vendor_bundle_dep`` key referencing the original wrapper so findings can
    be remapped back after scanning.
    """
    extra = []
    seen_keys = {(d["groupId"], d["artifactId"], d["version"]) for d in deps}
    for dep in deps:
        aid = dep.get("artifactId", "")
        for pattern, grp_id, art_ids in _VENDOR_BUNDLE_EXPANSIONS:
            m = pattern.match(aid)
            if not m:
                continue
            bundled_version = ".".join(m.groups())
            for bundled_aid in art_ids:
                key = (grp_id, bundled_aid, bundled_version)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                extra.append({
                    "groupId":           grp_id,
                    "artifactId":        bundled_aid,
                    "version":           bundled_version,
                    "raw_version":       bundled_version,
                    "prop_name":         None,
                    "transitive":        True,
                    "vendor_bundle_dep": dep,
                })
    return extra


def _remap_vendor_bundle_findings(findings: list) -> list:
    """Fold expanded-bundle findings back onto their wrapper artifact.

    Any finding whose dep has a ``vendor_bundle_dep`` key is merged back under
    the original wrapper dep.  Vulns from all expansions of the same wrapper
    are combined into one finding, duplicates removed, and severity escalated
    to the highest found.  A ``bundled_via`` list records which underlying
    packages carried the CVEs.  Non-bundle findings pass through unchanged.
    """
    normal  = [f for f in findings if "vendor_bundle_dep" not in f["dep"]]
    bundles = [f for f in findings if "vendor_bundle_dep" in f["dep"]]

    if not bundles:
        return normal

    merged: dict = {}
    for f in bundles:
        wrapper = f["dep"]["vendor_bundle_dep"]
        bkey = f"{wrapper['groupId']}:{wrapper['artifactId']}:{wrapper['version']}"
        via  = f"{f['dep']['groupId']}:{f['dep']['artifactId']}:{f['dep']['version']}"

        if bkey not in merged:
            merged[bkey] = {
                "dep":         wrapper,
                "vulns":       list(f["vulns"]),
                "severity":    f["severity"],
                "bundled_via": [via],
            }
            for opt in ("safe_version", "latest_version", "module"):
                if opt in f:
                    merged[bkey][opt] = f[opt]
        else:
            mf = merged[bkey]
            existing_ids = {v.get("id") for v in mf["vulns"]}
            for v in f["vulns"]:
                if v.get("id") not in existing_ids:
                    mf["vulns"].append(v)
                    existing_ids.add(v.get("id"))
            if via not in mf["bundled_via"]:
                mf["bundled_via"].append(via)
            if SEV_RANK.get(f["severity"], 0) > SEV_RANK.get(mf["severity"], 0):
                mf["severity"] = f["severity"]

    return normal + list(merged.values())


DEP_TREE_LINE_RE  = re.compile(
    r'\[INFO\]\s+[+\\\| ]*[-\\+]\s+'
    r'([A-Za-z0-9_.${}\-]+):([A-Za-z0-9_.${}\-]+):[A-Za-z0-9_.${}\-]+'  # gid:aid:type
    r':(?:[A-Za-z][A-Za-z0-9_.\-]*:)?'   # optional classifier (starts with a letter, not a digit)
    r'([A-Za-z0-9_.${}\-]+):'            # version — captured
    r'([A-Za-z0-9_.\-]+)'                # scope — captured so we can filter
)

# ────────────────────  ─────────────────────────────────  ───────────────────────
# DISPLAY HELPERS
# ─────────────────────────────────────────────────│────────────────────────────

def banner():
    print()
    print(f"{C.CYAN}{'=' * 68}{C.RESET}")
    print(f"{C.CYAN}  ADR — Automated Dependency Remediation  v{VERSION}{C.RESET}")
    print(f"{C.CYAN}  Fortify Edition | pom.xml Patcher + Maven Build Validator{C.RESET}")
    print(f"{C.CYAN}{'=' * 68}{C.RESET}")
    print(f"  {C.YELLOW}⚠  Script-generated fix — ensure QA validates all jars before UAT / Production.{C.RESET}")
    print()


def section(title: str):
    pad = "-" * max(1, 58 - len(title))
    print(f"\n{C.CYAN}  -- {title} {pad}{C.RESET}")



# ──────────────────────────────────────────────────────────────────────────────
# PHASE 1 -- PARSE pom.xml
# Extracts all dependencies and tracks whether each version is defined directly
# or via a property reference, so fixes are applied at the correct location.
# ──────────────────────────────────────────────────────────────────────────────

NS = {"m": "http://maven.apache.org/POM/4.0.0"}


def _text(el, tag: str) -> str:
    child = el.find(f"m:{tag}", NS)
    if child is None:
        child = el.find(tag)
    return (child.text or "").strip() if child is not None else ""


def resolve_properties(content: str) -> dict:
    """Returns {prop_name: value} from the <properties> section."""
    props = {}
    try:
        root = ET.fromstring(content)
        for search in ("m:properties", "properties"):
            el = root.find(search, NS) if "m:" in search else root.find(search)
            if el is not None:
                for child in el:
                    tag = child.tag.split("}")[-1]
                    props[tag] = (child.text or "").strip()
                break
    except ET.ParseError:
        pass
    return props


def expand(value: str, props: dict) -> str:
    return PROPERTY_REF_RE.sub(lambda m: props.get(m.group(1), m.group(0)), value)


def parse_dependencies(content: str, extra_props: dict = None) -> tuple:
    """
    Returns (deps, props).
    Each dep dict:
      groupId, artifactId, version (resolved), raw_version,
      prop_name  -- the property key if version came from ${prop}, else None

    extra_props: optional parent/root pom properties used as fallback when a
    ${property} reference cannot be resolved from this pom's own <properties>.
    This handles the common case where a submodule declares a version like
    ${apache.beam.version} that is only defined in the parent pom.xml.
    """
    props = resolve_properties(content)
    # Merge extra_props (parent pom) as lower-priority fallback — local props win
    if extra_props:
        props = {**extra_props, **props}

    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        print(f"{C.RED}[ERROR] pom.xml is not valid XML: {exc}{C.RESET}")
        sys.exit(1)

    all_deps = (
        list(root.iter("{http://maven.apache.org/POM/4.0.0}dependency"))
        + list(root.iter("dependency"))
    )

    deps, seen = [], set()
    for dep in all_deps:
        gid = _text(dep, "groupId")
        aid = _text(dep, "artifactId")
        raw = _text(dep, "version")
        if not gid or not aid or not raw:
            continue
        # Skip scopes that Fortify SCA excludes by default
        scope = (_text(dep, "scope") or "compile").strip().lower()
        if scope in EXCLUDED_SCOPES:
            continue
        resolved = expand(raw, props)
        if not resolved or resolved.startswith("${"):
            continue
        key = (gid, aid, resolved)
        if key in seen:
            continue
        seen.add(key)
        prop_match = PROPERTY_REF_RE.fullmatch(raw.strip())
        deps.append({
            "groupId":    gid,
            "artifactId": aid,
            "version":    resolved,
            "raw_version": raw,
            "prop_name":  prop_match.group(1) if prop_match else None,
        })

    return deps, props



_QA_STEPS = [
    "1.  Run  mvn clean verify  on the feature branch to confirm no build breaks.",
    "2.  Raise a Pull Request from the feature branch into {base_branch}.",
    "3.  Assign for peer-review -- pay attention to transitive dependency pins.",
    "4.  Ensure QA validates all patched JARs before UAT / Production promote.",
    "5.  Track any SKIP items as manual-action tickets.",
]


# ────────────────────────────────│──────────────│──────────────────────────────
# PHASE 5 -- APPLY FIXES
# ──────────────────────────────────────────────────────────────────────────────

def _upgrade_version(content: str, dep: dict, new_version: str) -> str:
    """
    Upgrades a dependency version in raw pom.xml content.
    Case A: version from a property  -> updates the property value
    Case B: version hardcoded inline -> updates the <version> tag in context
    Returns updated content (unchanged if no pattern matched).
    """
    flags = re.DOTALL

    # Case A: version is a property reference e.g. ${jackson.version}
    if dep["prop_name"]:
        prop    = re.escape(dep["prop_name"])
        pattern = rf"(<{prop}>){re.escape(dep['version'])}(</{prop}>)"
        new     = re.sub(pattern, rf"\g<1>{new_version}\g<2>", content, flags=flags)
        if new != content:
            return new

    # Case B: version hardcoded — match using groupId + artifactId as context
    gid = re.escape(dep["groupId"])
    aid = re.escape(dep["artifactId"])
    ver = re.escape(dep["version"])

    # groupId before artifactId (standard order)
    pattern = (rf"(<groupId>{gid}</groupId>\s*"
               rf"<artifactId>{aid}</artifactId>\s*"
               rf"<version>){ver}(</version>)")
    new = re.sub(pattern, rf"\g<1>{new_version}\g<2>", content, flags=flags)
    if new != content:
        return new

    # artifactId before groupId (less common but valid)
    pattern = (rf"(<artifactId>{aid}</artifactId>\s*"
               rf"<groupId>{gid}</groupId>\s*"
               rf"<version>){ver}(</version>)")
    return re.sub(pattern, rf"\g<1>{new_version}\g<2>", content, flags=flags)


def apply_transitive_fixes(root_content: str, all_findings: list) -> tuple:
    """
    For each unique vulnerable transitive dependency that has a known safe version,
    injects or updates a <dependencyManagement> entry in the root pom.xml content.
    This pins the transitive version project-wide across all modules.

    Returns (updated_content, injected_list, already_ok_list, no_safe_list).
    """
    # Deduplicate by (gid, aid) across all modules — pick highest safe version
    trans_map = {}
    for f in all_findings:
        dep  = f["dep"]
        if not dep.get("transitive") and not dep.get("_needs_depmanagement_pin"):
            continue
        safe = f.get("safe_version", "")
        if not safe:
            continue
        key = (dep["groupId"], dep["artifactId"])
        existing = trans_map.get(key)
        if not existing or _version_tuple(safe) > _version_tuple(existing["safe"]):
            trans_map[key] = {"gid": dep["groupId"], "aid": dep["artifactId"],
                              "ver": dep["version"], "safe": safe}

    no_safe = sorted({
        f"{f['dep']['groupId']}:{f['dep']['artifactId']}  {f['dep']['version']}  (no safe version found)"
        for f in all_findings
        if f["dep"].get("transitive") and not f.get("safe_version")
    })

    if not trans_map:
        return root_content, [], [], no_safe

    content   = root_content
    injected  = []
    already_ok = []

    def _dep_xml(gid, aid, ver, indent="            "):
        return (f"{indent}<dependency>\n"
                f"{indent}    <groupId>{gid}</groupId>\n"
                f"{indent}    <artifactId>{aid}</artifactId>\n"
                f"{indent}    <version>{ver}</version>\n"
                f"{indent}</dependency>")

    for (gid, aid), info in trans_map.items():
        safe  = info["safe"]
        cur   = info["ver"]
        label = f"{gid}:{aid}  {cur} -> {safe}"

        # Is this dep already present anywhere inside <dependencyManagement>?
        in_dm = bool(re.search(
            rf'<dependencyManagement>.*?<groupId>\s*{re.escape(gid)}\s*</groupId>\s*'
            rf'<artifactId>\s*{re.escape(aid)}\s*</artifactId>',
            content, re.DOTALL))

        if in_dm:
            # Extract the exact version string currently in the DM entry (may be ${prop} or literal)
            dm_ver_m = re.search(
                rf'<dependencyManagement>.*?'
                rf'<groupId>\s*{re.escape(gid)}\s*</groupId>\s*'
                rf'<artifactId>\s*{re.escape(aid)}\s*</artifactId>.*?'
                rf'<version>([^<]+)</version>',
                content, re.DOTALL)
            dm_ver_raw = dm_ver_m.group(1).strip() if dm_ver_m else cur

            # Detect if the DM entry uses a property reference e.g. ${log4j.version}
            prop_m = PROPERTY_REF_RE.fullmatch(dm_ver_raw)
            prop_in_dm = prop_m.group(1) if prop_m else None

            if prop_in_dm:
                # Resolve current property value to check if it's already safe
                prop_val_m = re.search(
                    rf'<{re.escape(prop_in_dm)}>([^<]+)</{re.escape(prop_in_dm)}>',
                    content)
                current_prop_val = prop_val_m.group(1).strip() if prop_val_m else cur
                if current_prop_val == safe:
                    already_ok.append(f"{gid}:{aid}  (property ${{{prop_in_dm}}} already at {safe})")
                    continue
                # Update the property value — preserves the ${...} reference in DM
                new = _upgrade_version(content, {"groupId": gid, "artifactId": aid,
                                                  "version": current_prop_val,
                                                  "prop_name": prop_in_dm}, safe)
                if new != content:
                    content = new
                    injected.append(
                        f"[UPDATED property ${{{prop_in_dm}}}] {label}")
                else:
                    injected.append(f"[MANUAL] {label}  (update ${{{prop_in_dm}}} manually)")
            else:
                # Literal version in DM — check if already safe
                if dm_ver_raw == safe:
                    already_ok.append(f"{gid}:{aid}  (already at {safe} in dependencyManagement)")
                    continue
                # Update the literal version using _upgrade_version
                new = _upgrade_version(content, {"groupId": gid, "artifactId": aid,
                                                  "version": dm_ver_raw, "prop_name": None}, safe)
                if new != content:
                    content = new
                    injected.append(f"[UPDATED in depMgmt] {label}")
                else:
                    injected.append(f"[MANUAL] {label}  (update manually in dependencyManagement)")
        else:
            new_dep = _dep_xml(gid, aid, safe)

            # Inject before closing </dependencies> inside <dependencyManagement>
            dm_close = re.search(
                r'(<dependencyManagement>.*?)([ \t]*</dependencies>\s*</dependencyManagement>)',
                content, re.DOTALL)
            if dm_close:
                insert_at = dm_close.start(2)
                content   = content[:insert_at] + "\n" + new_dep + "\n" + content[insert_at:]
                injected.append(f"[ADDED to depMgmt]   {label}")
            else:
                # No <dependencyManagement> at all — create one before </project>
                dm_block = ("    <dependencyManagement>\n"
                            "        <dependencies>\n"
                            f"{new_dep}\n"
                            "        </dependencies>\n"
                            "    </dependencyManagement>\n")
                content = re.sub(r'(</project>)', dm_block + r'\1', content)
                injected.append(f"[ADDED new depMgmt]  {label}")

    return content, injected, already_ok, no_safe


def apply_fixes(content: str, findings: list) -> tuple:
    applied, skipped = [], []

    for f in findings:
        dep    = f["dep"]
        latest = f.get("safe_version", "")
        label  = f"{dep['groupId']}:{dep['artifactId']}  {dep['version']} -> {latest}"

        if dep.get("transitive"):
            # Transitive fixes are handled separately in apply_transitive_fixes()
            # on the root pom — skip here to avoid duplicate entries
            continue

        if not latest:
            skipped.append(f"{dep['groupId']}:{dep['artifactId']}  "
                           f"(Maven Central returned no version -- update manually)")
            continue
        if latest == dep["version"]:
            skipped.append(f"{label}  (already on latest)")
            continue

        new = _upgrade_version(content, dep, latest)
        if new != content:
            content = new
            applied.append(label)
        else:
            # Version literal not in this pom.xml — likely managed by a parent BOM or
            # ancestor property.  Flag it for dependencyManagement pinning instead of
            # reporting as unfixable.
            if dep["version"] not in content:
                dep["_needs_depmanagement_pin"] = True
            else:
                skipped.append(f"{label}  (pattern not matched -- update manually)")

    return content, applied, skipped


# ──────────────────────────────────────────────────────────────────────────────
# GIT AUTOMATION HELPERS
# ────────────────────────  ────────────  ────────────────────  ───────────────────

def _run_git(cmd: list, repo_root: str, desc: str) -> subprocess.CompletedProcess:
    """Executes a git command with basic logging."""
    pretty_cmd = " ".join(cmd)
    print(f"{C.GRAY}[GIT] {desc}: {pretty_cmd}{C.RESET}")
    try:
        result = subprocess.run(
            cmd,
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
        if result.stdout.strip():
            print(f"{C.GRAY}{result.stdout.strip()}{C.RESET}")
        return result
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() if exc.stderr else ""
        print(f"{C.RED}[GIT ERROR] {desc} failed ({stderr or exc}){C.RESET}")
        sys.exit(1)


def _find_git_root(path: str) -> str:
    """Returns the absolute git root directory for the provided path."""
    start = os.path.abspath(path)
    if os.path.isfile(start):
        start = os.path.dirname(start)
    try:
        result = subprocess.run(
            ["git", "-C", start, "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return ""


def _prepare_git_branch(repo_root: str, jira_id: str, base_branch_override: str = "") -> tuple:
    """Fetch origin, resolve base branch, pull, then create a new feature branch.
    Returns (branch_name, base_branch).
    NOTE: Call this BEFORE applying any file changes so the branch is the
    correct base for all modifications."""

    # When called from FortifyAI pipeline, jira_id is already the full branch
    # name (e.g. 'feature/fortify-fix-1697672-c6266fa8'). Use it verbatim.
    # For legacy/manual invocations with a plain JIRA ID, build the old format.
    if jira_id.startswith("feature/"):
        branch = jira_id
    else:
        today  = datetime.now().strftime("%Y%m%d")
        branch = f"feature/{jira_id}_fortify_fix_{today}"

    # fetch is best-effort — temp clones created by the pipeline may have no remote
    try:
        subprocess.run(
            ["git", "fetch", "origin"],
            cwd=repo_root, capture_output=True, text=True, timeout=30,
        )
    except Exception:
        pass

    # Use caller-supplied branch if provided, otherwise auto-detect
    if base_branch_override:
        base_branch = base_branch_override
    else:
        base_branch = None
        sym = subprocess.run(
            ["git", "symbolic-ref", "refs/remotes/origin/HEAD"],
            cwd=repo_root, capture_output=True, text=True,
        )
        if sym.returncode == 0 and sym.stdout.strip():
            base_branch = sym.stdout.strip().split("/")[-1]
        if not base_branch:
            for candidate in ("main", "master"):
                r = subprocess.run(
                    ["git", "rev-parse", "--verify", candidate],
                    cwd=repo_root, capture_output=True,
                )
                if r.returncode == 0:
                    base_branch = candidate
                    break
        if not base_branch:
            base_branch = "main"

    # checkout base branch — non-fatal if we're already on a detached HEAD or similar
    co = subprocess.run(
        ["git", "checkout", base_branch],
        cwd=repo_root, capture_output=True, text=True,
    )
    if co.returncode != 0:
        print(f"{C.YELLOW}[GIT] Could not checkout {base_branch} ({co.stderr.strip()}) — using current HEAD{C.RESET}")

    # pull — non-fatal (temp clone may have no remote)
    try:
        subprocess.run(
            ["git", "pull", "origin", base_branch],
            cwd=repo_root, capture_output=True, text=True, timeout=30,
        )
    except Exception:
        pass

    create = subprocess.run(
        ["git", "checkout", "-b", branch],
        cwd=repo_root, capture_output=True, text=True,
    )
    if create.returncode != 0:
        if "already exists" in (create.stderr or "").lower():
            _run_git(["git", "checkout", branch], repo_root, f"checkout existing {branch}")
        else:
            print(f"{C.RED}[GIT ERROR] Unable to create branch {branch}:{C.RESET} {create.stderr.strip()}")
            sys.exit(1)
    else:
        print(f"{C.GREEN}[GIT] Created branch {branch} from {base_branch}{C.RESET}")

    return branch, base_branch


def _finalize_git_changes(
        repo_root: str,
        pom_paths,           # str or list[str]
        jira_id: str,
        branch: str,
        base_branch: str = "main",
        push: bool = False,
        commit_subject: str = "",
        commit_body: str = "",
) -> dict:
    """Stages, commits, and optionally pushes the updated pom(s).
    Returns a dict with commit verification info."""
    if isinstance(pom_paths, str):
        pom_paths = [pom_paths]

    for pom_path in pom_paths:
        rel_path = os.path.relpath(pom_path, repo_root)
        _run_git(["git", "add", rel_path], repo_root, f"stage {rel_path}")

    if not commit_subject:
        commit_subject = f"{jira_id}: vulnerability fix - {datetime.now().strftime('%Y-%m-%d')}"

    # Build the full commit command with subject + body
    commit_cmd = ["git", "commit", "-m", commit_subject]
    if commit_body:
        commit_cmd += ["-m", commit_body]

    commit = subprocess.run(
        commit_cmd,
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    git_info = {
        "branch":      branch,
        "base_branch": base_branch,
        "message":     commit_subject,
        "body":        commit_body,
        "hash":        "",
        "full_hash":   "",
        "status":      "",
        "pushed":      False,
        "author":      "",
        "email":       "",
        "timestamp":   "",
        "remote_url":  "",
        "files_changed": [],
        "repo_root":   repo_root,
    }

    # Capture remote URL early (always available)
    try:
        ru = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=repo_root, capture_output=True, text=True,
        )
        git_info["remote_url"] = ru.stdout.strip()
    except Exception:
        pass

    if commit.returncode != 0:
        combined = ((commit.stdout or "") + (commit.stderr or "")).lower()
        if "nothing to commit" in combined or "nothing added to commit" in combined:
            print(f"{C.YELLOW}[GIT] No changes detected; skipping commit.{C.RESET}")
            git_info["status"] = "skipped (nothing to commit)"
        else:
            print(f"{C.RED}[GIT ERROR] Commit failed:{C.RESET} {(commit.stderr or commit.stdout or '').strip()}")
            git_info["status"] = "FAILED"
            sys.exit(1)
    else:
        print(f"{C.GREEN}[GIT] Commit created: {commit_subject}{C.RESET}")
        git_info["status"] = "committed"
        try:
            h = subprocess.run(
                ["git", "rev-parse", "--short", "HEAD"],
                cwd=repo_root, capture_output=True, text=True, check=True,
            )
            git_info["hash"] = h.stdout.strip()
        except Exception:
            pass
        # Capture full hash, author, email, timestamp, files changed
        try:
            log = subprocess.run(
                ["git", "log", "-1",
                 "--format=%H%n%ae%n%an%n%ci",
                 "HEAD"],
                cwd=repo_root, capture_output=True, text=True, check=True,
            )
            parts = log.stdout.strip().splitlines()
            if len(parts) >= 4:
                git_info["full_hash"]  = parts[0]
                git_info["email"]      = parts[1]
                git_info["author"]     = parts[2]
                git_info["timestamp"]  = parts[3]
            elif len(parts) == 3:
                git_info["full_hash"]  = parts[0]
                git_info["email"]      = parts[1]
                git_info["author"]     = parts[2]
        except Exception:
            pass
        try:
            diff = subprocess.run(
                ["git", "diff", "--name-only", "HEAD~1", "HEAD"],
                cwd=repo_root, capture_output=True, text=True,
            )
            git_info["files_changed"] = [
                f.strip() for f in diff.stdout.splitlines() if f.strip()
            ]
        except Exception:
            pass

    if push:
        _run_git(["git", "push", "-u", "origin", branch], repo_root, "push branch")
        git_info["pushed"] = True
        git_info["status"] = "committed + pushed"

    return git_info


# ──────────────────────────────────────────────────────────────────────────────
# MAVEN BUILD
# ──────────────────────────────────────────────────────────────────────────────

# Well-known Maven bin directories to try when 'mvn' is not on PATH
_MVN_FALLBACK_DIRS = [
    r"C:\Program Files\Apache\maven\bin",
    r"C:\Program Files\Maven\bin",
    r"C:\tools\maven\bin",
]


def _find_mvn() -> str:
    """Returns the mvn executable path. Checks PATH first, then fallback locations."""
    for candidate in ("mvn", "mvn.cmd"):
        found = shutil.which(candidate)
        if found:
            return found
    # Check fallback dirs
    for d in _MVN_FALLBACK_DIRS:
        for exe in ("mvn.cmd", "mvn"):
            full = os.path.join(d, exe)
            if os.path.isfile(full):
                return full
    return ""


def _kill_process_tree(pid: int) -> None:
    """Force-kills a process and all its children.
    On Windows, Maven's JVM child process survives a plain proc.kill() because
    the mvn.cmd batch script spawns java.exe as a separate process. taskkill /T
    kills the entire tree by PID."""
    try:
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                capture_output=True, timeout=10,
            )
        else:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
    except Exception:
        pass


def _run_maven_build(project_root: str, mvn_exe: str = "", skip_tests: bool = False) -> tuple:
    """Run 'mvn clean install' in project_root.
    Returns (success: bool | None, duration: float).
    None = maven not found (skipped).  False = build failed.  True = success.
    skip_tests: when True adds -DskipTests to the Maven command (tests are skipped).
    """
    if not mvn_exe:
        mvn_exe = _find_mvn()
    if not mvn_exe:
        print(f"  {C.YELLOW}[BUILD] Maven not found — skipping build verification.{C.RESET}")
        return None, 0.0

    mvn_cmd = [mvn_exe, "clean", "install", "--no-transfer-progress"]
    if skip_tests:
        mvn_cmd.append("-DskipTests")
        print(f"  {C.GRAY}[BUILD] Running mvn clean install -DskipTests ...{C.RESET}", flush=True)
    else:
        print(f"  {C.GRAY}[BUILD] Running mvn clean install (with tests) ...{C.RESET}", flush=True)

    t0 = time.time()
    proc = None
    output_lines = []
    try:
        proc = subprocess.Popen(
            mvn_cmd,
            cwd=project_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        # Stream output line-by-line so progress is visible in real time
        for raw in iter(proc.stdout.readline, b""):
            line = raw.decode(errors="replace").rstrip()
            output_lines.append(line)
            print(f"  {C.GRAY}{line}{C.RESET}", flush=True)
        proc.wait(timeout=600)
        duration = time.time() - t0
        if proc.returncode != 0:
            print(f"  {C.RED}[BUILD] Build FAILED (exit {proc.returncode}){C.RESET}")
            return False, duration
        return True, duration
    except subprocess.TimeoutExpired:
        if proc:
            _kill_process_tree(proc.pid)
        print(f"  {C.RED}[BUILD] Timed out after 600s — build killed.{C.RESET}")
        return False, time.time() - t0
    except Exception as exc:
        print(f"  {C.RED}[BUILD] Error running maven: {exc}{C.RESET}")
        return False, time.time() - t0


def collect_transitive_pool(project_path: str, mvn_exe: str, timeout: int = 300) -> dict:
    """
    Runs 'mvn dependency:tree -Dverbose' ONCE on the project root pom and returns
    a pool dict: (groupId, artifactId, version) -> dep_dict for every dep in the
    full resolved tree across all modules.  Call this once before the module loop.
    Tries offline mode first (uses .m2 cache, fast); falls back to online if needed.
    Returns {} if mvn is unavailable, the command fails, or times out.
    """
    if not mvn_exe:
        mvn_exe = _find_mvn()
    if not mvn_exe:
        return {}

    root_pom = (project_path if os.path.isfile(project_path)
                else os.path.join(project_path, "pom.xml"))
    if not os.path.isfile(root_pom):
        return {}

    cwd = os.path.dirname(root_pom)

    def _run(extra_flags: list, t: int) -> str:
        # NOTE: Do NOT use CREATE_NEW_PROCESS_GROUP on Windows — it breaks
        # Maven's stdout pipe, causing communicate() to hang indefinitely.
        # Instead, kill the process tree by PID on timeout.
        try:
            proc = subprocess.Popen(
                [mvn_exe, "dependency:tree"] + extra_flags + ["-f", root_pom],
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except (FileNotFoundError, OSError):
            return ""
        try:
            stdout, _ = proc.communicate(timeout=t)
            return stdout if proc.returncode == 0 else ""
        except subprocess.TimeoutExpired:
            _kill_process_tree(proc.pid)
            try:
                proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            return ""

    # Try offline first (uses .m2 cache — fast, ~seconds)
    print(f"  {C.GRAY}[TRANSITIVE] Trying offline (.m2 cache) ...{C.RESET}", flush=True)
    output = _run(["-o", "--no-transfer-progress"], 60)

    if not output:
        # Fall back to online — Maven will download missing metadata
        print(f"  {C.GRAY}[TRANSITIVE] Cache incomplete — fetching from remote "
              f"(may take a few minutes on first run) ...{C.RESET}", flush=True)
        output = _run(["--no-transfer-progress"], timeout)

    if not output:
        return {}

    pool = {}
    for line in output.splitlines():
        m = DEP_TREE_LINE_RE.search(line)
        if not m:
            continue
        gid, aid, ver = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
        scope = m.group(4).strip().lower()
        # Skip same scopes Fortify excludes (test, provided, system)
        if scope in EXCLUDED_SCOPES:
            continue
        if not gid or not aid or not ver or ver.startswith("${"):
            continue
        key = (gid, aid, ver)
        if key not in pool:
            pool[key] = {
                "groupId":    gid,
                "artifactId": aid,
                "version":    ver,
                "raw_version": ver,
                "prop_name":  None,
                "transitive": True,
            }
    return pool


def get_effective_pom_content(pom_path: str, mvn_exe: str = "") -> str:
    """Run 'mvn help:effective-pom' for pom_path and return the fully-resolved XML.

    This resolves:
      • All ${property} references from parent POM chains
      • Versions managed via BOM imports (<scope>import</scope>)

    Returns empty string on any failure — callers must fall back to raw pom.xml.
    Cleans up the temporary output file in all cases.
    """
    if not mvn_exe:
        mvn_exe = _find_mvn()
    if not mvn_exe or not os.path.isfile(pom_path):
        return ""

    cwd      = os.path.dirname(os.path.abspath(pom_path))
    out_file = os.path.join(cwd, ".adr_effective_pom_tmp.xml")

    try:
        proc = subprocess.Popen(
            [
                mvn_exe, "help:effective-pom",
                f"-Doutput={out_file}",
                "-f", pom_path,
                "--no-transfer-progress",
                "-q",
            ],
            cwd=cwd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            proc.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            _kill_process_tree(proc.pid)
            try:
                proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            return ""

        if proc.returncode != 0 or not os.path.isfile(out_file):
            return ""

        with open(out_file, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except Exception:
        return ""
    finally:
        try:
            if os.path.isfile(out_file):
                os.remove(out_file)
        except OSError:
            pass


def parse_dependencies_effective(eff_content: str, raw_content: str) -> tuple:
    """Parse deps from the effective POM and back-patch prop_name from the raw pom.

    Strategy:
      1. Parse effective POM → all versions fully resolved (no ${...} gaps).
      2. Parse raw pom.xml   → collects prop_name for auto-fixable deps.
      3. Merge: effective-POM version + raw prop_name where available.

    Deps that only exist in the effective POM (BOM-managed, unresolved in raw)
    are included with prop_name=None (reported but not auto-fixed).
    Returns (deps, props) in the same format as parse_dependencies().
    """
    deps_eff,  _        = parse_dependencies(eff_content)
    deps_raw,  props_raw = parse_dependencies(raw_content)

    # Build lookup: (groupId, artifactId) -> prop_name from raw parse
    prop_lookup: dict = {}
    for d in deps_raw:
        prop_lookup[(d["groupId"], d["artifactId"])] = d.get("prop_name")

    # Patch effective deps with raw prop_names
    for d in deps_eff:
        key = (d["groupId"], d["artifactId"])
        if key in prop_lookup:
            d["prop_name"] = prop_lookup[key]
        # else: BOM-managed / unresolvable in raw — leave prop_name=None

    return deps_eff, props_raw


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────

def _discover_pom_files(path: str) -> list:
    """Returns a list of pom.xml paths to process.
    If path is a file, returns [path].
    If path is a directory:
      1. Reads the <modules> section from the root pom.xml (declared submodules).
      2. Recursively walks the directory tree to find any additional pom.xml files
         in immediate subdirectories that are NOT declared in <modules> (orphan
         modules, e.g. standalone sub-projects skipped from the parent build).
         This ensures Fortify-scanned JARs from unlisted modules are also covered."""
    if os.path.isfile(path):
        return [os.path.abspath(path)]
    if not os.path.isdir(path):
        return []

    root_pom = os.path.join(path, "pom.xml")
    if not os.path.isfile(root_pom):
        return []

    found = [os.path.abspath(root_pom)]

    # Phase 1: Parse <modules> from the parent POM to discover active submodules
    try:
        tree = ET.parse(root_pom)
        ns_match = re.match(r'\{[^}]+\}', tree.getroot().tag)
        ns = ns_match.group(0) if ns_match else ""
        for modules_tag in tree.getroot().iter(f"{ns}modules"):
            for module_tag in modules_tag.findall(f"{ns}module"):
                module_name = (module_tag.text or "").strip()
                if not module_name:
                    continue
                # module path is relative to the parent POM directory
                sub_pom = os.path.abspath(os.path.join(path, module_name, "pom.xml"))
                if os.path.isfile(sub_pom) and sub_pom not in found:
                    found.append(sub_pom)
    except ET.ParseError:
        pass  # if parent POM is unparseable, return just the root

    # Phase 2: Walk subdirectories to catch pom.xml files NOT listed in <modules>.
    # These "orphan" modules are still scanned by Fortify SCA (via subModuleDependencies)
    # but are invisible to the parent build, causing missed CVE coverage.
    found_set = set(found)
    for entry in os.scandir(path):
        if not entry.is_dir(follow_symlinks=False):
            continue
        candidate = os.path.abspath(os.path.join(entry.path, "pom.xml"))
        if os.path.isfile(candidate) and candidate not in found_set:
            found.append(candidate)
            found_set.add(candidate)

    return found


def _build_commit_message(jira_id: str, all_findings: list,
                          skip_set: set = None) -> tuple:
    """Returns (subject_line, body) for the git commit.
    Subject: [FORTIFY_ID]: vulnerability fix - X Critical, Y High, Z Medium (N packages, M CVEs)
    Body: structured ADR commit message with Changes, Breaking Changes, and caution footer.
    Artifacts in skip_set are labelled [SKIP - Manual Action] and excluded from fix counts."""

    if skip_set is None:
        skip_set = set()

    # Deduplicate by groupId:artifactId — same package in N modules counts once
    seen_coords: dict = {}   # coord -> finding (first occurrence, highest sev wins)
    for f in all_findings:
        dep  = f["dep"]
        key  = f"{dep['groupId']}:{dep['artifactId']}"
        if key not in seen_coords:
            seen_coords[key] = f
        else:
            # keep the higher severity entry
            if SEV_RANK.get(f.get("severity", ""), 0) > \
               SEV_RANK.get(seen_coords[key].get("severity", ""), 0):
                seen_coords[key] = f

    unique_findings = list(seen_coords.values())

    # Only count severities for findings that were actually fixed (not skipped by flag)
    fixed_findings = [f for f in unique_findings
                      if f["dep"]["artifactId"] not in skip_set]
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    total_cves  = 0
    for f in fixed_findings:
        sev = f.get("severity", "").upper()
        if sev in sev_counts:
            sev_counts[sev] += 1
        total_cves += len(f.get("vulns", []))

    parts = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM"):
        if sev_counts[sev]:
            parts.append(f"{sev_counts[sev]} {sev.capitalize()}")
    sev_summary = ", ".join(parts) if parts else "no CVEs"
    subject = (f"{jira_id}: vulnerability fix - {sev_summary}"
               f" ({len(fixed_findings)} package(s) fixed, {total_cves} CVE(s))")

    # Build body — group by WHERE the fix was applied, not where the dep appears
    #   depMgmt section : transitive deps  +  BOM-managed direct deps (_needs_depmanagement_pin)
    #   inline section  : true direct deps with version literal changed in pom.xml
    #   Both sections deduplicate by groupId:artifactId so the same package appears only once.
    depmgmt_fixes = []   # → root pom <dependencyManagement>
    inline_fixes  = []   # → individual module pom version bump
    seen_depmgmt  = set()
    seen_inline   = set()

    for f in all_findings:
        dep = f["dep"]
        key = (dep["groupId"], dep["artifactId"])
        if dep.get("transitive") or dep.get("_needs_depmanagement_pin"):
            # Skip if already recorded as an inline fix (root pom <dependencyManagement>
            # was updated directly, so the module poms will pick up the new version
            # automatically — no separate override entry needed).
            if key not in seen_depmgmt and key not in seen_inline:
                seen_depmgmt.add(key)
                depmgmt_fixes.append(f)
        else:
            if key not in seen_inline:
                seen_inline.add(key)
                inline_fixes.append(f)

    # Build numbered Changes list
    changes = []
    for f in inline_fixes:
        dep   = f["dep"]
        safe  = f.get("safe_version", "")
        coord = f"{dep['groupId']}:{dep['artifactId']}"
        if dep["artifactId"] in skip_set:
            changes.append(f"{coord}  {dep['version']}  [SKIP - Manual Action]  (excluded via --skip flag)")
        elif safe and safe != dep["version"]:
            changes.append(f"{coord}  {dep['version']} -> {safe}  [FIXED in pom.xml]")
        else:
            changes.append(f"{coord}  {dep['version']}  [MANUAL - no safe version on Maven Central]")

    for f in depmgmt_fixes:
        dep   = f["dep"]
        safe  = f.get("safe_version", "")
        coord = f"{dep['groupId']}:{dep['artifactId']}"
        kind  = "transitive" if dep.get("transitive") else "dependency override"
        if dep["artifactId"] in skip_set:
            changes.append(f"{coord}  {dep['version']}  [SKIP - Manual Action]  (excluded via --skip flag)")
        elif safe and safe != dep["version"]:
            changes.append(f"{coord}  {dep['version']} -> {safe}  [PINNED in <dependencyManagement> — {kind}]")
        else:
            changes.append(f"{coord}  {dep['version']}  [MANUAL - no safe version on Maven Central]")

    # Collect skipped / manual items as breaking change candidates
    manual_items = [c for c in changes if "[MANUAL" in c or "[SKIP" in c]
    breaking_changes = "None"
    if manual_items:
        breaking_changes = "\n".join(f"{i+1}. {item}" for i, item in enumerate(manual_items))

    lines = [
        f"The Automated Dependency Remediation (ADR) tool [v {VERSION}] has identified",
        "and applied fixes to direct dependencies in the pom.xml.",
        "",
        "Changes:",
    ]
    for i, change in enumerate(changes, 1):
        lines.append(f"{i}. {change}")

    lines += [
        "",
        f"Breaking Changes: {breaking_changes}",
        "",
        "CAUTION: Please verify build stability and integration tests before merging to master.",
        "",
        f"Co-authored-by: ADR-Bot [v {VERSION}]",
    ]

    return subject, "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description=f"ADR — Automated Dependency Remediation v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Modes (mutually exclusive):\n"
            "  --scan                    Scan for vulnerabilities only — no files modified\n"
            "  --fix                     Apply fixes + maven build verification (no git commit)\n"
            "  --commit FORTIFY_ID       Apply fixes + maven build + git branch/commit\n\n"
            "Options:\n"
            "  --push                    Push the created branch after committing (requires --commit)\n"
            "  --base-branch BRANCH      Base branch to checkout from before creating the feature branch\n"
            "                            (auto-detected from remote HEAD if not provided)\n"
            "  --mvn PATH                Path to mvn executable (auto-detected if not provided)\n"
            "  --skip ARTIFACTS          Comma-separated artifact IDs to exclude from auto-fix\n"
            "                            e.g. --skip spring-core,spring-boot\n"
            "  --include-scopes SCOPES   Comma-separated scopes to include in scanning\n"
            "                            Default excludes: test, provided, system\n"
            "                            system is always excluded (not resolvable from Maven Central)\n"
            "                            e.g. --include-scopes test,provided\n"
            "  --target-versions JSON    JSON map {groupId:artifactId: {safe_version,...}} from Fortify pipeline\n"
            "  --skipTests true|false    Skip Maven tests during build verification\n"
            "                            true = skip tests (-DskipTests)  |  false = run tests (default: false)\n"
            "\n"
            "Examples:\n"
            "  python adr_fortify.py /path/to/project --scan\n"
            "  python adr_fortify.py /path/to/project --scan --include-scopes test,provided\n"
            "  python adr_fortify.py /path/to/project --fix --mvn /usr/bin/mvn\n"
            "  python adr_fortify.py /path/to/project --commit FORTIFY-a4105c54\n"
            "  python adr_fortify.py /path/to/project --commit FORTIFY-a4105c54 --push\n"
            "  python adr_fortify.py /path/to/project --commit FORTIFY-a4105c54 --base-branch develop\n"
            "  python adr_fortify.py /path/to/project --commit FORTIFY-a4105c54 --push --skipTests true\n"
            "  python adr_fortify.py /path/to/project --fix --skipTests false\n"
        ),
    )
    parser.add_argument("project_path", help="Path to the project directory (or a single pom.xml)")

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--scan",   action="store_true",
                            help="Scan and report vulnerabilities only — no files modified")
    mode_group.add_argument("--fix",    action="store_true",
                            help="Apply version fixes + run maven build verification (no git commit)")
    mode_group.add_argument("--commit", metavar="FORTIFY_ID",
                            help="Apply fixes + maven build + git branch/commit, e.g. --commit FORTIFY-a4105c54")

    parser.add_argument("--push",    action="store_true",
                        help="Push the created branch after committing (requires --commit)")
    parser.add_argument("--base-branch", default="", metavar="BRANCH",
                        help="Base branch to checkout from before creating the feature branch "
                             "(auto-detected from remote HEAD if not provided), e.g. --base-branch develop")
    parser.add_argument("--mvn",     default="", metavar="PATH",
                        help="Path to mvn executable (auto-detected if not provided)")
    parser.add_argument("--skip",    default="", metavar="ARTIFACTS",
                        help="Comma-separated artifact IDs to exclude from auto-fix, "
                             "e.g. --skip spring-core,spring-boot,spring-context")
    parser.add_argument("--include-scopes", default="", metavar="SCOPES",
                        help="Comma-separated scopes to include in scanning "
                             "(test/provided excluded by default; system always excluded), "
                             "e.g. --include-scopes test,provided")
    parser.add_argument("--target-versions", default="", metavar="JSON",
                        help="JSON dict of {groupId:artifactId: {safe_version, severity, cve_id}} "
                             "injected by adr_fix.py from the Fortify pipeline. "
                             "Only deps present in this map are fixed.")
    parser.add_argument("--skipTests", type=lambda v: v.lower() == "true",
                        default=False, metavar="true|false",
                        help="Skip Maven tests during build verification. "
                             "true = skip tests (-DskipTests), false = run tests (default: false)")
    args = parser.parse_args()

    # ── Parse --target-versions JSON ──────────────────────────────────────────
    # Format: {"groupId:artifactId": {"safe_version": "...", "severity": "...", "cve_id": "..."}}
    _target_map: dict = {}
    if args.target_versions:
        try:
            _target_map = json.loads(args.target_versions)
            _tv_summary = ", ".join(
                f"{k} -> {v.get('safe_version', '?')}" for k, v in _target_map.items()
            )
            print(f"  {C.CYAN}[Fortify]{C.RESET}  Target versions loaded: {_tv_summary}")
        except (json.JSONDecodeError, KeyError) as exc:
            print(f"{C.RED}[ERROR] --target-versions is not valid JSON: {exc}{C.RESET}")
            sys.exit(1)

    if not _target_map:
        print(f"{C.YELLOW}[WARN] --target-versions not provided — no deps will be fixed. "
              f"Use --scan for a read-only report.{C.RESET}")

    # Adjust excluded scopes based on --include-scopes
    # system is always excluded — cannot be resolved from Maven Central
    _user_include = {s.strip().lower() for s in args.include_scopes.split(",") if s.strip()}
    _invalid_scopes = _user_include - {"test", "provided"}
    if _invalid_scopes:
        print(f"{C.YELLOW}[WARN] Unknown/non-includable scope(s) ignored: "
              f"{', '.join(sorted(_invalid_scopes))} "
              f"(only 'test' and 'provided' can be included){C.RESET}")
    global EXCLUDED_SCOPES
    EXCLUDED_SCOPES = ({"test", "provided", "system"} - _user_include) | {"system"}

    # Build skip set — artifact IDs excluded from auto-fix (treated as manual)
    skip_set = {s.strip() for s in args.skip.split(",") if s.strip()}

    # Derive convenience aliases matching old names used throughout main()
    args.analyze_only = args.scan
    args.jira_id      = args.commit or ""

    # Resolve pom.xml files to process
    pom_files = _discover_pom_files(args.project_path)
    if not pom_files:
        print(f"{C.RED}[ERROR] No pom.xml found at: {args.project_path}{C.RESET}")
        sys.exit(1)


    # Ensure Unicode box-drawing chars work when piped on Windows
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        print(f"{C.YELLOW}[WARN] Unable to force UTF-8 output; continuing with default encoding.{C.RESET}")

    banner()
    mode = (
        "SCAN ONLY (no changes written)" if args.scan else
        f"FIX + COMMIT  [{args.commit}]"  if args.commit else
        "FIX (no git commit)"
    )
    mode += "  +transitive"
    if _user_include:
        mode += f"  +scopes({','.join(sorted(_user_include))})"
    root_label= os.path.abspath(args.project_path)
    print(f"  Target  : {C.WHITE}{root_label}{C.RESET}")
    print(f"  Modules : {C.WHITE}{len(pom_files)} pom.xml file(s) found{C.RESET}")
    print(f"  Mode    : {C.WHITE}{mode}{C.RESET}")

    # ── Git: prepare branch BEFORE applying any file changes ─────────────────
    git_branch, git_base = None, "main"
    if args.jira_id and not args.analyze_only:
        git_root = _find_git_root(pom_files[0])
        if not git_root:
            print(f"{C.RED}[ERROR] --commit requires running inside a git repository.{C.RESET}")
            sys.exit(1)
        print()
        section("GIT -- PREPARING BRANCH")
        git_branch, git_base = _prepare_git_branch(git_root, args.jira_id, args.base_branch)

    # ── Transitive dep pool: ONE mvn dependency:tree run on root pom ─────────
    mvn_exe       = args.mvn or _find_mvn()   # resolved once; used for transitive + effective-pom + build
    transitive_pool = {}   # (gid, aid, ver) -> dep_dict
    if mvn_exe:
        print()
        section("PHASE 1b -- TRANSITIVE DEPS (mvn dependency:tree)")
        print(f"  {C.GRAY}Running mvn dependency:tree on root pom (this may take a minute) ...{C.RESET}",
              flush=True)
        t_pool = time.time()
        transitive_pool = collect_transitive_pool(
            os.path.abspath(args.project_path), args.mvn, timeout=300
        )
        elapsed_pool = time.time() - t_pool
        if transitive_pool:
            print(f"  {C.GREEN}[TRANSITIVE]{C.RESET} {C.BOLD}{len(transitive_pool)}{C.RESET}"
                  f" dep(s) in resolved tree  {C.GRAY}[{elapsed_pool:.1f}s]{C.RESET}")
        else:
            mvn_found = bool(collect_transitive_pool.__module__) and bool(args.mvn or _find_mvn())
            if not mvn_found:
                print(f"  {C.RED}[ERROR] Maven not found on PATH — transitive scanning skipped.{C.RESET}")
                print(f"  {C.YELLOW}  Add Maven bin/ to your PATH or pass --mvn /path/to/mvn{C.RESET}")
            else:
                print(f"  {C.YELLOW}[TRANSITIVE] 0 dep(s) — mvn timed out or returned no output."
                      f"  [{elapsed_pool:.1f}s]{C.RESET}")

    # ── Accumulate across all modules ────────────────────────────────────────
    all_findings  = []   # each finding gets a "module" key
    all_applied   = []   # (pom_path, msg)
    all_skipped   = []   # (pom_path, msg)
    all_backups   = []
    module_results = [] # list of dicts, one per pom
    _printed_flag_skips: set = set()  # suppress duplicate --skip flag log lines across modules

    # Pre-fetch effective POMs in parallel (one mvn invocation per module, concurrently)
    _eff_pom_cache: dict = {}    # pom_path -> resolved XML content (or "")
    if mvn_exe:
        print()
        section("PHASE 1 -- EFFECTIVE POM PRE-FETCH (parallel)")
        print(f"  {C.GRAY}Resolving effective POMs for {len(pom_files)} module(s) in parallel ...{C.RESET}",
              flush=True)
        t_eff    = time.time()
        done_eff = [0]
        with ThreadPoolExecutor(max_workers=min(len(pom_files), 6)) as exe:
            futures = {exe.submit(get_effective_pom_content, p, mvn_exe): p
                       for p in pom_files}
            for fut in as_completed(futures):
                pom_path_key = futures[fut]
                try:
                    _eff_pom_cache[pom_path_key] = fut.result() or ""
                except Exception:
                    _eff_pom_cache[pom_path_key] = ""
                done_eff[0] += 1
                print(f"\r  {C.GRAY}[EFF]{C.RESET}   {done_eff[0]}/{len(pom_files)} "
                      f"effective POM(s) resolved ...", end="", flush=True)
        print()   # clear \r line
        resolved = sum(1 for v in _eff_pom_cache.values() if v)
        print(f"  {C.GREEN if resolved == len(pom_files) else C.YELLOW}"
              f"{resolved}/{len(pom_files)} effective POM(s) resolved"
              f"{C.RESET}  {C.GRAY}[{time.time()-t_eff:.1f}s]{C.RESET}")

    timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_start  = time.time()

    # Pre-load root pom properties so submodule fallback parsers can resolve
    # ${property} references that are only defined in the parent pom (e.g.
    # ${apache.beam.version} in a child pom whose parent defines the value).
    _root_props: dict = {}
    if pom_files:
        try:
            with open(pom_files[0], "r", encoding="utf-8") as _rf:
                _root_props = resolve_properties(_rf.read())
        except OSError:
            pass

    total_mods = len(pom_files)

    for mod_idx, pom_path in enumerate(pom_files, 1):
        rel_path = os.path.relpath(pom_path, root_label if os.path.isdir(args.project_path)
                                   else os.path.dirname(pom_path))
        # Use <artifactId> from the pom as the module label; fall back to relative path
        try:
            _pt = ET.parse(pom_path)
            _ns_m = re.match(r'\{[^}]+\}', _pt.getroot().tag)
            _ns = _ns_m.group(0) if _ns_m else ""
            _aid = _pt.getroot().findtext(f"{_ns}artifactId") or ""
            module_label = _aid if _aid else rel_path
        except ET.ParseError:
            module_label = rel_path
        elapsed = time.time() - run_start
        print()
        print(f"{C.CYAN}{'─' * 68}{C.RESET}")
        print(f"  {C.BOLD}MODULE [{mod_idx}/{total_mods}]: {module_label}{C.RESET}"
              f"  {C.GRAY}(elapsed {elapsed:.0f}s){C.RESET}")
        print(f"{C.CYAN}{'─' * 68}{C.RESET}")

        try:
            with open(pom_path, "r", encoding="utf-8") as fh:
                content = fh.read()
        except OSError as exc:
            print(f"{C.RED}[ERROR] Unable to read {pom_path}: {exc}{C.RESET}")
            continue

        # Phase 1 — parse dependencies (effective POM preferred for full version resolution)
        t0 = time.time()
        eff_content = _eff_pom_cache.get(pom_path, "")
        if eff_content:
            deps, props = parse_dependencies_effective(eff_content, content)
            print(f"  {C.GRAY}Parsed{C.RESET}  {C.BOLD}{len(deps)}{C.RESET} deps"
                  f"  (effective POM — parent+BOM resolved)"
                  f"  {C.GRAY}[{time.time()-t0:.1f}s]{C.RESET}")
        elif mvn_exe:
            # Fallback: try on-demand (should not normally reach here)
            eff_content = get_effective_pom_content(pom_path, mvn_exe)
            if eff_content:
                deps, props = parse_dependencies_effective(eff_content, content)
                print(f"  {C.GRAY}Parsed{C.RESET}  {C.BOLD}{len(deps)}{C.RESET} deps"
                      f"  (effective POM — fallback on-demand)"
                      f"  {C.GRAY}[{time.time()-t0:.1f}s]{C.RESET}")
            else:
                deps, props = parse_dependencies(content, extra_props=_root_props)
                print(f"  {C.GRAY}Parsed{C.RESET}  {C.BOLD}{len(deps)}{C.RESET} deps"
                      f"  (raw pom — effective POM unavailable)"
                      f"  {C.GRAY}[{time.time()-t0:.1f}s]{C.RESET}")
        else:
            deps, props = parse_dependencies(content, extra_props=_root_props)
            print(f"  {C.GRAY}Parsed{C.RESET}  {C.BOLD}{len(deps)}{C.RESET} deps"
                  f"  ({len(props)} properties)  {C.GRAY}[{time.time()-t0:.1f}s]{C.RESET}")

        # Phase 1b — merge transitive deps from pre-collected pool (no extra mvn call)
        # Capture direct coords BEFORE merge so we can split direct vs transitive vulns later.
        _direct_coords = {(d["groupId"], d["artifactId"]) for d in deps}
        _trans_count = 0
        if transitive_pool and deps:
            direct_keys = {(d["groupId"], d["artifactId"], d["version"]) for d in deps}
            trans_deps = [v for k, v in transitive_pool.items() if k not in direct_keys]
            if trans_deps:
                _trans_count = len(trans_deps)
                print(f"  {C.GRAY}[TRANSITIVE]{C.RESET} +{C.BOLD}{_trans_count}{C.RESET}"
                      f" transitive dep(s) added for scanning")
                deps = deps + trans_deps
        elif transitive_pool and not deps:
            # Module has no direct deps but pool exists — add everything from pool
            trans_deps = list(transitive_pool.values())
            if trans_deps:
                _trans_count = len(trans_deps)
                print(f"  {C.GRAY}[TRANSITIVE]{C.RESET} +{C.BOLD}{_trans_count}{C.RESET}"
                      f" transitive dep(s) added for scanning")
                deps = trans_deps

        bundle_deps = _expand_vendor_bundles(deps)
        if bundle_deps:
            deps = deps + bundle_deps

        # Total deps actually being scanned for this module (after effective POM + transitive merge).
        # Captured here so the module summary table reflects the true scan scope.
        _scanned_dep_count = len(deps)

        # ── Merge Fortify target-version data onto matching dep dicts ─────────
        # _target_map keys: "groupId:artifactId" → {safe_version, severity, cve_id}
        # After Phase 1 parsing, deps have groupId/artifactId but no safe_version.
        # We annotate each dep that appears in _target_map so the findings builder
        # and apply_fixes can work exactly as before.
        #
        # Fallback: also try artifactId-only key in case the pom parser resolves
        # groupId differently (e.g. via ${project.groupId} parent inheritance).
        if _target_map:
            for dep in deps:
                coord = f"{dep['groupId']}:{dep['artifactId']}"
                target = _target_map.get(coord) or _target_map.get(dep['artifactId'])
                if target:
                    dep["safe_version"]   = target.get("safe_version", "")
                    dep["severity"]       = target.get("severity", "High")
                    dep["cve_id"]         = target.get("cve_id", "")
                    dep["latest_version"] = target.get("safe_version", "")
                    print(f"  {C.CYAN}[Fortify]{C.RESET}  Matched '{coord}' → safe version {dep['safe_version']}")

            # Warn about any target keys that matched nothing in the parsed deps
            matched_coords = {
                f"{dep['groupId']}:{dep['artifactId']}"
                for dep in deps if dep.get("safe_version")
            }
            matched_bare = {
                dep['artifactId']
                for dep in deps if dep.get("safe_version")
            }
            for key in _target_map:
                if key not in matched_coords and key not in matched_bare:
                    print(f"  {C.YELLOW}[WARN] Target key '{key}' did not match any dep in pom.xml "
                          f"— check groupId spelling or parent inheritance{C.RESET}")

        # Findings come pre-resolved from the Fortify pipeline (triage → version_resolver).
        # Each dep dict carries safe_version, severity, and cve_id set upstream.
        findings = []
        for dep in deps:
            safe_ver = dep.get("safe_version", "")
            severity = dep.get("severity", "HIGH")
            cve_id   = dep.get("cve_id", "")
            if safe_ver:
                vuln = {"id": cve_id, "source": "Fortify", "severity": severity}
                findings.append({
                    "dep":            dep,
                    "vulns":          [vuln],
                    "severity":       severity,
                    "safe_version":   safe_ver,
                    "latest_version": dep.get("latest_version", safe_ver),
                    "module":         module_label,
                })

        findings = _remap_vendor_bundle_findings(findings)

        if not findings:
            print(f"  {C.GREEN}✓ No actionable findings for this module{C.RESET}")
            module_results.append({"pom": pom_path, "label": module_label,
                                   "deps": _scanned_dep_count, "trans": _trans_count, "direct_coords": _direct_coords,
                                   "findings": [], "applied": [], "skipped": []})
            continue

        print(f"  {C.CYAN}[Fortify]{C.RESET}  {C.BOLD}{len(findings)}{C.RESET} dep(s) to fix")

        # Tag each finding with its module
        for f in findings:
            f["module"] = module_label
        all_findings.extend(findings)

        if args.analyze_only:
            module_results.append({"pom": pom_path, "label": module_label,
                                   "deps": _scanned_dep_count, "trans": _trans_count, "direct_coords": _direct_coords,
                                   "findings": findings, "applied": [], "skipped": []})
            continue

        # Phase 5 — apply direct dep version fixes (skip excluded artifacts)
        t0 = time.time()
        fix_findings = [f for f in findings if f["dep"]["artifactId"] not in skip_set]
        skipped_by_flag = [f for f in findings if f["dep"]["artifactId"] in skip_set]
        content, applied, skipped = apply_fixes(content, fix_findings)
        for f in skipped_by_flag:
            art = f["dep"]["artifactId"]
            msg = f"{f['dep']['groupId']}:{art} skipped (--skip flag)"
            if art not in _printed_flag_skips:
                print(f"  {C.YELLOW}[SKIP ]{C.RESET}  {msg}  (applies to all modules)")
                _printed_flag_skips.add(art)
            all_skipped.append((pom_path, msg))
        for msg in applied:
            print(f"  {C.GREEN}[FIXED]{C.RESET}  {msg}")
            all_applied.append((pom_path, msg))
        for msg in skipped:
            print(f"  {C.YELLOW}[SKIP ]{C.RESET}  {msg}")
            all_skipped.append((pom_path, msg))

        if applied:
            backup_path = f"{pom_path}.bak_{timestamp}"
            shutil.copy2(pom_path, backup_path)
            all_backups.append(backup_path)
            print(f"  {C.GRAY}Backup : {backup_path}{C.RESET}")
            try:
                with open(pom_path, "w", encoding="utf-8") as fh:
                    fh.write(content)
                print(f"\n  {C.GREEN}pom.xml updated successfully.  {C.GRAY}[{time.time()-t0:.1f}s]{C.RESET}")
            except OSError as exc:
                print(f"{C.RED}[ERROR] Failed to write {pom_path}: {exc}{C.RESET}")
                sys.exit(1)
        else:
            print(f"\n  {C.YELLOW}No direct fixes for this module — transitive overrides handled in root pom.{C.RESET}")

        module_results.append({"pom": pom_path, "label": module_label,
                               "deps": _scanned_dep_count, "trans": _trans_count, "direct_coords": _direct_coords,
                               "findings": findings, "applied": applied, "skipped": skipped})

    # ── Phase 5b: Transitive dep fixes → inject into root pom dependencyManagement ──
    trans_root_pom_updated = False   # set True if Phase 5b writes root pom
    if not args.scan and not args.analyze_only and all_findings:
        root_pom_path = pom_files[0]
        try:
            with open(root_pom_path, "r", encoding="utf-8") as fh:
                root_content = fh.read()
            t0 = time.time()
            # Exclude skipped artifacts from transitive fixes too
            trans_findings = [f for f in all_findings if f["dep"]["artifactId"] not in skip_set]
            new_root, t_injected, t_already_ok, t_no_safe = apply_transitive_fixes(
                root_content, trans_findings)
            for msg in t_injected:
                print(f"  {C.GREEN}[TRANS ]{C.RESET}  {msg}")
                all_applied.append((root_pom_path, msg))
            for msg in t_already_ok:
                print(f"  {C.GRAY}[OK    ]{C.RESET}  {msg}")
            for msg in t_no_safe:
                print(f"  {C.YELLOW}[MANUAL]{C.RESET}  {msg}")
            if new_root != root_content:
                backup_root = f"{root_pom_path}.bak_{timestamp}"
                if backup_root not in all_backups:
                    shutil.copy2(root_pom_path, backup_root)
                    all_backups.append(backup_root)
                with open(root_pom_path, "w", encoding="utf-8") as fh:
                    fh.write(new_root)
                trans_root_pom_updated = True
                print(f"\n  {C.GREEN}Root pom.xml updated with {len(t_injected)} transitive override(s)."
                      f"  {C.GRAY}[{time.time()-t0:.1f}s]{C.RESET}")
            elif not t_injected:
                print(f"  {C.YELLOW}No transitive overrides needed.{C.RESET}")
        except OSError as exc:
            print(f"  {C.RED}[ERROR] Could not update root pom.xml for transitive fixes: {exc}{C.RESET}")

    if args.scan:
        print(f"\n  {C.YELLOW}Scan mode — no changes written."
              f"  Use --commit FORTIFY-<id> to apply fixes.{C.RESET}")


    elapsed_so_far = time.time() - run_start
    print()
    print(f"  {C.GRAY}── All {total_mods} module(s) processed in {elapsed_so_far:.0f}s ──{C.RESET}")

    print()
    print(f"{C.CYAN}{'=' * 68}{C.RESET}")
    print(f"  {C.BOLD}SCAN REPORT{C.RESET}")
    print(f"{C.CYAN}{'=' * 68}{C.RESET}")

    # ── Compute execution metadata once (reused in report header, PDF, exec summary) ──
    _rpt_login = os.environ.get("USERNAME") or getpass.getuser()
    _rpt_fullname = ""
    try:
        _buf_rpt = ctypes.create_unicode_buffer(256)
        _sz_rpt  = ctypes.c_ulong(256)
        if ctypes.windll.secur32.GetUserNameExW(3, _buf_rpt, ctypes.byref(_sz_rpt)):
            _rpt_fullname = _buf_rpt.value.split("\\")[-1]
    except Exception:
        pass
    _rpt_exec_user = (f"{_rpt_login}  |  {_rpt_fullname}"
                      if _rpt_fullname and _rpt_fullname != _rpt_login else _rpt_login)
    _rpt_git_url = ""
    try:
        _rpt_gr = subprocess.run(
            ["git", "-C", os.path.abspath(args.project_path), "remote", "get-url", "origin"],
            capture_output=True, text=True, timeout=5)
        _rpt_git_url = _rpt_gr.stdout.strip()
    except Exception:
        pass
    _rpt_elapsed = time.time() - run_start
    _rpt_mins, _rpt_secs = divmod(int(_rpt_elapsed), 60)
    _rpt_elapsed_str = f"{_rpt_mins}m {_rpt_secs}s" if _rpt_mins else f"{_rpt_secs}s"
    _report_exec_info = {
        "app_name":          os.path.basename(os.path.abspath(args.project_path)),
        "executed_by":       _rpt_exec_user,
        "run_started":       datetime.fromtimestamp(run_start).strftime("%Y-%m-%d %H:%M:%S"),
        "total_elapsed":     _rpt_elapsed,
        "total_elapsed_str": _rpt_elapsed_str,
        "modules_count":     len(module_results) if module_results else 1,
        "git_url":           _rpt_git_url,
    }

    # ─   Maven build verification (before any git commit) ─────────────────────
    maven_ok = None
    maven_duration = 0.0
    if not args.analyze_only and all_applied:
        project_root = (
            os.path.abspath(args.project_path)
            if os.path.isdir(args.project_path)
            else os.path.dirname(os.path.abspath(args.project_path))
        )
        maven_ok, maven_duration = _run_maven_build(project_root, mvn_exe=mvn_exe,
                                                      skip_tests=args.skipTests)
        if not maven_ok:
            print()
            print(f"  {C.RED}[ABORT] Build failed — reverting all pom.xml changes from backups.{C.RESET}")
            restored, failed = 0, 0
            for backup in all_backups:
                original = backup[:backup.rfind(".bak_")]
                try:
                    shutil.copy2(backup, original)
                    os.remove(backup)
                    restored += 1
                    print(f"  {C.YELLOW}[REVERTED]{C.RESET} {original}")
                except OSError as exc:
                    failed += 1
                    print(f"  {C.RED}[RESTORE ERROR]{C.RESET} {original}: {exc}")
            print()
            print(f"  {C.YELLOW}Restored {restored} file(s). Fix the build error above and re-run.{C.RESET}")
            sys.exit(1)

    # ── Git: commit (branch was already created before fixes were applied) ──────
    git_info = None
    if not args.analyze_only and args.jira_id and all_applied and git_branch:
        commit_subject, commit_body = _build_commit_message(args.jira_id, all_findings, skip_set)
        # Collect poms to stage: modules with direct fixes + root pom if transitive overrides were added
        poms_to_stage = [r["pom"] for r in module_results if r["applied"]]
        if trans_root_pom_updated and pom_files[0] not in poms_to_stage:
            poms_to_stage.append(pom_files[0])
        git_info = _finalize_git_changes(
            git_root,
            poms_to_stage,
            args.jira_id,
            git_branch,
            git_base,
            push=args.push,
            commit_subject=commit_subject,
            commit_body=commit_body,
        )

    # ── EXECUTION SUMMARY ─────────────────────────────────────────────────────
    total_findings  = len(all_findings)

    # Unique vulnerable packages (deduplicated by groupId:artifactId)
    _unique_vuln_keys = {
        f"{f['dep']['groupId']}:{f['dep']['artifactId']}" for f in all_findings
    }
    unique_findings = len(_unique_vuln_keys)

    # Deduplicate applied/skipped counts by artifact coordinate (groupId:artifactId).
    # The same artifact may appear in multiple module poms but should count as 1 action.
    def _coord(msg: str) -> str:
        """Extract groupId:artifactId from a fix/skip message string."""
        return msg.split("  ")[0].strip()

    total_applied = len({_coord(msg) for _, msg in all_applied})
    total_skipped = len({_coord(msg) for _, msg in all_skipped})

    print()
    print(f"{C.CYAN}{'=' * 68}{C.RESET}")
    print(f"  {C.BOLD}EXECUTION SUMMARY{C.RESET}")
    print(f"{C.CYAN}{'=' * 68}{C.RESET}")

    # Refresh git URL in case git_info (from commit step) has a richer value
    _git_url = (git_info.get("remote_url", "") if git_info else "") or _report_exec_info["git_url"]
    # Refresh elapsed now that maven build is also complete
    total_elapsed = time.time() - run_start
    mins, secs = divmod(int(total_elapsed), 60)
    _elapsed_str = f"{mins}m {secs}s" if mins else f"{secs}s"

    exec_info = {
        **_report_exec_info,
        "total_elapsed":     total_elapsed,
        "total_elapsed_str": _elapsed_str,
        "maven_status":      maven_ok,
        "maven_duration":    maven_duration,
        "total_findings":    unique_findings,
        "git_url":           _git_url,
    }

    # Build status, timing, and backup info
    _run_started_str = _report_exec_info["run_started"]
    print(f"  {'Executed By':<14}: {exec_info['executed_by']}")
    print(f"  {'Scanned':<14}: {_run_started_str}   |   Total time: {_elapsed_str}")
    if _git_url:
        print(f"  {'Repository':<14}: {C.GRAY}{_git_url}{C.RESET}")
    print(f"  {'Findings':<14}: {unique_findings} unique package(s)"
          + (f"  ({total_findings} occurrences)" if total_findings > unique_findings else ""))
    print(f"  {'Fixes applied':<14}: {C.GREEN}{total_applied}{C.RESET}   "
          f"{'Manual needed'}: {C.YELLOW if total_skipped else C.WHITE}{total_skipped}{C.RESET}")

    # Maven build status and backup info (fix/commit mode only)
    if maven_ok is True:
        print(f"  {C.GREEN}[BUILD] ✓  mvn clean install SUCCESS{C.RESET}")
    elif maven_ok is False:
        print(f"  {C.RED}[BUILD] ✗  mvn clean install FAILED — changes reverted{C.RESET}")
    if all_backups:
        print(f"  {C.GRAY}[BACKUP] {len(all_backups)} backup(s) created{C.RESET}")

    # >> Vulnerability Breakdown (deduped, direct vs transitive)
    if all_findings:
        print()
        print(f"  {C.BOLD}>> Vulnerability Breakdown{C.RESET}")

        # Deduplicate by groupId:artifactId, keep highest severity
        seen_vb: dict = {}
        for f in all_findings:
            key = f"{f['dep']['groupId']}:{f['dep']['artifactId']}"
            if key not in seen_vb or \
               SEV_RANK.get(f.get("severity",""),0) > SEV_RANK.get(seen_vb[key].get("severity",""),0):
                seen_vb[key] = f

        direct_vb = sorted(
            [f for f in seen_vb.values() if not f["dep"].get("transitive")],
            key=lambda f: (-SEV_RANK.get(f.get("severity",""), 0), f["dep"]["artifactId"])
        )
        trans_vb = sorted(
            [f for f in seen_vb.values() if f["dep"].get("transitive")],
            key=lambda f: (-SEV_RANK.get(f.get("severity",""), 0), f["dep"]["artifactId"])
        )

        def _vb_list(rows_data, title):
            if not rows_data:
                return
            print(f"\n  {title}")
            for f in rows_data:
                dep     = f["dep"]
                safe    = f.get("safe_version", "")
                latest  = f.get("latest_version", "")
                can_fix = bool(safe) and safe != dep["version"]
                try:
                    no_higher = (not latest) or (_version_tuple(latest) <= _version_tuple(dep["version"]))
                except Exception:
                    no_higher = not latest
                fixed_to = safe if can_fix else "(manual)"
                latest_s = "(none higher)" if no_higher else latest
                cve_n    = len(f.get("vulns", []))
                print(
                    f"    {dep['groupId']}:{dep['artifactId']}  {dep['version']} -> {fixed_to}"
                    f"  (latest: {latest_s}, severity: {f.get('severity', '')}, cves: {cve_n})"
                )

        _vb_list(direct_vb,
                 f"Direct dependencies  [{len(direct_vb)} package(s)]:")
        _vb_list(trans_vb,
                 f"Transitive dependencies  [{len(trans_vb)} package(s)"
                 f" — pinned via dependencyManagement]:")

    # >> Fix Details
    if all_applied or all_skipped:
        print()
        print("  >> Fix Details")
        def _short_pom(p):
            return os.path.relpath(p, root_label if os.path.isdir(args.project_path)
                                   else os.path.dirname(p))
        FA = [(_short_pom(p),) + tuple(m.split("  ")) for p, m in all_applied]
        # Deduplicate skip rows: same artifact skipped in N modules → one row with "N module(s)"
        _skip_by_comp: dict = {}
        for p, m in all_skipped:
            comp = m.split("  ")[0]
            _skip_by_comp.setdefault(comp, {"msg": m, "poms": []})["poms"].append(_short_pom(p))
        FS = []
        for comp, info in _skip_by_comp.items():
            n = len(info["poms"])
            mod_label = info["poms"][0] if n == 1 else f"{n} module(s)"
            FS.append((mod_label,) + tuple(info["msg"].split("  ")))

        for mod, comp, *rest in FA:
            action = rest[0] if rest else ""
            print(f"    [FIXED] {mod}  {comp}" + (f"  {action}" if action else ""))
        for mod, comp, *rest in FS:
            action = rest[0] if rest else ""
            print(f"    [SKIP ] {mod}  {comp}" + (f"  {action}" if action else ""))

    # >> Git Commit Verification
    if git_info:
        print()
        print("  >> Git Commit Verification")
        print(f"    Fortify ID   : {args.commit or ''}")
        print(f"    Branch       : {git_info['branch']}")
        print(f"    Created From : {git_info.get('base_branch', 'master')}")
        print(f"    Commit       : {git_info['hash'] or 'n/a'}")
        print(f"    Commit Message: {git_info['message']}")
        print(f"    Status       : {git_info['status']}")
        print(f"    Pushed       : {'Yes' if git_info['pushed'] else 'No (run with --push)'}")

    print()
    print(f"  Next step  :  {C.CYAN}mvn clean verify{C.RESET}")
    print(f"{C.CYAN}{'=' * 68}{C.RESET}")

    # ── QA Warning ────────────────────────────────────────────────────────────
    W = 68
    print()
    print(f"  {C.YELLOW}{'⚠' + ' ' + 'IMPORTANT — SCRIPT-GENERATED FIX':{'─'}<{W-4}}{C.RESET}")
    print(f"  {C.YELLOW}│{C.RESET}  This fix was applied automatically by ADR v{VERSION}.")
    print(f"  {C.YELLOW}│{C.RESET}  Dependency upgrades may introduce breaking API or behaviour changes.")
    print(f"  {C.YELLOW}│{C.RESET}")
    print(f"  {C.YELLOW}│{C.RESET}  Before promoting to UAT or Production, ensure:")
    _base_branch = git_info.get("base_branch", "main") if git_info else "main"
    for step in _QA_STEPS:
        print(f"  {C.YELLOW}│{C.RESET}  {C.BOLD}  {step.format(base_branch=_base_branch)}{C.RESET}")
    print(f"  {C.YELLOW}└{'─' * (W - 2)}{C.RESET}")
    print()


if __name__ == "__main__":
    main()