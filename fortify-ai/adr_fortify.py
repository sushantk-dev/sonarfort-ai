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
    --offline                            Skip all API calls (air-gapped environments)
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
import math
import time
import shutil
import signal
import ctypes
import getpass
import argparse
import subprocess
import urllib.request
import urllib.error
import urllib.parse
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
    MAGENTA = "\033[95m"  if _USE_COLOR else ""
    CYAN    = "\033[96m"  if _USE_COLOR else ""
    BLUE    = "\033[94m"  if _USE_COLOR else ""
    GREEN   = "\033[92m"  if _USE_COLOR else ""
    WHITE   = "\033[97m"  if _USE_COLOR else ""
    GRAY    = "\033[90m"  if _USE_COLOR else ""
    BOLD    = "\033[1m"   if _USE_COLOR else ""
    RESET   = "\033[0m"   if _USE_COLOR else ""


SEV_COLOR = {
    "CRITICAL": C.RED,
    "HIGH":     C.YELLOW,
    "MODERATE": C.MAGENTA,
    "MEDIUM":   C.MAGENTA,
    "LOW":      C.YELLOW,
    "INFO":     C.CYAN,
}
SEV_RANK = {"CRITICAL": 5, "HIGH": 4, "MODERATE": 3, "MEDIUM": 3, "LOW": 2, "INFO": 1}

VERSION          = "8.4-fortify"

MAVEN_SEARCH_URL = "https://search.maven.org/solrsearch/select"
# NOTE: OSV/NVD/GHSA/OSS scanning removed — CVE detection is handled upstream
# by Fortify SCA. ADR's role here is pom.xml patching and Maven build validation.

PROPERTY_REF_RE   = re.compile(r"\$\{([^}]+)\}")
VERSION_XML_RE    = re.compile(r"<version>([^<]+)</version>")
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


def get_vuln_severity(v: dict) -> str:
    """Return severity string for a vuln dict.
    In the Fortify pipeline, severity is set directly on the vuln dict by the
    findings builder. Falls back to 'HIGH' if not present.
    """
    return (v.get("severity") or "HIGH").upper()

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


def _generate_pdf_report(findings: list, total_scanned: int, project_path: str,
                          applied: list = None, skipped: list = None,
                          git_info: dict = None,
                          module_results: list = None,
                          exec_info: dict = None,
                          skip_set: set = None) -> "str | None":
    """Generate a PDF scan report saved to the project root. Returns file path or None.
    applied / skipped: list of (pom_path, msg) tuples from commit/fix mode.
    git_info: dict with branch/hash/message/status from commit mode.
    exec_info: dict with executed_by, hostname, total_elapsed, maven_status, maven_duration.
    """
    try:
        from fpdf import FPDF
        from fpdf.enums import XPos, YPos
    except ImportError:
        import subprocess, sys
        print(f"  {C.YELLOW}[PDF] fpdf2 not found -- installing...{C.RESET}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "fpdf2", "-q"])
        from fpdf import FPDF
        from fpdf.enums import XPos, YPos

    try:
        return _generate_pdf_body(findings, total_scanned, project_path,
                                   applied, skipped, git_info, module_results, exec_info,
                                   FPDF, XPos, YPos, skip_set or set())
    except Exception as exc:
        print(f"  {C.RED}[PDF] Report generation failed: {exc}{C.RESET}")
        import traceback; traceback.print_exc()
        return None


def _generate_pdf_body(findings, total_scanned, project_path,
                       applied, skipped, git_info, module_results, exec_info,
                       FPDF, XPos, YPos, skip_set=None):
    """Inner PDF generation -- separated so _generate_pdf_report can safely catch all errors."""
    NL = {"new_x": XPos.LMARGIN, "new_y": YPos.NEXT}

    def _t(text: str) -> str:
        """Sanitize text to Latin-1 safe (Helvetica range)."""
        return (str(text)
                .replace("\u2014", "--").replace("\u2013", "-")
                .replace("\u2192", "->").replace("\u2190", "<-")
                .replace("\u26a0", "!")
                .replace("\u2019", "'").replace("\u2018", "'")
                .replace("\u201c", '"').replace("\u201d", '"')
                .encode("latin-1", errors="replace").decode("latin-1"))

    # ---- Deduplicate findings ------------------------------------------------
    seen: dict = {}
    for f in findings:
        key = f"{f['dep']['groupId']}:{f['dep']['artifactId']}"
        if key not in seen:
            seen[key] = f
        else:
            if SEV_RANK.get(f.get("severity", ""), 0) > SEV_RANK.get(seen[key].get("severity", ""), 0):
                seen[key] = f
    unique   = list(seen.values())
    counts   = {}
    for f in unique:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    # Use skip_set (artifact IDs excluded via --skip flag) to correctly classify
    # Auto-fixable vs Manual Action — same logic as terminal print_report().
    if skip_set is None:
        skip_set = set()

    u_auto   = sum(1 for f in unique
                   if f.get("safe_version") and f["safe_version"] != f["dep"]["version"]
                   and f["dep"]["artifactId"] not in skip_set)
    u_manual = len(unique) - u_auto

    # ---- Design tokens -------------------------------------------------------
    BLUE       = (0, 150, 200)
    BLUE_MED   = (0, 100, 160)
    BG_ALT     = (245, 247, 250)
    BORDER_CLR = (220, 220, 220)
    SEV_RGB = {
        "CRITICAL": (220,  50,  50),
        "HIGH":     (224, 120,   0),
        "MODERATE": (210, 170,  30),   # amber
        "MEDIUM":   (210, 170,  30),   # amber
        "LOW":      (160, 130,   0),   # dark gold — readable on yellow bg
    }

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.abspath(project_path)
    out_pdf = os.path.join(out_dir, f"ADR_scan_report_{ts}.pdf")

    class _PDF(FPDF):
        def header(self):
            # Full-width ADR blue header bar
            self.set_fill_color(*BLUE)
            self.rect(0, 0, 210, 12, "F")
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(255, 255, 255)
            self.set_xy(10, 2)
            self.cell(130, 8,
                      _t(f"ADR -- Automated Dependency Remediation  v{VERSION}"),
                      border=0, fill=False)
            self.set_font("Helvetica", "", 9)
            self.set_xy(140, 2)
            self.cell(60, 8, _t(now_str), border=0, fill=False, align="R")
            # Thin blue separator line
            self.set_draw_color(*BLUE)
            self.line(0, 13, 210, 13)
            self.set_y(17)

        def footer(self):
            self.set_y(-14)
            self.set_font("Helvetica", "", 7)
            self.set_text_color(150, 150, 150)
            self.cell(95, 10, "Equifax | D360/Perigon | CONFIDENTIAL -- Internal Use Only", align="L")
            self.cell(95, 10, f"Page {self.page_no()} of {{nb}}", align="R")

    pdf = _PDF()
    pdf.alias_nb_pages()
    pdf.set_margins(10, 15, 10)
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    def _section_header(title: str):
        """Full-width filled ADR-blue section header bar with white bold text."""
        pdf.set_fill_color(*BLUE)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 9, _t(f"  {title}"), border=0, fill=True, **NL)
        pdf.ln(3)

    # ==== PAGE 1: OVERVIEW ===================================================

    # Title & metadata
    app_name = os.path.basename(os.path.abspath(project_path))
    pdf.set_font("Helvetica", "B", 17)
    pdf.set_text_color(*BLUE)
    pdf.cell(0, 10, _t("Common Vulnerabilities and Exposures (CVE) Scan Report"), **NL)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 5, _t(f"Report Generated By: Automated Dependency Remediation [ADR] v{VERSION}  |  Owner: Perigon  |  Dev: sxs1616"), **NL)
    pdf.ln(4)

    # ---- Executive Summary variables (used later, near remediation bar) ----
    _highest_sev_label = "None"
    for _sv in ("CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW"):
        if counts.get(_sv, 0) > 0:
            _highest_sev_label = _sv.capitalize()
            break
    _mods_cnt = len(module_results) if module_results else (exec_info or {}).get("modules_count", 1)

    # Metadata grid
    pdf.set_font("Helvetica", "", 10)
    lbl_w, val_w = 42, 148

    def _meta_row(label, value):
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(lbl_w, 6, _t(label + ":"), border=0)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(20, 20, 20)
        pdf.cell(val_w, 6, _t(str(value)), border=0, **NL)

    ei = exec_info or {}

    # Derive Business Criticality from highest severity found (Fortify style)
    _bc_order = [("CRITICAL", (220, 50,  50)),
                 ("HIGH",     (224, 120,   0)),
                 ("MEDIUM",   (210, 170,  30)),
                 ("MODERATE", (210, 170,  30)),
                 ("LOW",      (160, 130,   0))]
    _bc_label, _bc_rgb = "None", (100, 100, 100)
    for _sev, _rgb in _bc_order:
        if counts.get(_sev, 0) > 0:
            _bc_label = _sev.capitalize()
            _bc_rgb   = _rgb
            break

    # Scan Status & Rating — high-water mark (Fortify AppSec standard)
    #   Critical > 0  -> 1 Star  / Failed  / Red
    #   High     > 0  -> 2 Stars / Failed  / Red
    #   Medium   > 0  -> 3 Stars / Warning / Orange
    #   Low      > 0  -> 4 Stars / Success / Green
    #   None          -> 5 Stars / Success / Green
    _med_cnt = counts.get("MEDIUM", 0) + counts.get("MODERATE", 0)
    if counts.get("CRITICAL", 0) > 0:
        _scan_stars, _scan_status, _scan_rgb = 1, "Failed",   (220,  50,  50)
    elif counts.get("HIGH", 0) > 0:
        _scan_stars, _scan_status, _scan_rgb = 2, "Failed",   (220,  50,  50)
    elif _med_cnt > 0:
        _scan_stars, _scan_status, _scan_rgb = 3, "Warning",  (224, 120,   0)
    elif counts.get("LOW", 0) > 0:
        _scan_stars, _scan_status, _scan_rgb = 4, "Success",  ( 40, 167,  69)
    else:
        _scan_stars, _scan_status, _scan_rgb = 5, "Success",  ( 40, 167,  69)

    def _meta_row_colored(label, value, val_rgb):
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(lbl_w, 6, _t(label + ":"), border=0)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*val_rgb)
        pdf.cell(val_w, 6, _t(str(value)), border=0, **NL)

    def _meta_section_header(title):
        """Subtle blue bold sub-section divider inside the metadata block."""
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*BLUE)
        pdf.cell(0, 5, _t(title), border=0, **NL)
        y_line = pdf.get_y()
        pdf.set_draw_color(*BLUE)
        pdf.line(10, y_line, 200, y_line)
        pdf.ln(2)

    def _meta_row_stars(label, star_count, total=5, rgb_filled=(220, 170, 0), rgb_empty=(200, 200, 200)):
        """Label col | value col: text '(N/5 Stars)' first (aligned with all values),
        then small filled/empty square indicators immediately after."""
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(lbl_w, 6, _t(label + ":"), border=0)
        # value column — squares first, then [N/5 Stars] text
        # pdf.c_margin (+1 mm) offsets rect to match the internal text margin used
        # by pdf.cell() in every other value row, so squares line up with "Success" / "0"
        x0, y_row = pdf.get_x() + pdf.c_margin, pdf.get_y()
        sq, gap = 3, 1
        for i in range(total):
            pdf.set_fill_color(*(rgb_filled if i < star_count else rgb_empty))
            pdf.rect(x0 + i * (sq + gap), y_row + 1.5, sq, sq, "F")
        pdf.set_xy(x0 + total * (sq + gap) + 2, y_row)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(20, 20, 20)
        pdf.cell(0, 6, _t(f"[{star_count}/{total} Stars]"), border=0, **NL)

    # ── Application Details ──────────────────────────────────────────────────
    _meta_section_header("Application Details")
    _meta_row("Application",           app_name)
    _meta_row_colored("Business Criticality", "High", (224, 120, 0))
    if ei.get("git_url"):
        _meta_row("Git Repository",    ei.get("git_url", ""))

    # ── Scan Results ─────────────────────────────────────────────────────────
    _meta_section_header("Scan Results")
    _meta_row_colored("Scan Status",   _scan_status, _scan_rgb)
    _meta_row_stars(  "Scan Rating",   _scan_stars,  rgb_filled=_scan_rgb)
    _meta_row("Total CVEs Found",      ei.get("total_findings", len(findings)))

    # ── Execution Details ────────────────────────────────────────────────────
    _meta_section_header("Execution Details")
    _meta_row("Scanned",               now_str)
    _meta_row("Executed By",           ei.get("executed_by", ""))
    _meta_row("Total Exec. Time",      ei.get("total_elapsed_str", ""))
    pdf.ln(6)

    _section_header("Scan Overview")
    pdf.ln(3)

    # ---- Stat cards ---------------------------------------------------------
    _modules_count = len(module_results) if module_results else (ei.get("modules_count", 1))
    STAT_CARDS = [
        (str(total_scanned),   "Total Scanned",  BLUE,           (0,   0,   0)),
        (str(_modules_count),  "Modules",        (0, 120, 180),  (0, 120, 180)),
        (str(len(unique)),     "Exposure",       (220, 50,  50), (220,  50,  50)),
        (str(u_auto),          "Auto-fixable",   (40, 167, 69),  (40, 167,  69)),
        (str(u_manual),        "Manual Action",  (255, 152, 0),  (200, 110,   0)),
    ]
    card_gap = 2
    card_w   = (190 - 4 * card_gap) / 5   # exactly 190mm total = banner width
    card_h   = 22
    x_start  = 10
    y_card   = pdf.get_y()
    pdf.set_auto_page_break(False)
    for i, (num, lbl, border_clr, num_clr) in enumerate(STAT_CARDS):
        cx = x_start + i * (card_w + card_gap)
        pdf.set_fill_color(255, 255, 255)
        pdf.set_draw_color(*BORDER_CLR)
        pdf.rect(cx, y_card, card_w, card_h, "DF")
        pdf.set_fill_color(*border_clr)
        pdf.rect(cx, y_card, 3, card_h, "F")
        # number
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(*num_clr)
        num_w = pdf.get_string_width(num)
        pdf.text(cx + 4 + (card_w - 4 - num_w) / 2, y_card + 13, _t(num))
        # label
        pdf.set_font("Helvetica", "", 6)
        pdf.set_text_color(100, 100, 100)
        lbl_w = pdf.get_string_width(_t(lbl))
        pdf.text(cx + 4 + (card_w - 4 - lbl_w) / 2, y_card + 19, _t(lbl))
    pdf.set_auto_page_break(True, margin=15)
    pdf.set_y(y_card + card_h + 6)

    # ---- Severity distribution bar ------------------------------------------
    _sev_bar_segs = [
        ("CRITICAL", SEV_RGB["CRITICAL"], counts.get("CRITICAL", 0)),
        ("HIGH",     SEV_RGB["HIGH"],     counts.get("HIGH", 0)),
        ("MEDIUM",   SEV_RGB["MEDIUM"],   counts.get("MEDIUM", 0) + counts.get("MODERATE", 0)),
        ("LOW",      SEV_RGB["LOW"],      counts.get("LOW", 0)),
    ]
    _bar_total = sum(c for _, _, c in _sev_bar_segs)
    if _bar_total > 0:
        _bar_x, _bar_y = 10, pdf.get_y()
        _bar_w, _bar_h = 190, 8
        _bx = _bar_x
        pdf.set_auto_page_break(False)
        for _slabel, (_sr, _sg, _sb), _sc in _sev_bar_segs:
            if _sc <= 0:
                continue
            _seg_w = _bar_w * _sc / _bar_total
            pdf.set_fill_color(_sr, _sg, _sb)
            pdf.rect(_bx, _bar_y, _seg_w, _bar_h, "F")
            if _seg_w > 15:
                pdf.set_font("Helvetica", "B", 7)
                pdf.set_text_color(255, 255, 255)
                _lbl = _t(f"{_slabel} {_sc}")
                _lw = pdf.get_string_width(_lbl)
                if _lw < _seg_w - 2:
                    pdf.text(_bx + (_seg_w - _lw) / 2, _bar_y + 5, _lbl)
            _bx += _seg_w
        pdf.set_auto_page_break(True, margin=15)
        pdf.set_y(_bar_y + _bar_h + 4)

    # ---- Severity breakdown badges ------------------------------------------
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(70, 70, 70)
    pdf.cell(0, 6, "Severity Breakdown:", **NL)
    pdf.set_draw_color(200, 200, 200)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(3)

    # Use same colours as SEV_RGB so distribution bar and badges always match
    SEVERITY_BOXES = [
        ("CRITICAL", SEV_RGB["CRITICAL"]),
        ("HIGH",     SEV_RGB["HIGH"]),
        ("MEDIUM",   SEV_RGB["MEDIUM"]),
        ("LOW",      SEV_RGB["LOW"]),
    ]
    # merge MODERATE into MEDIUM
    merged = {}
    for s, clr in SEVERITY_BOXES:
        merged[s] = counts.get(s, 0) + (counts.get("MODERATE", 0) if s == "MEDIUM" else 0)
    total_sev = sum(merged.values())   # use merged so MODERATE is included

    # 5 boxes (CRITICAL HIGH MEDIUM LOW TOTAL) × same gap → exactly 190mm = banner width
    box_gap = 2
    box_w   = (190 - 4 * box_gap) / 5
    box_h   = 22
    x_box   = 10
    y_box   = pdf.get_y()

    pdf.set_auto_page_break(False)
    all_boxes = SEVERITY_BOXES + [("TOTAL", (0, 150, 200))]
    for sev, (r, g, b) in all_boxes:
        cnt   = total_sev if sev == "TOTAL" else merged.get(sev, 0)
        lbl   = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium",
                 "LOW": "Low", "TOTAL": "Total"}.get(sev, sev.capitalize())
        # For very light / bright colours (e.g. LOW=pure yellow) use a darker border/text so
        # the banner strip and count remain visible; otherwise use the sev colour.
        _is_light = (r + g + b) > 600
        _accent   = (160, 130, 0) if _is_light else (r, g, b)
        # top colour banner
        pdf.set_fill_color(r, g, b)
        pdf.set_draw_color(*_accent)
        pdf.rect(x_box, y_box, box_w, 4, "F")
        # thin border around banner to make it visible when light
        if _is_light:
            pdf.set_draw_color(200, 190, 100)
            pdf.rect(x_box, y_box, box_w, 4, "D")
        # white card body
        pdf.set_fill_color(255, 255, 255)
        pdf.set_draw_color(220, 220, 220)
        pdf.rect(x_box, y_box + 4, box_w, box_h - 4, "FD")
        # count — use accent (dark) for light colours so it's readable
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(*_accent)
        cnt_str = str(cnt)
        cnt_w   = pdf.get_string_width(cnt_str)
        pdf.text(x_box + (box_w - cnt_w) / 2, y_box + 14, cnt_str)
        # label
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(80, 80, 80)
        _lbl_str_w = pdf.get_string_width(_t(lbl))
        pdf.text(x_box + (box_w - _lbl_str_w) / 2, y_box + 20, _t(lbl))
        x_box += box_w + box_gap
    pdf.set_auto_page_break(True, margin=15)
    pdf.set_y(y_box + box_h + 4)
    pdf.ln(2)

    # ---- Remediation progress bar (full width, text centred in bar) ----------
    if unique:
        _fix_pct  = u_auto / len(unique) if len(unique) > 0 else 0
        _rp_barw  = 190
        _rp_barh  = 8
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(70, 70, 70)
        pdf.cell(0, 6, "Remediation Coverage:", **NL)
        pdf.set_draw_color(200, 200, 200)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(3)
        _rp_y = pdf.get_y()
        # background (grey)
        pdf.set_fill_color(210, 210, 210)
        pdf.rect(10, _rp_y, _rp_barw, _rp_barh, "F")
        # filled portion (green)
        _filled_w = _rp_barw * _fix_pct
        if _filled_w > 0:
            pdf.set_fill_color(40, 167, 69)
            pdf.rect(10, _rp_y, _filled_w, _rp_barh, "F")
        # percentage label centred in bar
        _pct_str = _t(f"{_fix_pct:.0%}   ({u_auto} of {len(unique)} fixable)")
        _pct_w   = pdf.get_string_width(_pct_str)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(255, 255, 255) if _fix_pct >= 0.15 else pdf.set_text_color(50, 50, 50)
        pdf.text(10 + (_rp_barw - _pct_w) / 2, _rp_y + 5.5, _pct_str)
        pdf.set_y(_rp_y + _rp_barh + 4)

        # ---- Executive summary line below the bar ---------------------------
        pdf.ln(2)
        _summary_parts2 = [
            (_t(str(_mods_cnt)), True,  BLUE),
            (" modules scanned  |  ", False, (80, 80, 80)),
            (_t(str(len(unique))), True,  (220, 50, 50)),
            (" unique vulnerable packages  (highest: ", False, (80, 80, 80)),
            (_t(_highest_sev_label), True,  SEV_RGB.get(_highest_sev_label.upper(), (80,80,80))),
            (")  |  ", False, (80, 80, 80)),
            (_t(str(u_auto)), True,  (40, 167, 69)),
            (" auto-fixable  |  ", False, (80, 80, 80)),
            (_t(str(u_manual)), True,  (200, 110, 0)),
            (" require manual action", False, (80, 80, 80)),
        ]
        for _stxt, _sbold, _sclr in _summary_parts2:
            pdf.set_font("Helvetica", "B" if _sbold else "", 9)
            pdf.set_text_color(*_sclr)
            pdf.cell(pdf.get_string_width(_stxt), 6, _stxt)
        pdf.ln(6)

    # ---- Vulnerability Findings table (new page) ----------------------------
    pdf.add_page()
    _section_header("Vulnerability Findings")

    if not unique:
        # ── Zero-vulnerability disclaimer ────────────────────────────────────
        pdf.ln(4)
        # Green tick banner
        pdf.set_fill_color(40, 167, 69)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 10, _t("  No Vulnerabilities Found"), border=0, fill=True, **NL)
        pdf.ln(4)
        # Body text
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(50, 50, 50)
        pdf.multi_cell(0, 6, _t(
            "Great news!  The ADR scan finished and your current dependencies are clean.  "
            "Keep in mind that this only covers our automated dependency checks — if you have "
            "other security reports flagging issues, you'll still need to tackle those manually."
        ))
        pdf.ln(6)
    else:
        CW = [70, 26, 26, 26, 42]   # total = 190
        HDRS = ["Package", "Current", "Min Safe", "Latest", "Severity"]
        pdf.set_fill_color(*BLUE_MED)
        pdf.set_text_color(255, 255, 255)
        pdf.set_draw_color(*BORDER_CLR)
        pdf.set_font("Helvetica", "B", 8)
        for i, h in enumerate(HDRS):
            pdf.cell(CW[i], 7, _t(f"  {h}"), border=1, fill=True)
        pdf.ln()

        for idx, f in enumerate(unique):
            dep    = f["dep"]
            pkg    = f"{dep['groupId']}:{dep['artifactId']}"
            cur    = dep.get("version", "?")
            safe   = f.get("safe_version") or "-"
            latest = f.get("latest_version") or "-"
            sev    = f.get("severity", "HIGH")
            fill_bg = (255, 255, 255) if idx % 2 == 0 else BG_ALT
            # KEV / EPSS badge
            _is_kev = (f.get("kev") or
                       any(v.get("kev") for v in f.get("vulns", []) if isinstance(v, dict)))
            _vuln_epss_vals = [float(v.get("epss_score") or 0)
                               for v in f.get("vulns", [])
                               if isinstance(v, dict) and v.get("epss_score") is not None]
            _best_epss = max(_vuln_epss_vals) if _vuln_epss_vals else float(f.get("epss_score") or 0)
            _pkg_display = f"  {pkg[:38]}"
            if _is_kev:
                _pkg_display += " [!KEV]"
            elif _best_epss > 0.5:
                _pkg_display += f" [EPSS:{_best_epss:.0%}]"
            pdf.set_fill_color(*fill_bg)
            pdf.set_draw_color(*BORDER_CLR)
            pdf.set_font("Helvetica", "", 8)
            if _is_kev:
                pdf.set_text_color(200, 30, 30)
            elif _best_epss > 0.5:
                pdf.set_text_color(180, 80, 0)
            else:
                pdf.set_text_color(30, 30, 30)
            pdf.cell(CW[0], 7, _t(_pkg_display[:50]),  border=1, fill=True)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(CW[1], 7, _t(cur[:14]),           border=1, fill=True)
            if safe != "-" and safe != cur:
                pdf.set_text_color(40, 167, 69)
                pdf.set_font("Helvetica", "B", 8)
            pdf.cell(CW[2], 7, _t(safe[:14]),          border=1, fill=True)
            pdf.set_font("Helvetica", "", 8)
            if latest != "-" and latest != safe:
                pdf.set_text_color(0, 80, 180)
            else:
                pdf.set_text_color(30, 30, 30)
            pdf.cell(CW[3], 7, _t(latest[:14]),        border=1, fill=True)
            # Severity — coloured background
            _sev_bg_map = {
                "CRITICAL": (255, 220, 220), "HIGH": (255, 235, 210),
                "MEDIUM":   (255, 248, 210), "MODERATE": (255, 248, 210),
                "LOW":      (255, 255,   0),   # pure yellow
            }
            _sev_fg = SEV_RGB.get(sev.upper(), (30, 30, 30))
            _sev_bg = _sev_bg_map.get(sev.upper(), fill_bg)
            pdf.set_fill_color(*_sev_bg)
            pdf.set_text_color(*_sev_fg)
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(CW[4], 7, _t(f"  {sev.capitalize()}"), border=1, fill=True)
            pdf.ln()

        pdf.ln(4)

    # ---- Modules Scanned table ----------------------------------------------
    if module_results:
        pdf.add_page()
        _section_header("Modules Scanned")
        #  Module, Deps, Trans, D.Vuln, T.Vuln, Fixed, pom.xml path  (total = 190)
        MCW = [52, 16, 16, 16, 16, 16, 58]
        HDR = ["Module", "Deps", "Trans", "D.Vuln", "T.Vuln", "Fixed", "pom.xml path"]
        pdf.set_fill_color(*BLUE_MED)
        pdf.set_text_color(255, 255, 255)
        pdf.set_draw_color(*BORDER_CLR)
        pdf.set_font("Helvetica", "B", 8)
        for h, w in zip(HDR, MCW):
            pdf.cell(w, 7, _t(f"  {h}"), border=1, fill=True)
        pdf.ln()

        for idx, mr in enumerate(module_results):
            pdf.set_draw_color(*BORDER_CLR)
            pdf.set_font("Helvetica", "", 8)
            findings      = mr.get("findings", [])
            direct_coords = mr.get("direct_coords", set())
            d_vuln = sum(1 for f in findings
                         if (f["dep"]["groupId"], f["dep"]["artifactId"]) in direct_coords)
            t_vuln = len(findings) - d_vuln
            _total_vulns = d_vuln + t_vuln
            if _total_vulns == 0:
                fill_bg = (240, 255, 240)
            elif _total_vulns <= 2:
                fill_bg = (255, 255, 220)
            elif _total_vulns <= 5:
                fill_bg = (255, 235, 200)
            else:
                fill_bg = (255, 220, 220)
            pdf.set_fill_color(*fill_bg)
            mod_name  = _t(str(mr.get("label", mr.get("module", mr.get("name", "?"))))[:30])
            deps_cnt  = str(mr.get("deps", "?"))
            trans_cnt = str(mr.get("trans", 0))
            fix_cnt   = str(len(mr.get("applied", [])))
            pom_short = _t(os.path.basename(os.path.dirname(mr.get("pom", ""))) or "root")

            pdf.set_text_color(30, 30, 30)
            pdf.cell(MCW[0], 6, _t(f"  {mod_name}"), border=1, fill=True)
            pdf.cell(MCW[1], 6, _t(deps_cnt),          border=1, fill=True, align="C")
            pdf.set_text_color(0, 100, 160)
            pdf.cell(MCW[2], 6, _t(trans_cnt),          border=1, fill=True, align="C")
            # D.Vuln — red if non-zero
            pdf.set_text_color(180, 30, 30) if d_vuln else pdf.set_text_color(30, 30, 30)
            pdf.cell(MCW[3], 6, _t(str(d_vuln)),        border=1, fill=True, align="C")
            # T.Vuln — orange if non-zero
            pdf.set_text_color(200, 100, 0) if t_vuln else pdf.set_text_color(30, 30, 30)
            pdf.cell(MCW[4], 6, _t(str(t_vuln)),        border=1, fill=True, align="C")
            pdf.set_text_color(30, 30, 30)
            pdf.cell(MCW[5], 6, _t(fix_cnt),            border=1, fill=True, align="C")
            pdf.cell(MCW[6], 6, _t(f"  {pom_short}"),   border=1, fill=True)
            pdf.ln()

        pdf.ln(4)

    # ==== GIT COMMIT DETAILS (page 2 in commit mode) =========================
    if git_info:
        pdf.add_page()
        _section_header("Git Commit Details")

        status = git_info.get("status", "")
        pushed = git_info.get("pushed", False)
        status_rgb = (0, 150, 0) if "committed" in status else (200, 110, 0)

        def _git_row(key, val, vc=(30, 30, 30)):
            if not val:
                return
            val_str = _t(str(val))
            y0 = pdf.get_y()
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(80, 80, 80)
            pdf.set_xy(10, y0)
            pdf.cell(42, 6, _t(key), border="B")
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*vc)
            pdf.set_xy(52, y0)
            chars_per_line = 70
            lines = max(1, (len(val_str) + chars_per_line - 1) // chars_per_line)
            if lines == 1:
                pdf.cell(148, 6, val_str[:100], border="B", **NL)
            else:
                pdf.multi_cell(148, 6, val_str, border="B")
                pdf.set_xy(10, pdf.get_y())

        def _git_link_row(key, val, url, vc=(0, 100, 200)):
            """Like _git_row but value is a clickable hyperlink."""
            if not val:
                return
            val_str = _t(str(val))
            y0 = pdf.get_y()
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(80, 80, 80)
            pdf.set_xy(10, y0)
            pdf.cell(42, 6, _t(key), border="B")
            pdf.set_font("Helvetica", "U", 9)   # underline signals clickable
            pdf.set_text_color(*vc)
            pdf.set_xy(52, y0)
            pdf.cell(148, 6, val_str[:100], border="B", link=url, **NL)

        def _sub_section(title):
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(*BLUE_MED)
            pdf.cell(0, 7, _t(title), **NL)
            pdf.set_draw_color(*BLUE)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(2)

        # ---- Execution Summary ----------------------------------------------
        ei = exec_info or {}
        _sub_section("Execution Summary")
        _git_row("Executed By",   ei.get("executed_by", ""),       (30, 30, 30))
        _git_row("Machine",       ei.get("hostname", ""),          (30, 30, 30))
        _git_row("Run Started",   ei.get("run_started", ""),       (30, 30, 30))
        _git_row("Total Runtime", ei.get("total_elapsed_str", ""), (0, 130, 0))
        mvn_status = ei.get("maven_status")
        if mvn_status is not None:
            mvn_label = "SUCCESS" if mvn_status else "FAILED"
            mvn_dur   = ei.get("maven_duration", 0.0)
            mvn_str   = f"{mvn_label}  ({mvn_dur:.0f}s)"
            mvn_clr   = (0, 130, 0) if mvn_status else (200, 30, 30)
            _git_row("Maven Build", mvn_str, mvn_clr)
        pdf.ln(4)

        # ---- Branch & Repository --------------------------------------------
        _sub_section("Branch & Repository")
        _jira_id    = git_info.get("jira", "")
        _remote_url = git_info.get("remote_url", "")
        _branch     = git_info.get("branch", "")
        # Build clickable URLs
        _jira_url   = f"https://equifax.atlassian.net/browse/{_jira_id}" if _jira_id else ""
        _branch_url = ""
        _commit_url = ""
        if _remote_url:
            _repo_web = _remote_url.rstrip("/").removesuffix(".git")
            # Support GitHub / Bitbucket / GitLab URL patterns
            _branch_url = f"{_repo_web}/tree/{_branch}" if _branch else ""
            _full_hash  = git_info.get("full_hash", "")
            _commit_url = f"{_repo_web}/commit/{_full_hash}" if _full_hash else ""

        if _jira_url:
            _git_link_row("Fortify ID",        _jira_id,   _jira_url)
        else:
            _git_row("Fortify ID",             _jira_id)
        if _branch_url:
            _git_link_row("Feature Branch", _branch,    _branch_url)
        else:
            _git_row("Feature Branch",      _branch,    (0, 100, 200))
        _git_row("Created From",   git_info.get("base_branch", ""), (80, 80, 80))
        _git_row("Repository",     git_info.get("repo_root", ""),   (80, 80, 80))
        if _remote_url:
            _git_link_row("Remote URL",     _remote_url, _remote_url)
        pdf.ln(4)

        # ---- Commit Information ---------------------------------------------
        _sub_section("Commit Information")
        _git_row("Commit Hash",  git_info.get("hash", "n/a"),           (60, 60, 60))
        _full_hash_val = git_info.get("full_hash", "")
        if _commit_url:
            _git_link_row("Full Hash",  _full_hash_val, _commit_url, (60, 60, 60))
        else:
            _git_row("Full Hash",       _full_hash_val,               (120, 120, 120))
        _git_row("Status",       status,                                  status_rgb)
        _git_row("Pushed",       "Yes - pushed to origin" if pushed else
                                 "No - run with --push to push",
                                 (0, 130, 0) if pushed else (180, 80, 0))
        _git_row("Author",       git_info.get("author", ""),            (30, 30, 30))
        _git_row("Email",        git_info.get("email", ""),             (30, 30, 30))
        _git_row("Timestamp",    git_info.get("timestamp", ""),         (30, 30, 30))
        pdf.ln(4)

        # ---- Commit Message -------------------------------------------------
        _sub_section("Commit Message")
        pdf.set_fill_color(*BG_ALT)
        pdf.set_draw_color(*BORDER_CLR)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(30, 30, 30)
        pdf.multi_cell(190, 6, _t(git_info.get("message", "")), border=1, fill=True)
        body = _t(git_info.get("body", ""))
        if body:
            pdf.ln(1)
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(60, 60, 60)
            pdf.multi_cell(190, 5, body, border=1, fill=True)
        pdf.ln(4)

        # ---- Files Changed --------------------------------------------------
        files = git_info.get("files_changed", [])
        if files:
            _sub_section(f"Files Changed ({len(files)})")
            pdf.set_fill_color(*BLUE_MED)
            pdf.set_text_color(255, 255, 255)
            pdf.set_draw_color(*BORDER_CLR)
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(190, 7, _t("  File Path"), border=1, fill=True, **NL)
            for i, fp in enumerate(files):
                fill_bg = (255, 255, 255) if i % 2 == 0 else BG_ALT
                pdf.set_fill_color(*fill_bg)
                pdf.set_draw_color(*BORDER_CLR)
                pdf.set_font("Helvetica", "", 8)
                pdf.set_text_color(30, 30, 30)
                pdf.cell(190, 5, _t(f"  {fp[:100]}"), border="LR", fill=True, **NL)
            pdf.set_draw_color(*BORDER_CLR)
            pdf.cell(190, 0, "", border="T", **NL)
            pdf.ln(4)

        # ---- Next Steps -----------------------------------------------------
        _sub_section("Recommended Next Steps")
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(60, 60, 60)
        _base = _t(git_info.get("base_branch", "main"))
        for step in _QA_STEPS:
            pdf.cell(0, 6, _t(step.format(base_branch=_base)), **NL)

    # ==== CVE DETAIL CARDS (one page per CVE) ================================
    def _meta(key, val, vc=(30, 30, 30)):
        val_str = _t(str(val))
        chars_per_line = 70
        lines = max(1, (len(val_str) + chars_per_line - 1) // chars_per_line)
        row_h = 6
        y0 = pdf.get_y()
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(80, 80, 80)
        pdf.set_xy(10, y0)
        pdf.cell(42, row_h, _t(key), border="B")
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*vc)
        pdf.set_xy(52, y0)
        if lines == 1:
            pdf.cell(148, row_h, val_str[:90], border="B", **NL)
        else:
            pdf.multi_cell(148, row_h, val_str, border="B")
            pdf.set_xy(10, pdf.get_y())

    def _card_section(title):
        """Thin blue sub-section divider inside a CVE card."""
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*BLUE)
        pdf.cell(0, 6, title, **NL)
        pdf.set_draw_color(*BLUE)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(2)

    cve_counter = 0
    for f in unique:
        dep       = f["dep"]
        pkg       = f"{dep['groupId']}:{dep['artifactId']}"
        pkg_ver   = dep.get("version", "?")
        safe      = f.get("safe_version") or "-"
        latest    = f.get("latest_version") or "-"
        pkg_sev   = f.get("severity", "HIGH")
        module    = f.get("module", "")

        _comp_vulns  = [v for v in f.get("vulns", []) if isinstance(v, dict)]
        if not _comp_vulns:
            continue
        _comp_total = len(_comp_vulns)

        for _vi, vuln in enumerate(_comp_vulns, 1):
            cve_counter += 1
            vid     = vuln.get("id", "")
            aliases = [a for a in vuln.get("aliases", []) if a != vid]

            vsev = get_vuln_severity(vuln)
            if not isinstance(vsev, str) or vsev not in SEV_RGB:
                vsev = pkg_sev
            vr, vg, vb = SEV_RGB.get(vsev, (80, 80, 80))

            desc = (vuln.get("details") or vuln.get("summary") or "").strip()
            if not desc:
                desc = "No description available from OSV/NVD for this CVE."
            desc = desc.replace("\n", " ")

            cvss   = vuln.get("cvss_score", "")
            cwes   = vuln.get("cwes", [])
            source = vuln.get("source", "OSV")

            raw_refs = vuln.get("references", [])
            refs = []
            for r in raw_refs:
                if isinstance(r, dict):
                    url = r.get("url", "")
                    if url:
                        refs.append(url)
                elif isinstance(r, str) and r:
                    refs.append(r)
            refs = refs[:5]
            if vid.startswith("CVE-"):
                nvd_url = f"https://nvd.nist.gov/vuln/detail/{vid}"
                if nvd_url not in refs:
                    refs.insert(0, nvd_url)

            # ---- New page for every single CVE ------------------------------
            pdf.add_page()

            # Component context strip (compact blue header)
            pdf.set_fill_color(*BLUE_MED)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(0, 7,
                     _t(f"  Component: {dep['artifactId']}  ({dep['groupId']})"
                        f"   |   CVE {_vi} of {_comp_total}"),
                     border=0, fill=True, **NL)
            pdf.ln(2)

            # CVE header — full-width severity-coloured banner
            pdf.set_fill_color(vr, vg, vb)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", "B", 12)
            _hdr_lbl = f"  {vsev}   |   {cve_counter}.  {vid}"
            if aliases:
                _hdr_lbl += f"   (also: {', '.join(aliases[:2])})"
            pdf.cell(0, 12, _t(_hdr_lbl), border=0, fill=True, **NL)
            pdf.ln(4)

            # ---- Metadata 2-column grid -------------------------------------
            meta_rows = [
                ("Component",      pkg,                         (30,  30,  30)),
                ("Version",        pkg_ver,                     (180,  30,  30)),
                ("Fix Version",    safe,  (0, 130, 0) if safe != "-" else (150, 80, 0)),
                ("Latest Version", latest, (0, 80, 180) if latest not in ("-", safe) else (0, 130, 0)),
                ("Severity",       vsev,                        (vr,   vg,  vb)),
            ]
            if cvss:
                meta_rows.append(("CVSS Score",  cvss,          (30, 30, 30)))
            if cwes:
                meta_rows.append(("CWE",         "  ".join(cwes), (30, 30, 30)))
            meta_rows += [
                ("OWASP 2021", "A06:2021 -- Vulnerable and Outdated Components", (30, 30, 30)),
                ("Source",     source,                           (30, 30, 30)),
            ]
            if module:
                meta_rows.append(("Module",      module,        (30, 30, 30)))
            if vuln.get("kev"):
                meta_rows.append(("CISA KEV",    "! ACTIVELY EXPLOITED IN THE WILD", (200, 30, 30)))
            epss_score = vuln.get("epss_score")
            if epss_score is not None:
                epss_pct = vuln.get("epss_percentile", 0) or 0
                epss_str = f"{epss_score:.4f}  ({epss_pct*100:.1f}th percentile)"
                meta_rows.append(("EPSS Score",  epss_str,      (30, 30, 30)))
            _pub_str = vuln.get("published", "")
            if _pub_str:
                try:
                    _days_old = (datetime.now() - datetime.strptime(_pub_str[:10], "%Y-%m-%d")).days
                    _age_str  = f"{_days_old} days  (published {_pub_str[:10]})"
                    _age_clr  = ((200,30,30) if _days_old > 365 else
                                 (200,120,0) if _days_old > 180 else (0,130,0))
                    meta_rows.append(("Days Unpatched", _age_str, _age_clr))
                except Exception:
                    pass

            for key, val, vc in meta_rows:
                _meta(key, val, vc)

            # ---- Summary box ------------------------------------------------
            _card_section("Summary")
            pdf.set_fill_color(*BG_ALT)
            pdf.set_draw_color(*BORDER_CLR)
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(40, 40, 40)
            pdf.multi_cell(190, 5, _t(desc), border=1, fill=True)

            # ---- Recommendation ---------------------------------------------
            _card_section("Recommendation")
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(40, 40, 40)
            if safe != "-":
                rec = (f"Upgrade {dep['artifactId']} from {pkg_ver} to {safe} or higher. "
                       f"This is the minimum version with no known CVEs on Maven Central. "
                       f"Verify compatibility with your build before merging.")
            else:
                rec = (f"No safe version was found on Maven Central for {dep['artifactId']} {pkg_ver}. "
                       f"Manual remediation is required. Consider contacting the maintainer or "
                       f"evaluating an alternative component.")
            pdf.multi_cell(190, 5, _t(rec))

            # ---- References -------------------------------------------------
            if refs:
                _card_section("References")
                pdf.set_font("Helvetica", "", 8)
                pdf.set_text_color(0, 80, 160)
                for i, ref in enumerate(refs, 1):
                    pdf.cell(0, 5, _t(f"  {i}.  {ref[:100]}"), **NL)

            # ---- Location ---------------------------------------------------
            _card_section("Location")
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(60, 60, 60)
            pdf.cell(0, 5, _t(f"  Module          : {module or 'root'}"), **NL)
            pdf.cell(0, 5, _t(f"  Found via       : {source}"), **NL)
            trans    = f.get("dep", {}).get("transitive", False)
            dep_type = "Transitive (pinned via dependencyManagement)" if trans else "Direct dependency"
            pdf.cell(0, 5, _t(f"  Dependency type : {dep_type}"), **NL)
            pdf.ln(4)

    # ==== QA WARNING PAGE — only in fix/commit mode (applied is not None) ======
    if applied is not None:
        pdf.add_page()

        # Main orange banner
        pdf.set_fill_color(255, 152, 0)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 12, _t(f"  Automated Fixes Generated by ADR  [v{VERSION}]"), border=0, fill=True, **NL)
        pdf.ln(5)

        # Subtitle paragraph
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(50, 50, 50)
        pdf.multi_cell(0, 6, _t(
            "This report and the associated fixes were generated automatically. "
            "Because dependency upgrades can introduce breaking API or behavioral changes, "
            "all automated modifications must be verified before pushing or merging."
        ))
        pdf.ln(5)

        # Pre-Promotion Checklist header
        pdf.set_fill_color(0, 150, 200)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 9, _t("  Pre-Promotion Checklist (UAT & Production)"), border=0, fill=True, **NL)
        pdf.ln(3)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(50, 50, 50)
        pdf.cell(0, 6, _t("Ensure the following steps are completed before promoting these changes:"), **NL)
        pdf.ln(2)

        checklist = [
            ("Test Execution",    "Ensure all unit and integration tests pass successfully (mvn clean verify)."),
            ("QA Validation",     "The QA team must validate the generated JARs end-to-end."),
            ("Verify Overrides",  "Transitive pin overrides (<dependencyManagement>) require strict peer review."),
            ("Manual Resolutions","Any items marked as SKIP must be tracked and resolved manually."),
        ]
        for title, detail in checklist:
            y_b = pdf.get_y() + 3
            pdf.set_fill_color(0, 150, 200)
            pdf.rect(12, y_b, 3, 3, "F")
            pdf.set_x(18)
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(20, 20, 20)
            pdf.cell(38, 7, _t(title + ":"), border=0)
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(50, 50, 50)
            pdf.multi_cell(0, 7, _t(detail))
        pdf.ln(5)

        # CRITICAL MERGE WARNING box
        pdf.set_fill_color(220, 50, 50)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 10, _t("  CRITICAL MERGE WARNING"), border=0, fill=True, **NL)
        pdf.ln(3)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(50, 50, 50)
        pdf.multi_cell(0, 6, _t(
            "Do not merge this branch without human oversight. Because these dependency updates "
            "were machine-generated, a mandatory and comprehensive peer code review of the feature "
            "branch must be completed and approved prior to merging. Bypassing this review risks "
            "introducing critical instability into the main codebase."
        ))
        pdf.ln(4)


    # ==== PHASE 5 — APPLIED FIXES ============================================
    if applied or skipped:
        pdf.add_page()
        _section_header("Phase 5 -- Applied Fixes")

        if applied:
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(40, 167, 69)
            pdf.cell(0, 6, _t(f"Fixed ({len(applied)} change(s)):"), **NL)
            pdf.set_fill_color(*BLUE_MED)
            pdf.set_text_color(255, 255, 255)
            pdf.set_draw_color(*BORDER_CLR)
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(55,  7, _t("  Module / pom"),   border=1, fill=True)
            pdf.cell(135, 7, _t("  Change Applied"), border=1, fill=True, **NL)
            for idx, (pom, msg) in enumerate(applied):
                fill_bg = (240, 255, 240) if idx % 2 == 0 else (255, 255, 255)
                pdf.set_fill_color(*fill_bg)
                pdf.set_draw_color(*BORDER_CLR)
                pdf.set_text_color(30, 100, 30)
                pdf.set_font("Helvetica", "", 7)
                mod = _t(os.path.basename(os.path.dirname(pom)) or os.path.basename(pom))
                pdf.cell(55,  6, _t(f"  {mod[:28]}"), border=1, fill=True)
                pdf.set_text_color(30, 30, 30)
                pdf.cell(135, 6, _t(msg[:80]),          border=1, fill=True, **NL)
            pdf.ln(4)

        if skipped:
            # Deduplicate: collapse same artifact+reason across multiple modules into one row
            _skip_dedup: dict = {}  # msg -> list of module names
            for pom, msg in skipped:
                mod = os.path.basename(os.path.dirname(pom)) or os.path.basename(pom)
                _skip_dedup.setdefault(msg, []).append(mod)
            _skip_rows = list(_skip_dedup.items())  # [(msg, [mod, ...]), ...]

            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(255, 152, 0)
            pdf.cell(0, 6, _t(f"Skipped ({len(_skip_rows)} unique item(s), "
                               f"{len(skipped)} occurrence(s) -- manual action required):"), **NL)
            pdf.set_fill_color(255, 152, 0)
            pdf.set_text_color(255, 255, 255)
            pdf.set_draw_color(*BORDER_CLR)
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(40,  7, _t("  Affected Modules"), border=1, fill=True)
            pdf.cell(150, 7, _t("  Reason / Action"),  border=1, fill=True, **NL)
            for idx, (msg, mods) in enumerate(_skip_rows):
                fill_bg = (255, 248, 230) if idx % 2 == 0 else (255, 255, 255)
                pdf.set_fill_color(*fill_bg)
                pdf.set_draw_color(*BORDER_CLR)
                pdf.set_text_color(150, 80, 0)
                pdf.set_font("Helvetica", "", 7)
                mod_label = f"  {len(mods)} module(s)" if len(mods) > 1 else f"  {mods[0][:22]}"
                pdf.cell(40,  6, _t(mod_label), border=1, fill=True)
                pdf.set_text_color(30, 30, 30)
                pdf.cell(150, 6, _t(msg[:95]),  border=1, fill=True, **NL)
            pdf.ln(4)

    try:
        pdf.output(out_pdf)
    except Exception as pdf_err:
        print(f"  {C.RED}[PDF] Failed to save report: {pdf_err}{C.RESET}")
        return None
    return out_pdf


def print_report(findings: list, total_scanned: int = 0, skip_set: set = None, exec_info: dict = None):
    """Single consolidated report — called ONCE after all modules with all_findings."""

    if skip_set is None:
        skip_set = set()

    # Ensure component-level severity is consistent with per-vuln enriched data
    # Severity already set from Fortify pipeline — no recalculation needed.

    # ── Deduplicate by groupId:artifactId for accurate counts ─────────────────
    seen: dict = {}
    for f in findings:
        key = f"{f['dep']['groupId']}:{f['dep']['artifactId']}"
        if key not in seen:
            seen[key] = f
        else:
            if SEV_RANK.get(f.get("severity", ""), 0) > \
               SEV_RANK.get(seen[key].get("severity", ""), 0):
                seen[key] = f
    unique = list(seen.values())

    total_occ = len(findings)           # per-module occurrences (for context)
    u_auto    = sum(1 for f in unique
                    if f.get("safe_version") and f["safe_version"] != f["dep"]["version"]
                    and f["dep"]["artifactId"] not in skip_set)
    u_manual  = len(unique) - u_auto
    counts    = {}
    occ_counts = {}                     # per-module occurrence counts per severity
    for f in unique:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    for f in findings:
        occ_counts[f["severity"]] = occ_counts.get(f["severity"], 0) + 1

    # ── Table drawing helpers ─────────────────────────────────────────────────
    def _sep(cw, l="├", m="┼", r="┤"):
        return "  " + l + m.join("─" * (w + 2) for w in cw) + r

    def _row(cw, vals, colors=None):
        """One table row — uses BOLD-wrapped padding to survive Windows terminal color stripping."""
        parts = []
        for i, v in enumerate(vals):
            clr = (colors[i] if colors else "") or ""
            n   = cw[i] - len(v)
            if clr:
                pad = (C.BOLD + " " * n + C.RESET) if (n > 0 and C.BOLD) else " " * n
                parts.append(f" {clr}{v}{C.RESET}{pad} ")
            else:
                parts.append(f" {v}{' ' * n} ")
        return "  │" + "│".join(parts) + "│"

    def _hdr(title):
        print(f"\n  {C.CYAN}{C.BOLD}>> {title}{C.RESET}")

    # ── 1. REPORT HEADER (mirrors PDF page 1: metadata + stat cards + severity) ──
    ei            = exec_info or {}
    _app_name     = ei.get("app_name", "")
    _modules_cnt  = ei.get("modules_count", 0)
    _executed_by  = ei.get("executed_by", "")
    _run_started  = ei.get("run_started", "")
    _elapsed_str  = ei.get("total_elapsed_str", "")
    _git_url      = ei.get("git_url", "")

    # Business criticality = highest severity found
    _bc_order = ["CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"]
    bc_label  = next((s for s in _bc_order if counts.get(s, 0) > 0), "None")
    bc_color  = SEV_COLOR.get(bc_label, C.GRAY)

    # Scan Status + star rating (5-star scale: fewer stars = more critical)
    _med_n = counts.get("MEDIUM", 0) + counts.get("MODERATE", 0)
    if counts.get("CRITICAL", 0) > 0:
        _stars, _status, _st_c = 1, "Failed",  C.RED
    elif counts.get("HIGH", 0) > 0:
        _stars, _status, _st_c = 2, "Failed",  C.RED
    elif _med_n > 0:
        _stars, _status, _st_c = 3, "Warning", C.YELLOW
    elif counts.get("LOW", 0) > 0:
        _stars, _status, _st_c = 4, "Pass",    C.GREEN
    else:
        _stars, _status, _st_c = 5, "Pass",    C.GREEN
    _rating = "★" * _stars + "☆" * (5 - _stars)

    W = 68
    multi_module = total_occ > len(unique)
    _cves_found  = (f"{len(unique)} package(s)  ({total_occ} occurrences across modules)"
                    if multi_module else f"{len(unique)} package(s)")

    print(f"\n  {C.CYAN}{C.BOLD}CVE Scan Report  —  {_app_name or 'Project'}{C.RESET}")
    print(f"  {C.CYAN}{'─' * W}{C.RESET}")
    print(f"  {'Scan Status':<14}: {_st_c}{C.BOLD}{_status:<10}{C.RESET}  "
          f"Rating : {_st_c}{_rating} ({_stars}/5){C.RESET}")
    print(f"  {'Criticality':<14}: {bc_color}{C.BOLD}{bc_label:<10}{C.RESET}  "
          f"CVEs Found : {C.BOLD}{_cves_found}{C.RESET}")
    if _app_name:
        print(f"  {'Application':<14}: {C.WHITE}{_app_name}{C.RESET}")
    if _git_url:
        print(f"  {'Repository':<14}: {C.GRAY}{_git_url}{C.RESET}")
    _meta_parts = []
    if _executed_by:
        _meta_parts.append(f"By: {_executed_by}")
    if _run_started:
        _meta_parts.append(f"Scanned: {_run_started}")
    if _elapsed_str:
        _meta_parts.append(f"Time: {_elapsed_str}")
    if _meta_parts:
        print(f"  {'Execution':<14}: {C.GRAY}{'   |   '.join(_meta_parts)}{C.RESET}")
    print(f"  {C.CYAN}{'─' * W}{C.RESET}")
    print()

    # ── Stat cards (mirrors PDF Scan Overview tiles) ───────────────────────────
    _stat_items  = [
        ("Total Scanned", str(total_scanned)),
        ("Modules",       str(_modules_cnt) if _modules_cnt else "?"),
        ("Exposure",      str(len(unique))),
        ("Auto-fixable",  str(u_auto)),
        ("Manual Needed", str(u_manual)),
    ]
    _stat_colors = [C.WHITE, C.CYAN, C.RED if unique else C.GREEN, C.GREEN,
                    C.YELLOW if u_manual else C.WHITE]
    _sw = [max(len(t[0]), len(t[1])) + 2 for t in _stat_items]

    def _stat_row(parts):
        return "  " + "  ".join(parts)

    print(_stat_row(["┌" + "─" * w + "┐" for w in _sw]))
    print(_stat_row(["│" + t[0].center(w) + "│" for t, w in zip(_stat_items, _sw)]))
    _val_parts = []
    for t, w, clr in zip(_stat_items, _sw, _stat_colors):
        v  = t[1]
        lp = (w - len(v)) // 2
        rp = w - len(v) - lp
        _val_parts.append("│" + " " * lp + clr + C.BOLD + v + C.RESET + " " * rp + "│")
    print(_stat_row(_val_parts))
    print(_stat_row(["└" + "─" * w + "┘" for w in _sw]))
    print()

    # ── Severity badges (mirrors PDF severity badges) ──────────────────────────
    _SEV_DISPLAY = [("CRITICAL", C.RED), ("HIGH", C.YELLOW), ("MEDIUM", C.MAGENTA), ("LOW", C.YELLOW)]
    _total_sev   = sum(counts.get(s, 0) + (counts.get("MODERATE", 0) if s == "MEDIUM" else 0)
                       for s, _ in _SEV_DISPLAY)
    _sev_parts   = []
    for _s, _clr in _SEV_DISPLAY:
        _n = counts.get(_s, 0) + (counts.get("MODERATE", 0) if _s == "MEDIUM" else 0)
        _sev_parts.append(f"{_clr}[{_s}: {_n}]{C.RESET}")
    _sev_parts.append(f"{C.WHITE}[TOTAL: {_total_sev}]{C.RESET}")
    print(f"  Severity:  " + "  ".join(_sev_parts))

    if not unique:
        return

    # ── 2. VULNERABILITY FINDINGS TABLE ──────────────────────────────────────
    _hdr("VULNERABILITY FINDINGS")

    rows = []
    for f in unique:
        dep      = f["dep"]
        safe     = f.get("safe_version", "")
        latest   = f.get("latest_version", "")
        can_fix  = bool(safe) and safe != dep["version"]
        safe_str = safe if can_fix else "(manual)"
        artifact = dep["artifactId"] + (" (T)" if dep.get("transitive") else "")
        try:
            no_higher = (not latest) or (_version_tuple(latest) <= _version_tuple(dep["version"]))
        except Exception:
            no_higher = not latest
        latest_str = "(none higher)" if no_higher else latest
        rows.append({
            "artifact":  artifact,
            "current":   dep["version"],
            "safe":      safe_str,
            "latest":    latest_str,
            "cves":      str(len(f["vulns"])),
            "sev":       f"[{f['severity']:<8}]",
            "sev_raw":   f["severity"],
            "can_fix":   can_fix,
            "no_higher": no_higher,
        })

    hdr_cols = ["Component", "Current", "Fixed To", "Latest", "CVEs", "Severity"]
    key_cols = ["artifact", "current", "safe", "latest", "cves", "sev"]
    cw_f = [max(len(hdr_cols[i]), max(len(r[k]) for r in rows))
            for i, k in enumerate(key_cols)]

    print(_sep(cw_f, "┌", "┬", "┐"))
    print(_row(cw_f, hdr_cols, [C.BOLD] * len(hdr_cols)))
    print(_sep(cw_f))
    for i, r in enumerate(rows):
        sev_c  = SEV_COLOR.get(r["sev_raw"], C.WHITE)
        safe_c = C.GREEN if r["can_fix"] else C.YELLOW
        lat_c  = C.YELLOW if r["no_higher"] else C.BLUE
        vals   = [r["artifact"], r["current"], r["safe"], r["latest"], r["cves"], r["sev"]]
        clrs   = ["", C.RED, safe_c, lat_c, sev_c, sev_c]
        print(_row(cw_f, vals, clrs))
        if i < len(rows) - 1:
            print(_sep(cw_f))
    print(_sep(cw_f, "└", "┴", "┘"))
    if any(f["dep"].get("transitive") for f in unique):
        print(f"  {C.GRAY}  (T) = transitive dependency (pinned via dependencyManagement){C.RESET}")
    if total_occ > len(unique):
        print(f"  {C.GRAY}  Showing {len(unique)} unique package(s) — {total_occ} total occurrences across modules{C.RESET}")

    # ── 3. VULNERABILITY DETAILS (per-CVE cards) ─────────────────────────────
    W = 70
    _hdr("VULNERABILITY DETAILS")
    for idx, f in enumerate(unique, 1):
        dep     = f["dep"]
        safe    = f.get("safe_version", "")
        latest  = f.get("latest_version", "")
        can_fix = bool(safe) and safe != dep["version"]
        sev_c   = SEV_COLOR.get(f["severity"], C.WHITE)
        trans   = "  [transitive]" if dep.get("transitive") else ""
        comp    = f"{dep['groupId']} : {dep['artifactId']}{trans}"
        title_body = f"─[ #{idx}  {comp} ]"
        tail       = "─" * max(2, W - len(title_body))
        print()
        print(f"  {C.CYAN}┌{title_body}{tail}{C.RESET}")
        print(f"  {C.CYAN}│{C.RESET}  {'Version':<12}  "
              f"{C.RED}{dep['version']}{C.RESET}"
              f"{C.GRAY}  ← VULNERABLE{C.RESET}"
              f"{'':>6}Severity : {sev_c}[{f['severity']:<8}]{C.RESET}")
        if f.get("bundled_via"):
            via_str = ", ".join(f["bundled_via"])
            print(f"  {C.CYAN}│{C.RESET}  {'Bundles':<12}  "
                  f"{C.GRAY}{via_str}{C.RESET}")
        if can_fix:
            print(f"  {C.CYAN}│{C.RESET}  {'Next Safe':<12}  "
                  f"{C.GREEN}{safe}{C.RESET}"
                  f"  {C.GRAY}← minimum version with no known CVEs{C.RESET}")
        else:
            print(f"  {C.CYAN}│{C.RESET}  {'Next Safe':<12}  "
                  f"{C.YELLOW}Manual action required{C.RESET}"
                  f"  {C.GRAY}(no safe version on Maven Central){C.RESET}")
        if latest:
            print(f"  {C.CYAN}│{C.RESET}  {'Latest':<12}  {C.BLUE}{latest}{C.RESET}")
        elif safe:
            print(f"  {C.CYAN}│{C.RESET}  {'Latest':<12}  {C.BLUE}{safe}{C.RESET}"
                  f"  {C.GRAY}(Maven Central metadata unavailable){C.RESET}")
        print(f"  {C.CYAN}│{C.RESET}")
        print(f"  {C.CYAN}│{C.RESET}  Vulnerabilities ({len(f['vulns'])}):")
        for v in f["vulns"]:
            source  = v.get("source", "OSV")
            if source == "NVD":
                display_id = v.get("id", "")
                id_type    = "NVD"
            else:
                aliases    = v.get("aliases", [])
                cve_ids    = [a for a in aliases if a.startswith("CVE-")]
                ghsa_ids   = [a for a in aliases if a.startswith("GHSA-")]
                osv_id     = v.get("id", "")
                display_id = cve_ids[0] if cve_ids else (ghsa_ids[0] if ghsa_ids else osv_id)
                id_type    = "CVE " if display_id.startswith("CVE-") else \
                             "GHSA" if display_id.startswith("GHSA-") else "OSV "
            vuln_sev = get_vuln_severity(v)
            sev_c2   = SEV_COLOR.get(vuln_sev, C.WHITE)
            summary  = v.get("summary", "").strip()
            print(f"  {C.CYAN}│{C.RESET}")
            print(f"  {C.CYAN}│{C.RESET}    [{id_type}] {C.YELLOW}{display_id}{C.RESET}"
                  f"   Severity: {sev_c2}[{vuln_sev:<8}]{C.RESET}")
            if v.get("kev"):
                print(f"  {C.CYAN}│{C.RESET}           {C.RED}{C.BOLD}⚠  ACTIVELY EXPLOITED (CISA KEV){C.RESET}")
            epss = v.get("epss_score")
            if epss is not None:
                pct = v.get("epss_percentile", 0) or 0
                epss_bar = "█" * int(epss * 20)
                print(f"  {C.CYAN}│{C.RESET}           {C.GRAY}EPSS {epss:.4f}"
                      f"  ({pct*100:.1f}th pct)  {epss_bar}{C.RESET}")
            if summary:
                words, line, first = summary.split(), "", True
                for word in words:
                    if len(line) + len(word) + 1 > 54:
                        indent = "    " if first else "         "
                        print(f"  {C.CYAN}│{C.RESET}           {C.GRAY}{indent}{line}{C.RESET}")
                        line, first = word, False
                    else:
                        line = (line + " " + word).strip()
                if line:
                    indent = "    " if first else "         "
                    print(f"  {C.CYAN}│{C.RESET}           {C.GRAY}{indent}{line}{C.RESET}")
        print(f"  {C.CYAN}└{'─' * W}{C.RESET}")


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
            "  --offline                 Skip all API calls (useful for air-gapped environments)\n"
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
            "Environment Variables:\n"
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
    parser.add_argument("--offline", action="store_true",
                        help="Skip all API calls (useful for air-gapped environments)")
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

    # ── SCAN REPORT (single consolidated report for all modules) ──────────────
    total_deps = sum(r["deps"] for r in module_results)


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

    print_report(all_findings, total_deps, skip_set=skip_set, exec_info=_report_exec_info)

    # ── PDF Report ────────────────────────────────────────────────────────────
    if args.scan:
        _scan_exec_info = {
            **_report_exec_info,
            "maven_status":   None,
            "maven_duration": 0.0,
            "total_findings": len({f"{f['dep']['groupId']}:{f['dep']['artifactId']}" for f in all_findings}),
        }
        pdf_path = _generate_pdf_report(all_findings, total_deps, args.project_path,
                                          module_results=module_results,
                                          exec_info=_scan_exec_info,
                                          skip_set=skip_set)
        if pdf_path:
            print(f"\n  {C.GREEN}[PDF]{C.RESET}  Report saved → {C.CYAN}{pdf_path}{C.RESET}")

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

        def _vb_table(rows_data, title):
            if not rows_data:
                return
            print(f"\n  {C.CYAN}{title}{C.RESET}")
            HDR  = ["Artifact", "Group", "Current", "Fixed To", "Latest", "Severity", "CVEs"]
            data = []
            for f in rows_data:
                dep     = f["dep"]
                safe    = f.get("safe_version", "")
                latest  = f.get("latest_version", "")
                can_fix = bool(safe) and safe != dep["version"]
                try:
                    no_higher = (not latest) or (_version_tuple(latest) <= _version_tuple(dep["version"]))
                except Exception:
                    no_higher = not latest
                data.append([
                    dep["artifactId"],
                    dep["groupId"],
                    dep["version"],
                    safe if can_fix else "(manual)",
                    "(none higher)" if no_higher else latest,
                    f"[{f.get('severity', ''):<8}]",
                    str(len(f.get("vulns", []))),
                    can_fix,
                    no_higher,
                    f.get("severity", ""),  # raw sev for colour lookup (index 9)
                ])
            cw = [max(len(HDR[i]), max(len(r[i]) for r in data))
                  for i in range(len(HDR))]

            def _vs(l="├", m="┼", r="┤"):
                return "  " + l + m.join("─" * (w + 2) for w in cw) + r

            def _vr(vals, colors=None):
                parts = []
                for i, v in enumerate(vals):
                    clr = (colors[i] if colors else "") or ""
                    n   = cw[i] - len(v)
                    if clr:
                        pad = (C.BOLD + " " * n + C.RESET) if (n > 0 and C.BOLD) else " " * n
                        parts.append(f" {clr}{v}{C.RESET}{pad} ")
                    else:
                        parts.append(f" {v}{' ' * n} ")
                return "  │" + "│".join(parts) + "│"

            print(_vs("┌", "┬", "┐"))
            print(_vr(HDR, [C.BOLD] * len(HDR)))
            print(_vs())
            for i, r in enumerate(data):
                sev_c  = SEV_COLOR.get(r[9], C.WHITE)
                safe_c = C.GREEN if r[7] else C.YELLOW
                lat_c  = C.YELLOW if r[8] else C.BLUE
                print(_vr(r[:7], ["", C.GRAY, C.RED, safe_c, lat_c, sev_c, sev_c]))
                if i < len(data) - 1:
                    print(_vs())
            print(_vs("└", "┴", "┘"))

        _vb_table(direct_vb,
                  f"Direct dependencies  [{len(direct_vb)} package(s)]:")
        _vb_table(trans_vb,
                  f"Transitive dependencies  [{len(trans_vb)} package(s)"
                  f" — pinned via dependencyManagement]:")

    # >> Fix Details table
    if all_applied or all_skipped:
        print()
        print(f"  {C.BOLD}>> Fix Details{C.RESET}")
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
        all_fix_rows = (
            [(C.GREEN, "[FIXED]", r[0], r[1], r[2] if len(r) > 2 else "") for r in FA] +
            [(C.YELLOW, "[SKIP ]", r[0], r[1], r[2] if len(r) > 2 else "") for r in FS]
        )
        WS = max(len(r[1]) for r in all_fix_rows)
        WM = max(len(r[2]) for r in all_fix_rows)
        WC = max(len(r[3]) for r in all_fix_rows)
        WA = max(len(r[4]) for r in all_fix_rows) if any(r[4] for r in all_fix_rows) else 0

        def _fix_row(clr, status, mod, comp, action):
            base = f"  │ {clr}{status}{C.RESET} │ {mod:<{WM}} │ {comp:<{WC}}"
            if WA:
                act_n = max(0, WA - len(action))
                act_p = (C.BOLD + " " * act_n + C.RESET) if (act_n > 0 and C.BOLD) else " " * act_n
                return base + f" │ {clr}{action}{C.RESET}{act_p} │"
            return base + " │"

        top = f"  ┌{'─'*(WS+2)}┬{'─'*(WM+2)}┬{'─'*(WC+2)}" + (f"┬{'─'*(WA+2)}┐" if WA else "┐")
        mid = f"  ├{'─'*(WS+2)}┼{'─'*(WM+2)}┼{'─'*(WC+2)}" + (f"┼{'─'*(WA+2)}┤" if WA else "┤")
        bot = f"  └{'─'*(WS+2)}┴{'─'*(WM+2)}┴{'─'*(WC+2)}" + (f"┴{'─'*(WA+2)}┘" if WA else "┘")

        hdr_s = C.BOLD + "Status" + C.RESET
        hdr_m = C.BOLD + "Module" + C.RESET
        hdr_c = C.BOLD + "Component" + C.RESET
        hdr_a = C.BOLD + "Version Change" + C.RESET
        print(top)
        if WA:
            print(f"  │ {hdr_s}{' '*(WS-6)} │ {hdr_m}{' '*(WM-6)} │ {hdr_c}{' '*(WC-9)} │ {hdr_a}{' '*(WA-14)} │")
        else:
            print(f"  │ {hdr_s}{' '*(WS-6)} │ {hdr_m}{' '*(WM-6)} │ {hdr_c}{' '*(WC-9)} │")
        print(mid)
        for i, (clr, status, mod, comp, action) in enumerate(all_fix_rows):
            print(_fix_row(clr, status, mod, comp, action))
            if i < len(all_fix_rows) - 1:
                print(mid)
        print(bot)

    # >> Git Commit Verification
    if git_info:
        print()
        print(f"  {C.BOLD}>> Git Commit Verification{C.RESET}")
        status_clr = C.GREEN if "committed" in git_info["status"] else C.YELLOW
        git_rows = [
            ("Fortify ID",        args.commit or "",                                 C.WHITE),
            ("Branch",         git_info["branch"],                                C.CYAN),
            ("Created From",   git_info.get("base_branch", "master"),             C.GRAY),
            ("Commit Hash",    git_info["hash"] or "n/a",                         C.WHITE),
            ("Commit Message", git_info["message"],                               C.WHITE),
            ("Status",         git_info["status"],                                status_clr),
            ("Pushed",         "Yes" if git_info["pushed"] else "No (run with --push)",
                               C.GREEN if git_info["pushed"] else C.YELLOW),
        ]
        GK = max(len(r[0]) for r in git_rows)
        GV = min(max(len(r[1]) for r in git_rows), 52)  # cap value column at 52 chars
        top_g = f"  ┌{'─'*(GK+2)}┬{'─'*(GV+2)}┐"
        mid_g = f"  ├{'─'*(GK+2)}┼{'─'*(GV+2)}┤"
        bot_g = f"  └{'─'*(GK+2)}┴{'─'*(GV+2)}┘"
        title = "Git Commit Verification"
        print(top_g)
        print(f"  │ {C.BOLD}{title:<{GK+GV+3}}{C.RESET} │")
        print(f"  ├{'─'*(GK+2)}┬{'─'*(GV+2)}┤")
        for i, (key, val, clr) in enumerate(git_rows):
            # wrap long values across multiple lines within the column
            chunks = [val[j:j+GV] for j in range(0, max(len(val), 1), GV)]
            for ci, chunk in enumerate(chunks):
                k_str = key if ci == 0 else ""
                chunk_n = max(0, GV - len(chunk))
                chunk_p = (C.BOLD + " " * chunk_n + C.RESET) if (chunk_n > 0 and C.BOLD) else " " * chunk_n
                print(f"  │ {k_str:<{GK}} │ {clr}{chunk}{C.RESET}{chunk_p} │")
            if i < len(git_rows) - 1:
                print(mid_g)
        print(bot_g)

    print()
    print(f"  Next step  :  {C.CYAN}mvn clean verify{C.RESET}")
    print(f"{C.CYAN}{'=' * 68}{C.RESET}")

    # ── PDF Report (commit/fix mode — includes Phase 5 fix details) ───────────
    if not args.scan:
        _gi = None
        if git_info:
            _gi = {
                "jira":          args.jira_id or "",
                "branch":        git_info.get("branch", ""),
                "base_branch":   git_info.get("base_branch", ""),
                "hash":          git_info.get("hash", ""),
                "full_hash":     git_info.get("full_hash", ""),
                "message":       git_info.get("message", ""),
                "body":          git_info.get("body", ""),
                "status":        git_info.get("status", ""),
                "pushed":        git_info.get("pushed", False),
                "author":        git_info.get("author", ""),
                "email":         git_info.get("email", ""),
                "timestamp":     git_info.get("timestamp", ""),
                "remote_url":    git_info.get("remote_url", ""),
                "files_changed": git_info.get("files_changed", []),
                "repo_root":     git_info.get("repo_root", ""),
            }
        pdf_path = _generate_pdf_report(
            all_findings, total_deps, args.project_path,
            applied=all_applied, skipped=all_skipped, git_info=_gi,
            module_results=module_results, exec_info=exec_info,
            skip_set=skip_set
        )
        if pdf_path:
            print(f"\n  {C.GREEN}[PDF]{C.RESET}  Report saved → {C.CYAN}{pdf_path}{C.RESET}")

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