"""
FortifyAI — Fortify API Client
--------------------------------
All Fortify SSC REST API calls live here.  One class, one HTTP session,
one place to change if the API version ever moves.

Auth header:  Authorization: FortifyToken <token>
Base path:    /api/v3/

Endpoints used:
  GET  /api/v3/applications                                                — list / filter by name
  GET  /api/v3/applications/{applicationId}/releases                       — all releases or latest-first
  GET  /api/v3/releases/{releaseId}/vulnerabilities
  GET  /api/v3/releases/{releaseId}/vulnerabilities/{vulnId}/recommendations
  POST /api/v3/releases/{releaseId}/vulnerabilities/{vulnId}/comments

Name-based lookup helpers (new):
  get_application_by_name(name)          -> application dict
  get_latest_release(application_id)     -> release dict (most recent by createdDate)
  resolve_release_id_from_app_name(name) -> int releaseId (combines both steps)
"""

from __future__ import annotations

import time
from typing import Optional
from urllib.parse import urljoin

import requests
from loguru import logger
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config import FortifyAIConfig


# ── Helpers ───────────────────────────────────────────────────────────────────

def parse_primary_location(primary_location: str) -> dict:
    """
    Parse a Fortify primaryLocation string into its components.

    Example:
        "org.springframework:spring-context@5.3.31"
        → {"group_id": "org.springframework",
           "artifact_id": "spring-context",
           "current_version": "5.3.31"}

    Raises ValueError if the string does not match expected format.
    """
    try:
        group_artifact, version = primary_location.split("@", 1)
        group_id, artifact_id = group_artifact.split(":", 1)
        return {
            "group_id": group_id,
            "artifact_id": artifact_id,
            "current_version": version,
        }
    except ValueError as exc:
        raise ValueError(
            f"Cannot parse primaryLocation '{primary_location}': "
            "expected format 'groupId:artifactId@version'"
        ) from exc


# ── Client ────────────────────────────────────────────────────────────────────

class FortifyClient:
    """
    Thin wrapper around the Fortify SSC v3 REST API.

    Usage:
        client = FortifyClient.from_config(config)
        vulns = client.get_vulnerabilities(release_id=1723380)
    """

    _PAGE_SIZE = 50          # items per page for paginated endpoints
    _REQUEST_TIMEOUT = 60    # seconds per HTTP call

    def __init__(self, base_url: str, api_token: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._session = self._build_session(api_token)

    # ── Constructor helpers ───────────────────────────────────────────────────

    @classmethod
    def from_config(cls, config: FortifyAIConfig) -> "FortifyClient":
        return cls(
            base_url=config.fortify_base_url,
            api_token=config.fortify_api_token,
        )

    @staticmethod
    def _build_session(api_token: str) -> requests.Session:
        """Create a requests.Session with retry logic and auth header."""
        session = requests.Session()
        session.headers.update({
            "Authorization": f"Bearer {api_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        })

        # Retry on 429 (rate limit) and 5xx server errors
        retry = Retry(
            total=4,
            backoff_factor=1.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    # ── Internal HTTP ─────────────────────────────────────────────────────────

    def _url(self, path: str) -> str:
        """Build a full URL from a relative API path."""
        return urljoin(self._base_url + "/", path.lstrip("/"))

    def _get(self, path: str, params: Optional[dict] = None) -> dict:
        """GET a single JSON response; raise on HTTP error."""
        url = self._url(path)
        logger.debug(f"[FortifyClient] GET {url} params={params}")
        resp = self._session.get(url, params=params, timeout=self._REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    def _get_all_pages(self, path: str, params: Optional[dict] = None) -> list[dict]:
        """
        Paginate through all pages of a collection endpoint.
        Fortify v3 uses offset/limit pagination; items live under response["items"].
        """
        params = dict(params or {})
        params["limit"] = self._PAGE_SIZE
        params["offset"] = 0

        all_items: list[dict] = []

        while True:
            data = self._get(path, params)
            items = data.get("items", [])
            all_items.extend(items)

            total = data.get("totalCount", len(all_items))
            fetched = params["offset"] + len(items)

            logger.debug(
                f"[FortifyClient] Page fetched: {len(items)} items "
                f"({fetched}/{total})"
            )

            if fetched >= total or not items:
                break

            params["offset"] = fetched

        return all_items

    def _post(self, path: str, body: dict) -> dict:
        """POST JSON body; raise on HTTP error."""
        url = self._url(path)
        logger.debug(f"[FortifyClient] POST {url}")
        resp = self._session.post(url, json=body, timeout=self._REQUEST_TIMEOUT)
        resp.raise_for_status()
        # Some POST endpoints return 204 No Content
        if resp.status_code == 204 or not resp.content:
            return {}
        return resp.json()

    # ── Public API methods ────────────────────────────────────────────────────

    def get_applications(self) -> list[dict]:
        """
        GET /api/v3/applications
        Returns all applications visible to the API token.
        """
        logger.info("[FortifyClient] Fetching all applications")
        apps = self._get_all_pages("/api/v3/applications")
        logger.info(f"[FortifyClient] Found {len(apps)} application(s)")
        return apps

    def get_application_by_name(self, application_name: str) -> dict:
        """
        GET /api/v3/applications?filters=applicationName:<name>
        Looks up an application by its exact name and returns the application dict.

        The Fortify API uses server-side filter syntax:
            filters=applicationName:<value>

        Raises:
            ValueError  — if no application matches the given name.
            ValueError  — if more than one application matches (ambiguous).
        """
        logger.info(f"[FortifyClient] Looking up application by name: '{application_name}'")
        params = {"filters": f"applicationName:{application_name}"}
        data = self._get("/api/v3/applications", params=params)
        items: list[dict] = data.get("items", [])

        if not items:
            raise ValueError(
                f"No Fortify application found with name '{application_name}'. "
                "Check the spelling or use get_applications() to list all available names."
            )
        if len(items) > 1:
            names = [a.get("applicationName") for a in items]
            raise ValueError(
                f"Ambiguous application name '{application_name}': "
                f"matched {len(items)} applications: {names}. "
                "Provide a more specific name."
            )

        app = items[0]
        logger.info(
            f"[FortifyClient] Resolved '{application_name}' → "
            f"applicationId={app.get('applicationId')}"
        )
        return app

    def get_latest_release(self, application_id: int) -> dict:
        """
        GET /api/v3/applications/{applicationId}/releases
            ?orderBy=releaseCreatedDate&orderByDirection=DESC&limit=1

        Returns the single most-recently-created release for the application.

        Raises:
            ValueError — if the application has no releases.
        """
        logger.info(
            f"[FortifyClient] Fetching latest release for application {application_id}"
        )
        path = f"/api/v3/applications/{application_id}/releases"
        params = {
            "orderBy": "releaseCreatedDate",
            "orderByDirection": "DESC",
            "limit": 1,
            "offset": 0,
        }
        data = self._get(path, params=params)
        items: list[dict] = data.get("items", [])

        if not items:
            raise ValueError(
                f"Application {application_id} has no releases. "
                "A scan must be submitted before FortifyAI can remediate."
            )

        release = items[0]
        logger.info(
            f"[FortifyClient] Latest release → "
            f"releaseId={release.get('releaseId')}, "
            f"releaseName='{release.get('releaseName')}', "
            f"createdDate={release.get('releaseCreatedDate')}"
        )
        return release

    def resolve_release_id_from_app_name(self, application_name: str) -> int:
        """
        Convenience: resolve an application name → latest releaseId in one call.

        Equivalent to:
            app     = client.get_application_by_name(application_name)
            release = client.get_latest_release(app["applicationId"])
            return  release["releaseId"]

        Raises ValueError on lookup failure (propagated from both helpers).
        """
        app = self.get_application_by_name(application_name)
        release = self.get_latest_release(app["applicationId"])
        release_id: int = release["releaseId"]
        logger.info(
            f"[FortifyClient] Resolved '{application_name}' "
            f"→ applicationId={app['applicationId']} "
            f"→ releaseId={release_id}"
        )
        return release_id

    def get_all_releases_by_app_name(
        self,
        application_name: str,
        order_by: str = "releaseCreatedDate",
        order_direction: str = "DESC",
    ) -> tuple[dict, list[dict]]:
        """
        Convenience: resolve an application name -> all of its releases.

        GET /api/v3/applications?filters=applicationName:<name>
          then
        GET /api/v3/applications/{applicationId}/releases
            ?orderBy=<order_by>&orderByDirection=<order_direction>

        Parameters:
            application_name  — exact Fortify application name
            order_by          — field to sort releases by (default: releaseCreatedDate)
            order_direction   — "ASC" or "DESC" (default: DESC = newest first)

        Returns:
            (app, releases)
                app      — application dict (applicationId, applicationName, …)
                releases — list of all release dicts, sorted as requested

        Raises:
            ValueError — propagated from get_application_by_name if name not found
            ValueError — if the application has no releases
        """
        app = self.get_application_by_name(application_name)
        app_id: int = app["applicationId"]

        logger.info(
            f"[FortifyClient] Fetching all releases for "
            f"'{application_name}' (applicationId={app_id})"
        )
        path = f"/api/v3/applications/{app_id}/releases"
        params = {
            "orderBy": order_by,
            "orderByDirection": order_direction,
        }
        releases = self._get_all_pages(path, params)

        if not releases:
            raise ValueError(
                f"Application '{application_name}' (id={app_id}) has no releases. "
                "A scan must be submitted before FortifyAI can list releases."
            )

        logger.info(
            f"[FortifyClient] Found {len(releases)} release(s) "
            f"for '{application_name}'"
        )
        return app, releases

    def print_releases_summary(
        self,
        application_name: str,
        order_direction: str = "DESC",
    ) -> tuple[dict, list[dict]]:
        """
        Fetch and pretty-print all releases for an application name.

        Console output (newest-first by default):

            Application : 1038_US_D360-Citi-Triggers-on-Cloud_USIS  (id=147266)
            Total       : 15 release(s)

            #   releaseId   releaseName                      created              status      rating  C  H  M  L
            1   1723380     production_release_2026Q1.A0     2026-03-17T07:29:51  Completed   2       0  2  0  3
            2   ...

        Returns (app, releases) so callers can act on the data without a second API call.
        """
        app, releases = self.get_all_releases_by_app_name(
            application_name, order_direction=order_direction
        )

        app_name = app.get("applicationName", application_name)
        app_id   = app.get("applicationId")

        sep = "=" * 90
        header = (
            f"\n{sep}\n"
            f"  Application : {app_name}  (id={app_id})\n"
            f"  Total       : {len(releases)} release(s)\n"
            f"{sep}"
        )
        logger.info(header)

        col_fmt = (
            "{idx:<4} {rid:<12} {name:<40} {created:<22} "
            "{status:<12} {rating:<7} {c:<3} {h:<3} {m:<3} {l:<3}"
        )
        col_header = col_fmt.format(
            idx="#", rid="releaseId", name="releaseName",
            created="created", status="status",
            rating="rating", c="C", h="H", m="M", l="L",
        )
        logger.info(col_header)
        logger.info("-" * 90)

        for idx, rel in enumerate(releases, start=1):
            created_raw = rel.get("releaseCreatedDate", "")
            created = created_raw[:19] if created_raw else ""
            logger.info(
                col_fmt.format(
                    idx=idx,
                    rid=rel.get("releaseId", ""),
                    name=(rel.get("releaseName") or "")[:40],
                    created=created,
                    status=(rel.get("currentAnalysisStatusType") or "")[:12],
                    rating=rel.get("rating", ""),
                    c=rel.get("critical", 0),
                    h=rel.get("high", 0),
                    m=rel.get("medium", 0),
                    l=rel.get("low", 0),
                )
            )

        logger.info("=" * 90)
        return app, releases

    def get_releases(self, application_id: int) -> list[dict]:
        """
        GET /api/v3/applications/{applicationId}/releases
        Returns all releases for a given application.
        """
        logger.info(f"[FortifyClient] Fetching releases for application {application_id}")
        path = f"/api/v3/applications/{application_id}/releases"
        releases = self._get_all_pages(path)
        logger.info(
            f"[FortifyClient] Found {len(releases)} release(s) "
            f"for application {application_id}"
        )
        return releases

    def get_vulnerabilities(self, release_id: int) -> list[dict]:
        """
        GET /api/v3/releases/{releaseId}/vulnerabilities
        Returns all OSS vulnerabilities for a release.

        Filters applied server-side (where supported by API):
          - category = Open Source
          - isSuppressed = false

        Client-side filter also applied for robustness (API filter availability
        varies by SSC version).
        """
        logger.info(f"[FortifyClient] Fetching vulnerabilities for release {release_id}")

        path = f"/api/v3/releases/{release_id}/vulnerabilities"
        params = {
            # Server-side filters (Fortify v3 supports these as query params)
            "filters": "category:Open Source+isSuppressed:false",
        }

        raw = self._get_all_pages(path, params)

        # Client-side guard — ensures correctness regardless of server filter support
        vulns = [
            v for v in raw
            if v.get("category") == "Open Source"
            and not v.get("isSuppressed", False)
        ]

        logger.info(
            f"[FortifyClient] {len(vulns)} OSS vulnerability/ies returned "
            f"(of {len(raw)} total items before client filter)"
        )
        return vulns

    def get_recommendations(self, release_id: int, vuln_id: str) -> dict:
        """
        GET /api/v3/releases/{releaseId}/vulnerabilities/{vulnId}/recommendations
        Returns Sonatype recommendation data including safe upgrade versions.

        Key fields returned:
          sonatype.nextNonVulnerableVersion   — minimum safe version
          sonatype.greatestNonVulnerableVersion — latest safe version
          sonatype.explanation                — human-readable risk summary
          sonatype.links                      — advisory references
        """
        logger.debug(
            f"[FortifyClient] Fetching recommendations for vuln {vuln_id} "
            f"(release {release_id})"
        )
        path = (
            f"/api/v3/releases/{release_id}"
            f"/vulnerabilities/{vuln_id}/recommendations"
        )
        data = self._get(path)
        logger.debug(
            f"[FortifyClient] Recommendations received for {vuln_id}: "
            f"nextNonVulnerableVersion="
            f"{data.get('sonatype', {}).get('nextNonVulnerableVersion')}"
        )
        return data

    def post_comment(
        self,
        release_id: int,
        vuln_id: str,
        comment: str,
    ) -> dict:
        """
        POST /api/v3/releases/{releaseId}/vulnerabilities/{vulnId}/comments
        Write a comment back to a Fortify vulnerability finding.
        Used by the Fortify Writeback agent (Iteration 11).
        """
        logger.info(
            f"[FortifyClient] Posting comment to vuln {vuln_id} "
            f"(release {release_id})"
        )
        path = (
            f"/api/v3/releases/{release_id}"
            f"/vulnerabilities/{vuln_id}/comments"
        )
        body = {"comment": comment}
        result = self._post(path, body)
        logger.info(f"[FortifyClient] Comment posted to {vuln_id}")
        return result

    # ── Convenience: fetch + print done-when summary ──────────────────────────

    def print_vulnerability_summary(self, release_id: int) -> list[dict]:
        """
        Fetch vulnerabilities and print the Iteration 2 done-when console output:

            Fetched N vulnerabilities
            CVE-2024-38820  spring-context  5.3.31  → safe: 6.1.20
            ...

        Also fetches recommendations for each unique dep.
        Returns the raw vulnerability list.
        """
        vulns = self.get_vulnerabilities(release_id)
        logger.info(f"Fetched {len(vulns)} vulnerabilities")

        # Group by primaryLocation → collect CVEs per dep
        dep_map: dict[str, dict] = {}  # primaryLocation → {cves, vuln_id, parsed}

        for v in vulns:
            loc = v.get("primaryLocation", "")
            cve = v.get("checkId", "")
            vuln_id = v.get("vulnId", "")

            if loc not in dep_map:
                try:
                    parsed = parse_primary_location(loc)
                except ValueError:
                    parsed = {"group_id": "", "artifact_id": loc, "current_version": "?"}
                dep_map[loc] = {
                    "parsed": parsed,
                    "cves": [],
                    "vuln_id": vuln_id,   # use first vuln_id for recommendations lookup
                    "primary_location": loc,
                }

            if cve and cve not in dep_map[loc]["cves"]:
                dep_map[loc]["cves"].append(cve)

        # For each unique dep fetch recommendations and print summary line
        for loc, info in dep_map.items():
            artifact_id = info["parsed"]["artifact_id"]
            version = info["parsed"]["current_version"]
            cves = info["cves"]

            try:
                rec = self.get_recommendations(release_id, info["vuln_id"])
                safe = rec.get("sonatype", {}).get("nextNonVulnerableVersion") or "N/A"
            except Exception as exc:
                logger.warning(f"[FortifyClient] Could not fetch recommendations for {loc}: {exc}")
                safe = "ERROR"

            for cve in cves:
                logger.info(
                    f"{cve:<20} {artifact_id:<20} {version}  → safe: {safe}"
                )

        return vulns