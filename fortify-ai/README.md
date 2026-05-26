\# FortifyAI



Automated security dependency remediation pipeline for Maven projects. Scans Fortify SSC findings, resolves safe upgrade versions, applies fixes via ADR, validates the build, and opens a GitHub PR — all without manual intervention.



\---



\## CLI Usage



```bash

\# Start the API server

uvicorn api\_server:app --host 0.0.0.0 --port 8000 --reload

```



\---



\## `fortifyai.py` Commands



\### Basic



```bash

\# Run by release ID

python fortifyai.py --release 1723380



\# Run by application name (resolves latest release automatically)

python fortifyai.py --app-name 1038\_US\_D360-Citi-Triggers-on-Cloud\_USIS



\# List all releases for an app, then exit (no pipeline run)

python fortifyai.py --app-name 1038\_US\_D360-Citi-Triggers-on-Cloud\_USIS --list-releases

```



\### Repo Override



```bash

\# Override GITHUB\_REPO from .env at runtime (triggers auto-clone)

python fortifyai.py --release 1723380 --repo org/repo\_name



\# Combined with app-name

python fortifyai.py --app-name 1038\_US\_D360-Citi-Triggers-on-Cloud\_USIS --repo acme/backend

```



\### Offline Mode



```bash

\# Run from a saved JSON report — no Fortify SSC credentials needed

python fortifyai.py --report report.json



\# Offline + repo override

python fortifyai.py --report report.json --repo org/repo\_name

```



\### Max Upgrades



```bash

\# Limit to 5 deps per run, highest severity processed first

python fortifyai.py --release 1723380 --max-upgrades 5



\# Combined with app-name and repo

python fortifyai.py --app-name MyApp --max-upgrades 3 --repo acme/backend

```



\### Debug Logging



```bash

python fortifyai.py --release 1723380 --verbose

python fortifyai.py --app-name 1038\_US\_D360-Citi-Triggers-on-Cloud\_USIS --list-releases --verbose

```



\---



\## REST API



\### Utility



```

GET  /health                          # Liveness probe

GET  /config/validate                 # Validate current .env config

POST /auth/token                      # Fetch / refresh Fortify Bearer token

GET  /releases?app\_name=<name>        # List releases for an app

GET  /releases?app\_id=<id>            # List releases by app ID (skips name lookup)

GET  /resolve/app-name?app\_name=<name># Resolve name → app\_id + latest release\_id

```



\### Pipeline Status



```

GET /pipeline/status/{pipeline\_id}              # Overall status + all stage statuses

GET /pipeline/status/{pipeline\_id}/{stage\_name} # Status of a single stage

```



Stage names: `triage` · `version-resolver` · `context` · `api-diff` · `ai-reasoning` · `adr-fix` · `pr-agent` · `fortify-writeback`



\---



\### Full Pipeline Endpoints



All `/pipeline/\*` endpoints are \*\*async\*\* — they return a `pipeline\_id` immediately. Poll `GET /pipeline/status/{pipeline\_id}` to track progress.



\#### `POST /pipeline/live`

Full pipeline against a live Fortify SSC release.



```json

{

&#x20; "release\_id": 1723380,

&#x20; "max\_upgrades": 3,

&#x20; "config": {

&#x20;   "github\_repo": "acme/backend"

&#x20; }

}

```



\#### `POST /pipeline/offline`

Full pipeline from a saved JSON report — no SSC credentials needed.



```json

{

&#x20; "report\_path": "/tmp/report.json",

&#x20; "release\_id": 0,

&#x20; "max\_upgrades": 5,

&#x20; "config": {}

}

```



\#### `POST /pipeline/app-name`

Resolves app name → `app\_id` → latest `release\_id`, then runs the full pipeline.



```json

{

&#x20; "app\_name": "1038\_US\_MyApp\_USIS",

&#x20; "repo": "acme/backend",

&#x20; "max\_upgrades": 3,

&#x20; "config": {}

}

```



\#### `POST /pipeline/app-id`

Skips name lookup — resolves `app\_id` → latest `release\_id` directly.



```json

{

&#x20; "app\_id": 147266,

&#x20; "max\_upgrades": 3,

&#x20; "config": {}

}

```



\#### `POST /pipeline/dry-run`

Full analysis pipeline \*\*without\*\* side effects. ADR, PR creation, and Fortify writeback are skipped.



```json

{

&#x20; "release\_id": 1723380,

&#x20; "report\_path": null,

&#x20; "app\_name": null,

&#x20; "max\_upgrades": 5,

&#x20; "config": {}

}

```



\---



\### Partial Pipeline Endpoints



Stop the pipeline at a specific stage. All return a `pipeline\_id` immediately.



```

POST /pipeline/until/triage

POST /pipeline/until/version-resolver

POST /pipeline/until/context

POST /pipeline/until/api-diff

POST /pipeline/until/ai-reasoning

POST /pipeline/until/adr-fix

POST /pipeline/until/pr-agent

```



Request body is the same shape as the full pipeline endpoints (`release\_id`, `report\_path`, `app\_name`, `app\_id`, `max\_upgrades`, `config`).



\---



\### Individual Stage Endpoints



Call any stage in isolation.



```

POST /stages/triage             # Stage 1: filter \& group raw vulnerabilities

POST /stages/version-resolver   # Stage 2: resolve safe version candidates

POST /stages/context            # Stage 3: locate dep in codebase

POST /stages/api-diff           # Stage 4: run japicmp API diff

POST /stages/ai-reasoning       # Stage 5: AI safety verdict

POST /stages/adr-fix            # Stage 6: invoke adr.py --commit --push

POST /stages/ai-code-fix        # Stage 7: AI patch for broken call sites

POST /stages/pr-agent           # Stage 8: create GitHub PR

POST /stages/fortify-writeback  # Stage 9: post outcome comment to SSC

```



\---



\## `config` Object (ConfigOverrides)



All pipeline request bodies accept an optional `config` block to override `.env` values per-request.



| Field              | Type    | Description                                              |

|--------------------|---------|----------------------------------------------------------|

| `fortify\_base\_url` | string  | Fortify SSC base URL                                     |

| `fortify\_api\_token`| string  | Fortify Bearer token                                     |

| `github\_token`     | string  | GitHub personal access token                             |

| `github\_repo`      | string  | GitHub repo in `owner/repo` format                       |

| `project\_path`     | string  | Absolute path to Maven project root                      |

| `adr\_path`         | string  | Absolute path to `adr.py`                                |

| `japicmp\_jar\_path` | string  | Absolute path to japicmp fat-jar                         |

| `gcp\_project`      | string  | GCP project ID for Vertex AI                             |

| `gcp\_location`     | string  | GCP region (default: `us-central1`)                      |

| `max\_retries`      | int     | Max AI code-fix retries before escalating (1–10)         |

| `max\_upgrades`     | int     | Max deps to upgrade per run — `0` = unlimited            |

| `jira\_id\_prefix`   | string  | Prefix for JIRA IDs in commit/branch names               |

| `reviewers`        | string  | Comma-separated GitHub usernames for PR auto-assign      |

| `adr\_output\_dir`   | string  | Directory for ADR PDF reports and logs                   |

