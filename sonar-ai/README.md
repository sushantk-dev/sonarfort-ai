# SonarAI — Iteration 2

> **Agentic AI pipeline**: `sonar-report.json` → clone repo → LLM fix → GitHub PR
>
> **Iteration 2 adds**: multi-issue processing, RAG prior fix retrieval, parallel fan-out,
> Sonar rescan validation, 30-rule KB, LangSmith tracing, pipeline summary report.

---

## Architecture

```
sonar-report.json
      │
      ▼
┌─────────────┐
│   Ingest    │  Parse + sort ALL issues (BLOCKER → INFO)
│ (parser+KB) │  Cap via --max-issues
└──────┬──────┘
       │
       │  ┌─────────────────────────────────────────────────────────┐
       │  │ Per-Issue Loop (sequential) or Send API (parallel)       │
       │  │                                                          │
       │  │  ┌───────────┐   ┌────────────┐   ┌──────────────────┐  │
       │  │  │ Load Repo │──▶│ RAG Fetch  │──▶│    Planner LLM   │  │
       │  │  │(clone+AST)│   │(ChromaDB)  │   │ chain-of-thought  │  │
       │  │  └───────────┘   └────────────┘   └────────┬─────────┘  │
       │  │                                            │             │
       │  │                                   ┌────────▼─────────┐  │
       │  │                                   │  Generator LLM   │  │
       │  │                                   │  unified diff    │  │
       │  │                                   └────────┬─────────┘  │
       │  │                                            │             │
       │  │                                   ┌────────▼─────────┐  │
       │  │                                   │   Critic LLM     │  │
       │  │                                   │ adversarial check │  │
       │  │                                   └────────┬─────────┘  │
       │  │                           rejected (max 1 retry)        │
       │  │                                   ┌────────▼─────────┐  │
       │  │                                   │    Validate      │  │
       │  │                                   │ git+mvn+surefire │  │
       │  │                                   └────────┬─────────┘  │
       │  │                                            │             │
       │  │                  ┌─────────────────────────▼──────────┐ │
       │  │                  │            Deliver                  │ │
       │  │                  │  HIGH  → PR + CODEOWNERS + RAG store│ │
       │  │                  │  MEDIUM → Draft PR + RAG store      │ │
       │  │                  │  LOW   → escalation .md             │ │
       │  │                  │  [optional] Sonar API rescan        │ │
       │  │                  └─────────────────────────────────────┘ │
       │  └─────────────────────────────────────────────────────────┘
       │
       ▼
 Pipeline Summary Report (console + pipeline_summary.json)
```

---

## What's New in Iteration 2

### 1. Multi-Issue Sequential Processing
The pipeline now loops through **all** issues in the Sonar report (BLOCKER → INFO priority order), not just the first one. Use `--max-issues N` to cap.

### 2. RAG Prior Fix Retrieval (ChromaDB)
Before planning each fix, the agent queries a **local ChromaDB vector store** for similar past fixes. Relevant examples are embedded into the Planner prompt as few-shot context, improving fix quality and consistency over time. Successful fixes are automatically stored after PR creation.

### 3. Parallel Fan-Out (LangGraph Send API)
Enable with `--parallel` or `PARALLEL_ISSUES=true`. Issues are dispatched simultaneously via LangGraph's `Send` API, each running its own `load_repo → rag → plan → generate → critique → validate → deliver` subgraph.

### 4. Sonar Rescan Validation
Enable with `--rescan` or `ENABLE_SONAR_RESCAN=true`. After a PR is pushed, the pipeline queries the Sonar API to poll for analysis completion and verify the flagged rule no longer fires. Result shown in the PR body and pipeline summary.

### 5. Expanded Rule KB (10 → 30 rules)
The knowledge base now covers 30 Java rules including:
- Security: S2076 (OS injection), S2083 (path traversal), S2245 (predictable random), S2647 (HTTP auth)
- Concurrency: S3010 (static field race), S2274 (wait without loop), S4834 (sleep in loop)
- Correctness: S1764 (identical operands), S2184 (integer overflow), S1206 (equals/hashCode), S2189 (infinite loop)
- Quality: S2629 (eager log args), S3457 (format mismatch), S1172 (unused param), S1854 (dead store)
- And more...

### 6. LangSmith Tracing
Set `LANGSMITH_API_KEY` to automatically trace all three LLM calls (Planner, Generator, Critic) in LangSmith for debugging and prompt analysis.

### 7. Pipeline Summary Report
After all issues are processed, a summary is printed to the console and written to `pipeline_summary.json` with per-issue outcomes, PR URLs, escalation paths, and Sonar rescan results.

---

## Setup

### 1. Prerequisites
- Python 3.11+
- Java JDK + Maven (for compile/test validation)
- GCP project with Vertex AI enabled
- GitHub personal access token (repo + PR scope)

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Authenticate with GCP
```bash
gcloud auth application-default login
```

### 4. Configure environment
```bash
cp .env.example .env
# Fill in GCP_PROJECT and GITHUB_TOKEN at minimum
```

---

## Usage

### Basic (process all issues, sequential)
```bash
python main.py \
  --report sonar-report.json \
  --repo   https://github.com/owner/repo.git \
  --sha    abc123def456
```

### Iteration 2 — Process top 5 issues in parallel with rescan
```bash
python main.py \
  --report sonar-report.json \
  --repo   https://github.com/owner/repo.git \
  --sha    abc123def456 \
  --max-issues 5 \
  --parallel \
  --rescan \
  --summary
```

### Dry run (preview patches, no PRs)
```bash
python main.py \
  --report sonar-report.json \
  --repo   https://github.com/owner/repo.git \
  --sha    abc123def456 \
  --dry-run
```

### Disable RAG (first run or debugging)
```bash
python main.py ... --no-rag
```

---

## CLI Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--report` | ✅ | Path to `sonar-report.json` |
| `--repo` | ✅ | GitHub HTTPS clone URL |
| `--sha` | ✅ | Exact commit SHA used during the Sonar scan |
| `--max-issues` | ➖ | Cap on issues to process (default: all) |
| `--parallel` | ➖ | Fan-out issues in parallel via Send API |
| `--rescan` | ➖ | Enable Sonar API rescan after each fix |
| `--no-rag` | ➖ | Disable ChromaDB prior fix retrieval |
| `--dry-run` | ➖ | Preview patches without committing |
| `--summary` | ➖ | Print JSON summary to stdout |

---

## Confidence & PR Strategy

| Confidence | Action |
|------------|--------|
| **HIGH** (≥0.8) | Normal PR + auto-assign from CODEOWNERS + stored in RAG |
| **MEDIUM** (≥0.5) | Draft PR + review comment + stored in RAG |
| **LOW** (<0.5) | `escalations/{issueKey}_{rule}.md` — no PR, no RAG storage |

---

## Supported Rules (Iteration 2 — 30 rules)

### Security (BLOCKER / CRITICAL)
| Rule | Name |
|------|------|
| `java:S2068` | Hardcoded Credentials |
| `java:S2076` | OS Command Injection |
| `java:S2083` | Path Traversal |
| `java:S2189` | Infinite Loop |
| `java:S5547` | Weak Cipher Algorithm |
| `java:S2647` | Basic Auth Over HTTP |
| `java:S2245` | Predictable Random Seed |

### Correctness (CRITICAL)
| Rule | Name |
|------|------|
| `java:S2259` | Null Pointer Dereference |
| `java:S2095` | Resource Leak |
| `java:S3776` | Cognitive Complexity |
| `java:S1206` | equals Without hashCode |
| `java:S1764` | Identical Operands |
| `java:S2184` | Integer Overflow |
| `java:S3010` | Static Field Race Condition |
| `java:S2274` | wait() Without Loop |

### Quality (MAJOR)
| Rule | Name |
|------|------|
| `java:S106`  | System.out Instead of Logger |
| `java:S2166` | assert for Validation |
| `java:S1172` | Unused Method Parameter |
| `java:S1854` | Dead Store |
| `java:S2629` | Eager Log Arguments |
| `java:S3457` | Printf Format Mismatch |
| `java:S2387` | Field Shadowing |
| `java:S4834` | Thread.sleep in Loop |
| `java:S2589` | Always True/False Condition |
| `java:S3252` | Static Member via Instance |

### Maintenance (MINOR / INFO)
| Rule | Name |
|------|------|
| `java:S1192` | Duplicated String Literal |
| `java:S1481` | Unused Local Variable |
| `java:S2293` | Diamond Operator |
| `java:S1118` | Utility Class Constructor |
| `java:S1135` | TODO Comment |
| `java:S1123` | @Deprecated Without Javadoc |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GCP_PROJECT` | *(required)* | GCP project ID |
| `GITHUB_TOKEN` | *(required)* | GitHub PAT |
| `GCP_LOCATION` | `us-central1` | Vertex AI region |
| `VERTEX_MODEL` | `gemini-2.5-flash` | Primary LLM |
| `MAX_CRITIC_RETRIES` | `1` | Max Critic→Generator loops |
| `COMPILE_TIMEOUT` | `120` | mvn compile timeout (s) |
| `TEST_TIMEOUT` | `180` | mvn test timeout (s) |
| `CLONE_DIR` | `/tmp/sonar-ai-repos` | Repo clone directory |
| `ESCALATION_DIR` | `escalations` | Escalation file output |
| `CONFIDENCE_HIGH_THRESHOLD` | `0.8` | Score for HIGH label |
| `CONFIDENCE_MEDIUM_THRESHOLD` | `0.5` | Score for MEDIUM label |
| **`ENABLE_RAG`** | `true` | Enable ChromaDB RAG |
| **`CHROMA_PERSIST_DIR`** | `/tmp/sonar-ai-chroma` | ChromaDB storage path |
| **`RAG_TOP_K`** | `3` | Number of similar fixes to retrieve |
| **`LANGSMITH_API_KEY`** | *(optional)* | LangSmith tracing key |
| **`LANGSMITH_PROJECT`** | `sonar-ai` | LangSmith project name |
| **`ENABLE_SONAR_RESCAN`** | `false` | Post-fix Sonar API rescan |
| **`SONAR_RESCAN_TIMEOUT`** | `300` | Max wait seconds for analysis |
| **`PARALLEL_ISSUES`** | `false` | Process issues in parallel |
| **`MAX_PARALLEL_WORKERS`** | `3` | Parallel concurrency cap |
| **`MAX_ISSUES`** | `0` | Issue cap (0 = no limit) |

---

## Pipeline Summary

After every run, `pipeline_summary.json` is written:

```json
{
  "total": 5,
  "results": [
    {
      "issue_key": "AY...",
      "rule_key": "java:S2259",
      "severity": "CRITICAL",
      "file": "Foo.java",
      "line": 42,
      "outcome": "pr_opened",
      "confidence": 0.91,
      "pr_url": "https://github.com/owner/repo/pull/17",
      "sonar_rescan_ok": true
    }
  ]
}
```

---

## Project Structure

```
sonar-ai/
├── main.py                  # CLI entry point (--max-issues, --parallel, --rescan, etc.)
├── requirements.txt
├── .env.example
├── pipeline_summary.json    # Auto-generated after each run
├── data/
│   ├── rule_kb.json         # 30-rule Java knowledge base
│   └── sample-report.json
├── sonar_ai/
│   ├── config.py            # Pydantic Settings (Iteration 2 settings added)
│   ├── state.py             # AgentState (+ RAGContext, IssueResult)
│   ├── parser.py            # Sonar JSON parser + Rule KB loader
│   ├── repo_loader.py       # Git clone, file resolution, AST extraction
│   ├── prompts.py           # Prompt templates (+ RAG few-shot block)
│   ├── agents.py            # Three LLM nodes + retrieve_rag_context node
│   ├── rag_store.py         # NEW: ChromaDB RAG store/retrieve
│   ├── sonar_rescan.py      # NEW: Sonar API post-fix rescan
│   ├── validator.py         # git apply + mvn compile + mvn test
│   ├── deliver.py           # PR creation + RAG storage + escalation writer
│   ├── graph.py             # LangGraph: sequential loop + parallel Send API
│   ├── diff_repair.py       # Diff repair strategies
│   └── __init__.py
├── tests/
│   ├── test_parser.py
│   ├── test_rag_store.py    # NEW
│   └── test_sonar_rescan.py # NEW
└── escalations/
```

---

## Post-Iteration-2 Roadmap

- Docker sandbox for `mvn` execution (security isolation)
- Redis + RQ job queue for distributed processing
- LangGraph Postgres checkpointer (resume failed runs mid-pipeline)
- Full 200-rule KB with auto-generation from Sonar rule API
- Web dashboard (FastAPI + React) for pipeline monitoring
- Webhook mode: trigger from SonarCloud webhook on new analysis

---

*SonarAI v0.2.0 — Iteration 2*

gcloud auth login

gloud auth application-default login

ng serve

uvicorn api:app --reload --port 8000