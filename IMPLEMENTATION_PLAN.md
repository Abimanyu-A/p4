# P4 — Proof-Driven Vulnerability Validation Platform — Implementation Plan

## 1. Problem Restated

Build an automated source-code scanner for interpreted languages (Python, JavaScript first)
that runs a **Prepare → Scan → Validate → Prove** pipeline and suppresses false positives
using **LLM-assisted validation**, not pattern matching alone. It must beat a baseline
SAST tool on false-positive rate, dedupe the same vulnerability across repos, gate
auto-fix behind human approval, and escalate findings that breach an SLA age threshold.

## 2. Architecture

```
                    ┌──────────────────────────────────────────────┐
                    │              FastAPI Backend (Python)         │
                    │                                                │
  Repo(s) ────────▶ │  PREPARE   →   SCAN   →   VALIDATE  →  PROVE  │ ──▶ Dashboard (UI)
  (Flask/Express)   │  (CPG-lite)  (Semgrep    (Gemini       (Gemini│        │
                    │              taint      exploitability  PoC    │        ▼
                    │              rules)     + dedup)        gen)   │  DefectDojo
                    │                                                │  adapter (JSON
                    │  SQLite run store · SLA clock · Approval gate  │  export / POST)
                    └──────────────────────────────────────────────┘
                                        ▲
                                        │  same stage functions,
                                        │  no HTTP/threading involved
                              ┌───────────────────┐
                              │   `p4` CLI (CI)    │──▶ SARIF / JSON / exit code
                              └───────────────────┘
```

**Stage breakdown**

| Stage | What it does | Tooling |
|---|---|---|
| **Prepare** | Walks the target repo, builds a lightweight Code Property Graph: per-file AST (via Python `ast` / regex-based route extraction for JS), import graph, and a source→sink symbol table — no build/compile step required. | Python `ast` |
| **Scan** | Runs Semgrep with a custom ruleset targeting injection (SQL/command), insecure deserialization (`pickle`, `yaml.load`, `eval`, Node `child_process`), and SSRF (`requests`/`urllib`/`axios`/`http` with tainted URLs). Produces raw candidate findings — this is also the "baseline" output used for comparison. | Semgrep pattern rules |
| **Validate** | An LLM agent (Google Gemini) receives each candidate finding plus surrounding code + entrypoint context and reasons about real exploitability (is the source actually attacker-controlled? is there a sanitizer on the path?). Marks each `confirmed` / `false_positive` with a rationale. Also computes a normalized vulnerability signature (sink type + tainted-source shape) to **dedupe the same pattern across repos** into one finding group. | Gemini API, structured JSON output |
| **Prove** | For every `confirmed` finding, the LLM generates a concrete proof-of-concept — an HTTP request, CLI payload, or input string — that exercises the vulnerable path, plus a one-line "why this works." | Gemini API |

**Cross-cutting**
- **Human-approval gate**: a `confirmed` finding unlocks an "Approve & Generate Fix" action in the UI; the LLM-authored patch is only produced after a human clicks Approve — nothing auto-applies.
- **SLA breach handling**: every finding gets a `first_seen` timestamp; findings older than a configurable threshold (default 72h, backdated on 2 seed findings for demo purposes) are visually escalated (amber → red) and sorted to the top.
- **DefectDojo integration**: an adapter formats confirmed findings into DefectDojo's Generic Finding Import JSON. If `DEFECTDOJO_URL`/`DEFECTDOJO_API_KEY` are set it POSTs; otherwise it writes the payload to disk and the UI shows "would sync N findings."
- **CI/CD security gate**: the `p4` CLI (`backend/cli.py`) calls the same `prepare_repo` / `scan_repo` / `validate_findings` / `dedupe_findings` functions the dashboard uses, but synchronously and without the FastAPI/threading/SQLite-run machinery. `p4 scan` exits non-zero when a confirmed finding meets `--min-severity`, and can emit SARIF for GitHub code scanning or JSON for other tooling. `action.yml` wraps it as a reusable GitHub Action.

## 3. Technology Stack

- **Orchestration / API**: Python 3.12, FastAPI + Uvicorn, SQLite (via `sqlite3`) for run/finding persistence.
- **Scan**: Semgrep (custom pattern rules in `backend/rules/*.yaml`).
- **Agentic validation & PoC generation**: Google Gemini API (`gemini-flash-lite-latest` by default, free-tier friendly), structured JSON output for reliability.
- **Frontend**: React + TypeScript, built with Vite, served as static assets by FastAPI (`frontend/dist`) — no separate Node runtime needed in production. Chosen over Next.js because the dashboard is a pure client-side app against a REST API with no SSR/routing needs.
- **CLI / CI integration**: `p4` console script (packaged via `pyproject.toml`), SARIF 2.1.0 output (`backend/core/sarif.py`), a composite GitHub Action (`action.yml`).
- **Packaging & quality**: pinned dependencies, `ruff` for lint/format, `pytest` for the backend test suite, multi-stage `Dockerfile`, GitHub Actions CI.
- **Sample targets**: 3 small intentionally-vulnerable apps (2 Flask, 1 Express) with labeled ground truth (true vulns + look-alike false-positive traps + one vuln pattern duplicated across two repos) so precision/recall/F1 can be computed against a known answer key, not just eyeballed.

## 4. Evaluation Plan (Model Performance criterion)

- Ground-truth labels live in `sample_repos/ANSWER_KEY.json`.
- After each run, compute: baseline Semgrep precision/recall/F1 vs. pipeline (post-Validate) precision/recall/F1, plus false-positive-suppression rate = `(baseline_FP - pipeline_FP) / baseline_FP`.
- Surfaced as a comparison panel + bar chart in the UI, via `p4 evaluate` on the command line, and as an optional CI regression gate (`.github/workflows/ci.yml`, guarded on the `GEMINI_API_KEY` secret being available).

## 5. Build Order

1. Sample vulnerable repos + answer key (ground truth).
2. Semgrep rules (Prepare/Scan).
3. Pipeline core: models, prepare.py, scan.py, dedupe.py.
4. Gemini-backed validate.py (exploitability + dedup) and prove.py (PoC generation).
5. SLA clock + human-approval gate + DefectDojo adapter.
6. FastAPI endpoints + SQLite persistence.
7. Dashboard UI (pipeline stepper, findings table, PoC viewer, approval flow, comparison report).
8. `p4` CLI + SARIF output + pytest suite + Dockerfile + CI workflow + reusable Action.
9. End-to-end run, compute metrics, fix issues, polish UI.
10. README with architecture, setup, CI/CD usage.

## 6. Design Goals Recap

- **Solution architecture**: four decoupled stage modules behind one orchestrator; each stage's output is the next stage's typed input (`Finding` objects), swappable independently (e.g. swap Semgrep for Joern later), and reusable from either the web dashboard or the CLI.
- **AI use**: the LLM is used for *reasoning* (exploitability triage, cross-repo dedup, PoC synthesis, patch generation) — pattern matching (Semgrep) only proposes candidates, never decides.
- **UI/UX**: single-page dashboard, live pipeline progress, clear status color language, no dead ends (every finding has a next action).
- **Technical implementation**: typed pipeline, persisted runs, real Semgrep rules, real LLM calls with structured output and error handling, pytest coverage on the deterministic parts of the pipeline.
- **Model performance**: quantified precision/recall/F1 vs. baseline, checked continuously, not just claimed once.
- **Deployment/integration**: FastAPI service, Docker image, DefectDojo export adapter, and a CI/CD-ready CLI + GitHub Action — runnable via one command locally or as a gate in someone else's pipeline.
