"""FastAPI service for the P4 dashboard (Prepare -> Scan -> Validate -> Prove)."""

from __future__ import annotations

import threading
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.core import store
from backend.core.defectdojo import sync_to_defectdojo
from backend.core.evaluation import compute_report
from backend.core.pipeline import approve_and_fix, new_run_id, run_pipeline

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SAMPLE_REPOS_DIR = REPO_ROOT / "sample_repos"
FRONTEND_DIR = REPO_ROOT / "frontend" / "dist"

app = FastAPI(title="P4 - Proof-Driven Vulnerability Validation Platform")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    repos: list[str] | None = None


def _discover_sample_repos() -> dict[str, str]:
    repos = {}
    if not SAMPLE_REPOS_DIR.exists():
        return repos
    for entry in sorted(SAMPLE_REPOS_DIR.iterdir()):
        if entry.is_dir() and not entry.name.startswith("."):
            repos[entry.name] = str(entry)
    return repos


@app.get("/api/repos")
def list_repos():
    return {"repos": list(_discover_sample_repos().keys())}


@app.post("/api/scan")
def start_scan(req: ScanRequest):
    available = _discover_sample_repos()
    if req.repos:
        missing = [r for r in req.repos if r not in available]
        if missing:
            raise HTTPException(400, f"unknown repos: {missing}")
        selected = {name: available[name] for name in req.repos}
    else:
        selected = available

    if not selected:
        raise HTTPException(400, "no repos available to scan")

    run_id = new_run_id()
    thread = threading.Thread(target=run_pipeline, args=(run_id, selected), daemon=True)
    thread.start()
    return {"run_id": run_id}


@app.get("/api/runs")
def list_runs():
    return {"runs": [r.to_dict() for r in store.list_runs()]}


@app.get("/api/runs/{run_id}")
def get_run(run_id: str):
    run = store.get_run(run_id)
    if run is None:
        raise HTTPException(404, "run not found")
    return run.to_dict()


@app.get("/api/runs/{run_id}/findings")
def get_findings(run_id: str):
    findings = store.list_findings(run_id)
    return {"findings": [f.to_dict() for f in findings]}


@app.get("/api/runs/{run_id}/report")
def get_report(run_id: str):
    findings = store.list_findings(run_id)
    return compute_report(findings)


@app.post("/api/runs/{run_id}/defectdojo")
def defectdojo_sync(run_id: str):
    findings = store.list_findings(run_id)
    return sync_to_defectdojo(run_id, findings)


@app.post("/api/findings/{finding_id}/approve")
def approve_finding(finding_id: str):
    try:
        approve_and_fix(finding_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    finding = store.get_finding(finding_id)
    return finding.to_dict()


@app.get("/api/health")
def health():
    return {"status": "ok"}


if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
