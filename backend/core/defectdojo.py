"""DefectDojo integration adapter for remediation ticket workflows.

Formats confirmed findings into DefectDojo's Generic Finding Import JSON
schema. POSTs to a real DefectDojo instance if DEFECTDOJO_URL /
DEFECTDOJO_API_KEY are configured; otherwise writes the payload to disk so
the "would sync" behavior is still demonstrable without a live instance.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import requests

from .models import Finding, ValidationVerdict
from .severity import normalize

SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "n/a": "Info",
}

OUT_DIR = Path(__file__).resolve().parent.parent.parent / "run_artifacts"


def _to_generic_finding(f: Finding) -> dict:
    return {
        "title": f"[{f.vuln_class}] {f.rule_id} in {f.repo}/{f.file}:{f.line}",
        "description": f"{f.message}\n\nAnalyst rationale: {f.rationale}\n\n"
        f"Proof of concept:\n{f.poc or 'n/a'}\n\n{f.poc_explanation or ''}",
        "severity": SEVERITY_MAP.get(normalize(f.severity), "Medium"),
        "file_path": f.file,
        "line": f.line,
        "cwe": 0,
        "date": None,
        "active": True,
        "verified": True,
        "false_p": False,
        "duplicate": not f.is_dedup_primary,
        "tags": [f.vuln_class, f.repo, f.rule_id],
    }


def build_import_payload(findings: list[Finding]) -> dict:
    confirmed = [f for f in findings if f.verdict == ValidationVerdict.CONFIRMED]
    return {"findings": [_to_generic_finding(f) for f in confirmed]}


def sync_to_defectdojo(run_id: str, findings: list[Finding]) -> dict:
    payload = build_import_payload(findings)
    url = os.environ.get("DEFECTDOJO_URL")
    api_key = os.environ.get("DEFECTDOJO_API_KEY")

    if url and api_key:
        resp = requests.post(
            f"{url.rstrip('/')}/api/v2/import-scan/",
            headers={"Authorization": f"Token {api_key}"},
            json=payload,
            timeout=30,
        )
        resp.raise_for_status()
        return {"synced": True, "target": url, "count": len(payload["findings"])}

    OUT_DIR.mkdir(exist_ok=True)
    out_path = OUT_DIR / f"{run_id}_defectdojo_import.json"
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return {
        "synced": False,
        "would_sync_count": len(payload["findings"]),
        "artifact_path": str(out_path),
        "note": "DEFECTDOJO_URL/DEFECTDOJO_API_KEY not configured — payload written to disk instead.",
    }
