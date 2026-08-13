"""Scan stage: run Semgrep with our pattern rules against a prepared repo to
produce candidate findings. This is intentionally the same "cast a wide net"
behavior a baseline pattern-matching SAST tool would exhibit — precision is
the Validate stage's job, not this one.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from .models import Finding, ValidationVerdict, new_id

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
TAG_RE = re.compile(r"---\s*([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)")
CONTEXT_LINES = 3


def _nearest_tag_above(lines: list[str], line_no: int) -> str | None:
    start = max(0, line_no - 1 - 15)
    for i in range(line_no - 1, start - 1, -1):
        m = TAG_RE.search(lines[i])
        if m:
            return m.group(1)
    return None


def _snippet(lines: list[str], line_no: int) -> str:
    start = max(0, line_no - 1 - CONTEXT_LINES)
    end = min(len(lines), line_no + CONTEXT_LINES)
    out = []
    for i in range(start, end):
        marker = ">>" if i == line_no - 1 else "  "
        out.append(f"{marker} {i + 1:>4}| {lines[i]}")
    return "\n".join(out)


SEMGREP_BIN = shutil.which("semgrep") or "semgrep"


def run_semgrep(repo_path: str) -> dict:
    proc = subprocess.run(
        [
            SEMGREP_BIN,
            "scan",
            "--config",
            str(RULES_DIR),
            "--json",
            "--quiet",
            "--metrics=off",
            repo_path,
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if not proc.stdout.strip():
        raise RuntimeError(f"semgrep produced no output: {proc.stderr[-2000:]}")
    return json.loads(proc.stdout)


def scan_repo(run_id: str, repo_name: str, repo_path: str) -> list[Finding]:
    raw = run_semgrep(repo_path)
    root = Path(repo_path)
    findings: list[Finding] = []

    file_cache: dict[str, list[str]] = {}

    for result in raw.get("results", []):
        rel_path = result["path"]
        if rel_path not in file_cache:
            try:
                file_cache[rel_path] = (
                    Path(rel_path).read_text(encoding="utf-8", errors="ignore").splitlines()
                )
            except OSError:
                file_cache[rel_path] = []
        lines = file_cache[rel_path]
        line_no = result["start"]["line"]

        rel_display = (
            str(Path(rel_path).relative_to(root)).replace("\\", "/")
            if Path(rel_path).is_absolute()
            else rel_path
        )

        findings.append(
            Finding(
                id=new_id("f"),
                run_id=run_id,
                repo=repo_name,
                file=rel_display,
                line=line_no,
                rule_id=result["check_id"].split(".")[-1],
                vuln_class=result.get("extra", {}).get("metadata", {}).get("vuln_class", "unknown"),
                severity=result.get("extra", {}).get("severity", "WARNING"),
                message=result.get("extra", {}).get("message", "").strip(),
                code_snippet=_snippet(lines, line_no) if lines else "",
                ground_truth_tag=_nearest_tag_above(lines, line_no) if lines else None,
                verdict=ValidationVerdict.PENDING,
            )
        )

    return findings
