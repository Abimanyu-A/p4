"""Prove stage: for every confirmed finding, generate a concrete
proof-of-concept that demonstrates the vulnerability. Also generates a
remediation patch, but only on-demand after a human approves the finding
(the human-approval gate).
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from .llm import structured_call
from .models import Finding, ValidationVerdict

POC_SCHEMA = {
    "type": "object",
    "properties": {
        "poc": {
            "type": "string",
            "description": "A concrete, runnable proof-of-concept: a curl command, "
            "HTTP request, or CLI input that exercises the vulnerable path.",
        },
        "poc_explanation": {
            "type": "string",
            "description": "One sentence on why this input triggers the vulnerability.",
        },
    },
    "required": ["poc", "poc_explanation"],
}

FIX_SCHEMA = {
    "type": "object",
    "properties": {
        "patch": {
            "type": "string",
            "description": "A unified-diff-style or before/after code snippet showing "
            "the minimal fix for this vulnerability.",
        },
        "summary": {
            "type": "string",
            "description": "One sentence describing the fix.",
        },
    },
    "required": ["patch", "summary"],
}

POC_SYSTEM_PROMPT = """You are a security engineer writing a minimal, concrete \
proof-of-concept for a confirmed vulnerability, for inclusion in a remediation \
ticket. Assume the target is running locally (e.g. http://localhost:5000). Be \
specific and runnable — no placeholders like <URL_HERE>."""

FIX_SYSTEM_PROMPT = """You are a security engineer proposing the minimal code \
fix for a confirmed vulnerability. Keep the fix scoped to exactly this \
vulnerability — no unrelated refactoring."""


def _prove_one(finding: Finding) -> Finding:
    prompt = f"""Confirmed vulnerability:
- Class: {finding.vuln_class}
- Repo: {finding.repo}, file: {finding.file}, line {finding.line}
- Analyst rationale: {finding.rationale}

Code:
{finding.code_snippet}

Write a proof-of-concept."""
    result = structured_call(POC_SYSTEM_PROMPT, prompt, POC_SCHEMA)
    finding.poc = result["poc"]
    finding.poc_explanation = result["poc_explanation"]
    return finding


def prove_findings(findings: list[Finding]) -> list[Finding]:
    confirmed = [f for f in findings if f.verdict == ValidationVerdict.CONFIRMED]
    if not confirmed:
        return findings
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {pool.submit(_prove_one, f): f for f in confirmed}
        for fut in as_completed(futures):
            fut.result()
    return findings


def generate_fix(finding: Finding) -> Finding:
    """Only called after a human clicks 'Approve & Generate Fix' — never automatic."""
    prompt = f"""Confirmed, human-approved vulnerability:
- Class: {finding.vuln_class}
- File: {finding.file}, line {finding.line}
- Rationale: {finding.rationale}

Vulnerable code:
{finding.code_snippet}

Propose the minimal fix."""
    result = structured_call(FIX_SYSTEM_PROMPT, prompt, FIX_SCHEMA)
    finding.fix_patch = f"{result['summary']}\n\n{result['patch']}"
    return finding
