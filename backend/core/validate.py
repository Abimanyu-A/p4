"""Validate stage: an LLM agent reasons about real exploitability for every
candidate finding (clearing false positives that pattern-matching alone
cannot), and assigns a canonical dedup signature used to merge the same
vulnerability class across repos.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from .llm import structured_call
from .models import Finding, ValidationVerdict
from .prepare import CodePropertyGraph

VALIDATE_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {
            "type": "string",
            "enum": ["confirmed", "false_positive"],
            "description": "confirmed = a real attacker-exploitable vulnerability. "
            "false_positive = the sink is reached only by trusted/hardcoded data, "
            "or is otherwise not exploitable.",
        },
        "confidence": {
            "type": "number",
            "description": "0.0-1.0 confidence in the verdict.",
        },
        "rationale": {
            "type": "string",
            "description": "1-3 sentences: trace the data flow from source to sink "
            "and explain why it is or isn't exploitable.",
        },
        "dedup_signature": {
            "type": "string",
            "description": "A short kebab-case slug identifying the underlying "
            "vulnerability *pattern* (sink type + source shape), independent of "
            "file/repo/language, e.g. 'ssrf-outbound-request-user-controlled-url'. "
            "Findings across different repos with the same pattern must get the "
            "exact same signature so they can be merged.",
        },
    },
    "required": ["verdict", "confidence", "rationale", "dedup_signature"],
}

SYSTEM_PROMPT = """You are a senior application security engineer performing \
exploitability triage on candidate findings from a pattern-based static \
analysis scan. The scanner flags any occurrence of a dangerous sink \
(SQL execute, os.system, pickle.loads, eval, outbound HTTP request, etc.) \
without tracking whether the data reaching that sink is actually \
attacker-controlled. Your job is to read the surrounding code and decide:

1. Is there a real, external, attacker-controlled source (HTTP request \
   parameters/body, uploaded file content, etc.) reaching this sink?
2. Or is the sink only ever fed hardcoded literals, trusted config, or \
   otherwise-sanitized data, making the scanner's finding a false positive?

Be precise and skeptical. A variable name alone is not evidence of taint — \
trace where it is actually assigned from within the shown snippet."""


def _entrypoint_hint(cpg: CodePropertyGraph, finding: Finding) -> str:
    eps = [ep for ep in cpg.entrypoints if ep.file == finding.file]
    if not eps:
        return "No HTTP entrypoint metadata available for this file."
    lines = [f"  {ep.method} {ep.path} -> handler `{ep.handler}`() at line {ep.line}" for ep in eps]
    return "HTTP entrypoints defined in this file:\n" + "\n".join(lines)


def _validate_one(finding: Finding, cpg: CodePropertyGraph) -> Finding:
    user_prompt = f"""Candidate finding from static scan:
- Vulnerability class: {finding.vuln_class}
- Rule: {finding.rule_id}
- Scanner message: {finding.message}
- Repo: {finding.repo}
- File: {finding.file}, line {finding.line}

{_entrypoint_hint(cpg, finding)}

Code (>> marks the flagged line):
{finding.code_snippet}

Determine whether this is a real, exploitable vulnerability or a false \
positive, per the criteria in your instructions."""

    result = structured_call(SYSTEM_PROMPT, user_prompt, VALIDATE_SCHEMA)

    finding.verdict = (
        ValidationVerdict.CONFIRMED
        if result["verdict"] == "confirmed"
        else ValidationVerdict.FALSE_POSITIVE
    )
    finding.confidence = float(result["confidence"])
    finding.rationale = result["rationale"]
    finding.dedup_signature = result["dedup_signature"].strip().lower()
    return finding


def validate_findings(
    findings: list[Finding], cpg_by_repo: dict[str, CodePropertyGraph]
) -> list[Finding]:
    if not findings:
        return findings
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {pool.submit(_validate_one, f, cpg_by_repo[f.repo]): f for f in findings}
        for fut in as_completed(futures):
            fut.result()
    return findings
