"""SARIF 2.1.0 output for CI code-scanning integrations (e.g. GitHub's
`upload-sarif` action) so confirmed findings show up inline on a PR's
Security tab, not just in build logs.
"""

from __future__ import annotations

from .models import Finding, ValidationVerdict
from .severity import normalize

STANDARD_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}

TOOL_NAME = "p4"
TOOL_VERSION = "0.1.0"


def _rule(finding: Finding) -> dict:
    return {
        "id": finding.rule_id,
        "name": finding.rule_id,
        "shortDescription": {"text": finding.vuln_class.replace("_", " ").title()},
        "fullDescription": {"text": finding.message or finding.vuln_class},
        "help": {"text": finding.rationale or finding.message or finding.rule_id},
        "properties": {"tags": [finding.vuln_class]},
    }


def _result(finding: Finding) -> dict:
    level = STANDARD_TO_SARIF_LEVEL.get(normalize(finding.severity), "warning")
    return {
        "ruleId": finding.rule_id,
        "level": level,
        "message": {"text": finding.rationale or finding.message or finding.rule_id},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f"{finding.repo}/{finding.file}"},
                    "region": {"startLine": max(finding.line, 1)},
                }
            }
        ],
        "partialFingerprints": {
            "p4/dedupSignature": finding.dedup_signature or finding.id,
        },
    }


def build_sarif(findings: list[Finding]) -> dict:
    """Confirmed findings only — SARIF results are meant to be actionable,
    not a dump of everything the pattern-matching Scan stage flagged."""
    confirmed = [f for f in findings if f.verdict == ValidationVerdict.CONFIRMED]
    rules_by_id = {f.rule_id: _rule(f) for f in confirmed}
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": [_result(f) for f in confirmed],
            }
        ],
    }
