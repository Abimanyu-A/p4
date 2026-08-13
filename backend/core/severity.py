"""Severity normalization shared by SARIF output, CLI gating, and the
DefectDojo export. Semgrep itself only emits INFO/WARNING/ERROR; the rest of
the system works in the more conventional low/medium/high/critical scale.
"""

from __future__ import annotations

SEMGREP_TO_STANDARD = {
    "INFO": "low",
    "WARNING": "medium",
    "ERROR": "high",
}

SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def normalize(severity: str) -> str:
    """Map a raw scanner severity onto the low/medium/high/critical scale."""
    upper = (severity or "").upper()
    if upper in SEMGREP_TO_STANDARD:
        return SEMGREP_TO_STANDARD[upper]
    lower = (severity or "").lower()
    return lower if lower in SEVERITY_ORDER else "medium"


def meets_minimum(severity: str, minimum: str) -> bool:
    """True if `severity` is at or above `minimum` on the standard scale."""
    try:
        return SEVERITY_ORDER.index(normalize(severity)) >= SEVERITY_ORDER.index(normalize(minimum))
    except ValueError:
        return True
