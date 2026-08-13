from __future__ import annotations

from backend.core.models import ValidationVerdict
from backend.core.sarif import build_sarif


def test_build_sarif_includes_only_confirmed_findings(make_finding):
    confirmed = make_finding(
        id="f_confirmed", verdict=ValidationVerdict.CONFIRMED, severity="ERROR"
    )
    pending = make_finding(id="f_pending", verdict=ValidationVerdict.PENDING)
    fp = make_finding(id="f_fp", verdict=ValidationVerdict.FALSE_POSITIVE)

    sarif = build_sarif([confirmed, pending, fp])
    results = sarif["runs"][0]["results"]

    assert len(results) == 1
    assert results[0]["ruleId"] == confirmed.rule_id


def test_build_sarif_maps_severity_to_level(make_finding):
    high = make_finding(
        id="f_high", rule_id="rule-high", verdict=ValidationVerdict.CONFIRMED, severity="ERROR"
    )
    medium = make_finding(
        id="f_med", rule_id="rule-medium", verdict=ValidationVerdict.CONFIRMED, severity="WARNING"
    )
    low = make_finding(
        id="f_low", rule_id="rule-low", verdict=ValidationVerdict.CONFIRMED, severity="INFO"
    )

    sarif = build_sarif([high, medium, low])
    levels = {r["ruleId"]: r["level"] for r in sarif["runs"][0]["results"]}

    assert levels[high.rule_id] == "error"
    assert levels[medium.rule_id] == "warning"
    assert levels[low.rule_id] == "note"


def test_build_sarif_location_uses_repo_relative_path(make_finding):
    f = make_finding(
        id="f_1", verdict=ValidationVerdict.CONFIRMED, repo="myrepo", file="a/b.py", line=42
    )
    sarif = build_sarif([f])
    location = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "myrepo/a/b.py"
    assert location["region"]["startLine"] == 42


def test_build_sarif_empty_findings_produces_valid_empty_run():
    sarif = build_sarif([])
    assert sarif["runs"][0]["results"] == []
    assert sarif["version"] == "2.1.0"
