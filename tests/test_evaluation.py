from __future__ import annotations

import json

from backend.core.evaluation import ANSWER_KEY_PATH, compute_report
from backend.core.models import ValidationVerdict


def _answer_key_entries() -> list[dict]:
    return json.loads(ANSWER_KEY_PATH.read_text(encoding="utf-8"))["findings"]


def _finding_for_entry(make_finding, entry: dict, *, confirmed: bool):
    return make_finding(
        id=f"f_{entry['tag']}",
        repo=entry["repo"],
        file=entry["file"],
        vuln_class=entry["vuln_class"],
        ground_truth_tag=entry["tag"],
        verdict=ValidationVerdict.CONFIRMED if confirmed else ValidationVerdict.PENDING,
    )


def test_perfect_pipeline_confirms_only_true_positives(make_finding):
    entries = _answer_key_entries()
    findings = [
        _finding_for_entry(make_finding, e, confirmed=(e["ground_truth"] == "true_positive"))
        for e in entries
    ]
    report = compute_report(findings)

    assert report["pipeline"]["precision"] == 1.0
    assert report["pipeline"]["recall"] == 1.0
    assert report["pipeline"]["false_positives"] == 0
    assert report["total_true_vulns_planted"] == 9


def test_baseline_reflects_every_raw_scan_hit_as_positive(make_finding):
    entries = _answer_key_entries()
    findings = [_finding_for_entry(make_finding, e, confirmed=False) for e in entries]
    report = compute_report(findings)

    assert report["baseline"]["true_positives"] == 9
    assert report["baseline"]["false_positives"] == 4


def test_unconfirmed_pipeline_has_zero_recall(make_finding):
    entries = _answer_key_entries()
    findings = [_finding_for_entry(make_finding, e, confirmed=False) for e in entries]
    report = compute_report(findings)

    assert report["pipeline"]["true_positives"] == 0
    assert report["pipeline"]["recall"] == 0.0


def test_findings_without_ground_truth_tag_are_ignored(make_finding):
    f = make_finding(ground_truth_tag=None, verdict=ValidationVerdict.CONFIRMED)
    report = compute_report([f])
    assert report["pipeline"]["true_positives"] == 0
    assert report["baseline"]["true_positives"] == 0


def test_empty_findings_yields_zero_recall_full_false_negatives():
    report = compute_report([])
    assert report["baseline"]["false_negatives"] == 9
    assert report["pipeline"]["false_negatives"] == 9
