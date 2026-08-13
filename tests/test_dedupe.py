from __future__ import annotations

from backend.core.dedupe import dedupe_findings
from backend.core.models import ValidationVerdict


def test_groups_confirmed_findings_with_same_signature(make_finding):
    a = make_finding(
        id="f_a", repo="repo_a", verdict=ValidationVerdict.CONFIRMED, dedup_signature="ssrf-x"
    )
    b = make_finding(
        id="f_b", repo="repo_b", verdict=ValidationVerdict.CONFIRMED, dedup_signature="ssrf-x"
    )
    dedupe_findings([a, b])

    assert a.dedup_group_id is not None
    assert a.dedup_group_id == b.dedup_group_id
    assert a.is_dedup_primary is True
    assert b.is_dedup_primary is False


def test_does_not_group_singletons(make_finding):
    a = make_finding(id="f_a", verdict=ValidationVerdict.CONFIRMED, dedup_signature="unique-sig")
    dedupe_findings([a])
    assert a.dedup_group_id is None


def test_ignores_non_confirmed_findings(make_finding):
    a = make_finding(id="f_a", verdict=ValidationVerdict.FALSE_POSITIVE, dedup_signature="ssrf-x")
    b = make_finding(id="f_b", verdict=ValidationVerdict.FALSE_POSITIVE, dedup_signature="ssrf-x")
    dedupe_findings([a, b])
    assert a.dedup_group_id is None
    assert b.dedup_group_id is None


def test_different_vuln_class_not_merged(make_finding):
    a = make_finding(
        id="f_a",
        vuln_class="injection",
        verdict=ValidationVerdict.CONFIRMED,
        dedup_signature="same-sig",
    )
    b = make_finding(
        id="f_b", vuln_class="ssrf", verdict=ValidationVerdict.CONFIRMED, dedup_signature="same-sig"
    )
    dedupe_findings([a, b])
    assert a.dedup_group_id is None
    assert b.dedup_group_id is None
