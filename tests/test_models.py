from __future__ import annotations

import time

from backend.core.models import SLA_BREACH_SECONDS, ValidationVerdict


def test_to_dict_not_breached_when_recent(make_finding):
    f = make_finding(verdict=ValidationVerdict.CONFIRMED, first_seen=time.time())
    d = f.to_dict()
    assert d["sla_breached"] is False
    assert d["age_seconds"] < 5


def test_to_dict_breached_when_old_and_confirmed(make_finding):
    f = make_finding(
        verdict=ValidationVerdict.CONFIRMED,
        first_seen=time.time() - SLA_BREACH_SECONDS - 60,
    )
    assert f.to_dict()["sla_breached"] is True


def test_to_dict_not_breached_when_old_but_not_confirmed(make_finding):
    f = make_finding(
        verdict=ValidationVerdict.FALSE_POSITIVE,
        first_seen=time.time() - SLA_BREACH_SECONDS - 60,
    )
    assert f.to_dict()["sla_breached"] is False


def test_to_dict_serializes_enums_to_plain_strings(make_finding):
    f = make_finding(verdict=ValidationVerdict.CONFIRMED)
    d = f.to_dict()
    assert d["verdict"] == "confirmed"
    assert isinstance(d["approval_status"], str)
