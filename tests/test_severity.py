from __future__ import annotations

import pytest

from backend.core.severity import meets_minimum, normalize


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("ERROR", "high"),
        ("WARNING", "medium"),
        ("INFO", "low"),
        ("error", "high"),
        ("critical", "critical"),
        ("", "medium"),
        ("nonsense", "medium"),
    ],
)
def test_normalize(raw, expected):
    assert normalize(raw) == expected


def test_meets_minimum_true_when_equal():
    assert meets_minimum("ERROR", "high") is True


def test_meets_minimum_true_when_above():
    assert meets_minimum("ERROR", "low") is True


def test_meets_minimum_false_when_below():
    assert meets_minimum("INFO", "high") is False


def test_meets_minimum_low_is_permissive_default():
    for raw in ("INFO", "WARNING", "ERROR", "critical"):
        assert meets_minimum(raw, "low") is True
