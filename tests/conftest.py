from __future__ import annotations

import pytest

from backend.core.models import Finding


@pytest.fixture
def make_finding():
    """Factory for a minimal Finding with sane defaults, overridable per test."""

    def _make(**overrides) -> Finding:
        defaults = dict(
            id="f_test",
            run_id="run_test",
            repo="demo_repo",
            file="app.py",
            line=10,
            rule_id="python-os-system-call",
            vuln_class="injection",
            severity="ERROR",
            message="os.system() executes a string in a shell.",
            code_snippet=">>   10| os.system(cmd)",
        )
        defaults.update(overrides)
        return Finding(**defaults)

    return _make
