from __future__ import annotations

from types import SimpleNamespace

import pytest
import requests

from backend.core import verify as verify_module
from backend.core.models import ValidationVerdict
from backend.core.verify import (
    CanaryListener,
    ExploitSpec,
    _verify_one,
    _verify_oob_pickle,
    _verify_oob_query,
    _verify_sqli,
    _verify_ssrf,
    spin_up_sandbox,
    verify_findings,
)


@pytest.fixture
def canary():
    listener = CanaryListener()
    yield listener
    listener.shutdown()


@pytest.fixture(autouse=True)
def fast_canary_wait(monkeypatch):
    # Keep "no callback received" tests fast instead of waiting the real
    # production timeout.
    monkeypatch.setattr(verify_module, "CANARY_WAIT", 0.3)


# ---------- CanaryListener ----------


def test_canary_listener_records_a_real_hit(canary):
    token = canary.new_token()
    requests.get(f"http://127.0.0.1:{canary.port}/{token}", timeout=2)
    assert canary.wait_for_hit(token, timeout=1) is True


def test_canary_listener_reports_miss_for_unseen_token(canary):
    assert canary.wait_for_hit("never-sent", timeout=0.3) is False


# ---------- verify_findings: routing / graceful degradation ----------


def test_verify_findings_noop_when_nothing_confirmed(make_finding, monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("docker should never be invoked when nothing is confirmed")

    monkeypatch.setattr(verify_module.subprocess, "run", boom)
    f = make_finding(verdict=ValidationVerdict.FALSE_POSITIVE)
    verify_findings([f])
    assert f.verified is None


def test_verify_findings_unregistered_repo(make_finding):
    f = make_finding(repo="some_other_repo", verdict=ValidationVerdict.CONFIRMED)
    verify_findings([f])
    assert f.verified is None
    assert "no sandbox runner" in f.verification_detail.lower()


def test_verify_findings_degrades_when_docker_unavailable(make_finding, monkeypatch):
    def fake_run(*args, **kwargs):
        raise FileNotFoundError("docker not found")

    monkeypatch.setattr(verify_module.subprocess, "run", fake_run)
    f = make_finding(repo="vuln_flask_api", verdict=ValidationVerdict.CONFIRMED)
    verify_findings([f])
    assert f.verified is None
    assert "sandbox unavailable" in f.verification_detail.lower()


def test_verify_one_unregistered_rule(make_finding, canary):
    f = make_finding(rule_id="not-a-real-rule", verdict=ValidationVerdict.CONFIRMED)
    _verify_one(f, "http://127.0.0.1:1", canary)
    assert f.verified is None
    assert "no verification routine" in f.verification_detail.lower()


# ---------- spin_up_sandbox: teardown guarantees ----------


def test_spin_up_sandbox_tears_down_on_success(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(verify_module.subprocess, "run", fake_run)
    monkeypatch.setattr(verify_module, "_wait_until_ready", lambda *a, **k: True)

    with spin_up_sandbox("vuln_flask_api") as base_url:
        assert base_url == "http://127.0.0.1:5000"

    assert any(c[:2] == ["docker", "rm"] for c in calls)


def test_spin_up_sandbox_tears_down_even_when_never_ready(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(verify_module.subprocess, "run", fake_run)
    monkeypatch.setattr(verify_module, "_wait_until_ready", lambda *a, **k: False)

    with pytest.raises(RuntimeError):
        with spin_up_sandbox("vuln_flask_api"):
            pass

    assert any(c[:2] == ["docker", "rm"] for c in calls)


# ---------- individual verifier engines ----------


def test_verify_ssrf_true_when_sandbox_calls_back(canary, monkeypatch):
    # host.docker.internal only resolves from inside a container - swap in
    # 127.0.0.1 so this bare-host test can actually reach the canary.
    monkeypatch.setattr(
        verify_module, "_callback_url", lambda c, t: f"http://127.0.0.1:{c.port}/{t}"
    )
    spec = ExploitSpec("GET", "/webhooks/preview", "url")
    real_get = requests.get

    def fake_get(url, params=None, timeout=None):
        # stand-in for "the sandboxed app made the outbound request" - use
        # the real requests.get here, not the patched one, or this recurses
        real_get(params["url"], timeout=2)
        return SimpleNamespace(text="", status_code=200)

    try:
        requests.get = fake_get
        verified, detail = _verify_ssrf("http://fake", spec, canary)
    finally:
        requests.get = real_get

    assert verified is True
    assert "callback" in detail.lower()


def test_verify_ssrf_false_when_no_callback(canary, monkeypatch):
    spec = ExploitSpec("GET", "/webhooks/preview", "url")
    monkeypatch.setattr(
        verify_module.requests, "get", lambda *a, **k: SimpleNamespace(text="", status_code=200)
    )
    verified, detail = _verify_ssrf("http://fake", spec, canary)
    assert verified is False
    assert "no callback" in detail.lower()


def test_verify_oob_query_true_when_sandbox_calls_back(canary, monkeypatch):
    monkeypatch.setattr(
        verify_module, "_callback_url", lambda c, t: f"http://127.0.0.1:{c.port}/{t}"
    )
    spec = ExploitSpec("GET", "/reports/generate", "name")
    real_get = requests.get

    def fake_get(url, params=None, timeout=None):
        # the payload contains "curl <callback-url>" - simulate the shell
        # actually running it, using the real requests.get (not the patched
        # one, or this recurses into fake_get instead of hitting the canary)
        callback = params["name"].split("curl -s ", 1)[1].split(" #")[0]
        real_get(callback, timeout=2)
        return SimpleNamespace(text="", status_code=200)

    try:
        requests.get = fake_get
        verified, detail = _verify_oob_query("http://fake", spec, canary)
    finally:
        requests.get = real_get

    assert verified is True
    assert "callback" in detail.lower()


def test_verify_oob_pickle_sends_real_pickle_bytes(canary, monkeypatch):
    spec = ExploitSpec("POST", "/session/restore")
    captured = {}

    def fake_post(url, data=None, timeout=None):
        captured["data"] = data
        return SimpleNamespace(text="", status_code=200)

    monkeypatch.setattr(verify_module.requests, "post", fake_post)
    verified, detail = _verify_oob_pickle("http://fake", spec, canary)

    assert isinstance(captured["data"], bytes)
    assert captured["data"].startswith(b"\x80")  # real pickle protocol bytes, not text
    assert verified is False  # no real sandbox executed the gadget in this test
    assert "no callback" in detail.lower()


def test_verify_oob_pickle_true_when_gadget_fires(canary, monkeypatch):
    # host.docker.internal only resolves from inside a container (that's
    # the point of it), so for this bare-host test swap it for 127.0.0.1 -
    # the real Docker path is exercised separately (see manual verification
    # in the plan / README), this test is about the gadget mechanism itself.
    monkeypatch.setattr(
        verify_module, "_callback_url", lambda c, t: f"http://127.0.0.1:{c.port}/{t}"
    )

    spec = ExploitSpec("POST", "/session/restore")

    def fake_post(url, data=None, timeout=None):
        # stand-in for "the sandboxed app unpickled this and ran the gadget"
        # - real pickle.loads, real __reduce__ call, real os.system, real
        # curl subprocess, real HTTP hit on the canary. Nothing here is mocked.
        import pickle

        pickle.loads(data)
        return SimpleNamespace(text="", status_code=200)

    real_post = requests.post
    try:
        requests.post = fake_post
        verified, detail = _verify_oob_pickle("http://fake", spec, canary)
    finally:
        requests.post = real_post

    assert verified is True
    assert "gadget" in detail.lower()


def test_verify_sqli_reflected_payload(monkeypatch):
    spec = ExploitSpec("GET", "/orders/search", "customer")
    responses = iter(
        [
            SimpleNamespace(text='{"rows":[{"ok":true,"sql":"...customer = \'alice\'"}]}'),
            SimpleNamespace(
                text='{"rows":[{"ok":true,"sql":"...customer = \'\' OR \'1\'=\'1\' -- TOKEN\'"}]}'
            ),
        ]
    )

    def fake_get(url, params=None, timeout=None):
        resp = next(responses)
        resp.text = resp.text.replace("TOKEN", params["customer"].rsplit(" ", 1)[-1])
        return resp

    monkeypatch.setattr(verify_module.requests, "get", fake_get)
    verified, detail = _verify_sqli("http://fake", spec)
    assert verified is True
    assert "reflected" in detail.lower()


def test_verify_sqli_differential_row_count(monkeypatch):
    spec = ExploitSpec("GET", "/orders/search", "customer")
    responses = iter(
        [
            SimpleNamespace(text="{}", json=lambda: {"rows": [[1, "Widget", 19.99]]}),
            SimpleNamespace(
                text="{}", json=lambda: {"rows": [[1, "a", 1], [2, "b", 2], [3, "c", 3]]}
            ),
        ]
    )
    monkeypatch.setattr(verify_module.requests, "get", lambda *a, **k: next(responses))
    verified, detail = _verify_sqli("http://fake", spec)
    assert verified is True
    assert "rows" in detail.lower()


def test_verify_sqli_inconclusive_when_no_difference(monkeypatch):
    spec = ExploitSpec("GET", "/orders/search", "customer")
    same = SimpleNamespace(text="{}", json=lambda: {"rows": [[1, "Widget", 19.99]]})
    monkeypatch.setattr(verify_module.requests, "get", lambda *a, **k: same)
    verified, detail = _verify_sqli("http://fake", spec)
    assert verified is False


def test_verify_sqli_false_on_request_error(monkeypatch):
    spec = ExploitSpec("GET", "/orders/search", "customer")

    def fake_get(*a, **k):
        raise requests.RequestException("boom")

    monkeypatch.setattr(verify_module.requests, "get", fake_get)
    verified, detail = _verify_sqli("http://fake", spec)
    assert verified is False
    assert "failed" in detail.lower()
