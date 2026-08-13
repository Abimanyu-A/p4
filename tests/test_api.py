from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.api.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_list_repos_includes_sample_repos(client):
    resp = client.get("/api/repos")
    assert resp.status_code == 200
    repos = resp.json()["repos"]
    assert "vuln_flask_api" in repos
    assert "vuln_express_api" in repos


def test_scan_rejects_unknown_repo(client):
    resp = client.post("/api/scan", json={"repos": ["not_a_real_repo"]})
    assert resp.status_code == 400


def test_get_missing_run_returns_404(client):
    resp = client.get("/api/runs/not_a_real_run_id")
    assert resp.status_code == 404


def test_approve_missing_finding_returns_404(client):
    resp = client.post("/api/findings/not_a_real_finding/approve")
    assert resp.status_code == 404
