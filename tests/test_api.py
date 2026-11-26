"""API tests. Skipped automatically when FastAPI/httpx are not installed (pip install -r requirements.txt)."""
import pytest
pytest.importorskip("fastapi"); pytest.importorskip("httpx")
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch, fast_classifier):
    from src import database, api
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "api.db")
    monkeypatch.setattr(api, "CLASSIFIER", fast_classifier); api.ENGINES.clear()
    monkeypatch.setenv("CYBERQUANT_INITIAL_PASSWORD", "A-long-initial-password-1")
    from src.bootstrap import bootstrap_templates
    bootstrap_templates()
    with TestClient(api.app) as c:
        assert c.post("/api/v1/auth/login", json={"username": "admin", "password": "A-long-initial-password-1"}).status_code == 200
        yield c


def test_default_login_works(tmp_path, monkeypatch, fast_classifier):
    from src import database, api
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "d.db"); monkeypatch.setattr(api, "CLASSIFIER", fast_classifier)
    monkeypatch.delenv("CYBERQUANT_INITIAL_PASSWORD", raising=False); monkeypatch.setattr("src.demo_seed.seed_demo", lambda *a, **k: None)
    from src.bootstrap import bootstrap_templates
    bootstrap_templates()
    with TestClient(api.app) as c:
        assert c.post("/api/v1/auth/login", json={"username": "admin", "password": "Gandharva"}).json()["must_change_password"] is False
        assert c.get("/api/v1/servers").status_code == 200


def test_connect_send_review_and_budget(client):
    made = client.post("/api/v1/servers", json={"display_name": "Shop", "hostname": "shop.example", "sector": "Retail"}).json()
    sid, token = made["server_id"], made["agent_token"]
    now = datetime.now(timezone.utc)
    events = [{"event_at": (now - timedelta(seconds=300 - i * 20)).isoformat(), "request_method": "POST", "request_path": "/login", "response_status": 401,
               "source_ip": "198.51.100.5", "metadata": {"account": "priya"}} for i in range(6)]
    assert client.post(f"/api/v1/telemetry/{sid}", json={"events": events}, headers={"X-Agent-Token": "bad"}).status_code == 401
    assert client.post(f"/api/v1/telemetry/{sid}", json={"events": events}, headers={"X-Agent-Token": token}).json()["alerts_raised"] == 1
    analytics = client.get(f"/api/v1/servers/{sid}/analytics").json()
    incident = analytics["incidents"][0]
    assert incident["threat_type"] == "Brute force" and analytics["traffic"]["total"] == 6
    assert client.post(f"/api/v1/servers/{sid}/incidents/{incident['id']}/review", json={"decision": "genuine", "handling": "block_source"}).status_code == 422
    assert client.post(f"/api/v1/servers/{sid}/incidents/{incident['id']}/review", json={"decision": "attack", "handling": "block_source"}).status_code == 200
    assert client.get(f"/api/v1/telemetry/{sid}/blocklist", headers={"X-Agent-Token": token}).json()["blocklist"][0]["source_ip"] == "198.51.100.5"
    plan = client.post(f"/api/v1/servers/{sid}/budget-plan", json={"budget_inr": 300000, "period_days": 30}).json()
    assert plan["allocated_inr"] <= 300000 and plan["selected"]


def test_import_paths_are_restricted(client):
    assert client.post("/api/v1/admin/ingest/nvd", json={"zip_path": "/etc/passwd"}).status_code == 422


def test_signup_then_login_and_weak_password_rejected(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    monkeypatch.setenv("CYBERQUANT_DB", str(tmp_path / "t.db"))
    from src import api
    with TestClient(api.app) as c:
        assert c.post("/api/v1/auth/register", json={"username": "ravi", "password": "short"}).status_code == 422
        assert c.post("/api/v1/auth/register", json={"username": "ravi", "password": "alllowercase1234"}).status_code == 422
        ok = c.post("/api/v1/auth/register", json={"username": "ravi", "password": "Strong-Pass-2026"})
        assert ok.status_code == 200 and c.get("/api/v1/auth/me").json()["authenticated"]
        assert c.post("/api/v1/auth/register", json={"username": "RAVI", "password": "Strong-Pass-2026"}).status_code == 409
        c.post("/api/v1/auth/logout")
        assert c.get("/home", follow_redirects=False).status_code in (302, 307)
        assert c.post("/api/v1/auth/login", json={"username": "ravi", "password": "Strong-Pass-2026"}).status_code == 200
