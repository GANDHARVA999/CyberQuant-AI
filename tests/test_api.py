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
        assert c.post("/api/v1/auth/register", json={"username": "ravi", "email": "ravi@example.com", "password": "short"}).status_code == 422
        assert c.post("/api/v1/auth/register", json={"username": "ravi", "email": "ravi@example.com", "password": "alllowercase1234"}).status_code == 422
        ok = c.post("/api/v1/auth/register", json={"username": "ravi", "email": "ravi@example.com", "password": "Strong-Pass-2026"})
        assert ok.status_code == 200 and c.get("/api/v1/auth/me").json()["authenticated"]
        assert c.post("/api/v1/auth/register", json={"username": "RAVI", "email": "other@example.com", "password": "Strong-Pass-2026"}).status_code == 409
        c.post("/api/v1/auth/logout")
        assert c.get("/home", follow_redirects=False).status_code in (302, 307)
        assert c.post("/api/v1/auth/login", json={"username": "ravi", "password": "Strong-Pass-2026"}).status_code == 200


def test_forgot_and_reset_password(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    monkeypatch.setenv("CYBERQUANT_DEV_RESET_LINKS", "1"); monkeypatch.delenv("CYBERQUANT_SMTP_HOST", raising=False)
    from src import database, api
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "r.db")
    with TestClient(api.app) as c:
        assert c.post("/api/v1/auth/register", json={"username": "meera", "email": "meera@example.com", "password": "Strong-Pass-2026"}).status_code == 200
        c.post("/api/v1/auth/logout")
        unknown = c.post("/api/v1/auth/forgot", json={"identifier": "nobody@example.com"}).json()
        assert "dev_link" not in unknown                               # no hint whether the account exists
        known = c.post("/api/v1/auth/forgot", json={"identifier": "Meera@Example.com"}).json()
        token = known["dev_link"].split("token=")[1]
        assert c.post("/api/v1/auth/reset", json={"token": token, "new_password": "weakweakweak"}).status_code == 422
        assert c.post("/api/v1/auth/reset", json={"token": token, "new_password": "Brand-New-Pass-77"}).status_code == 200
        assert c.post("/api/v1/auth/reset", json={"token": token, "new_password": "Another-Pass-88x"}).status_code == 400   # single use
        assert c.post("/api/v1/auth/login", json={"username": "meera", "password": "Brand-New-Pass-77"}).status_code == 200


def test_google_sign_in_creates_and_reuses_account(tmp_path, monkeypatch):
    import base64, json, time
    from fastapi.testclient import TestClient
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "cid"); monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "secret")
    from src import database, api, auth_extra
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "g.db")
    claims = {"aud": "cid", "iss": "https://accounts.google.com", "exp": time.time() + 300, "email": "Sam@Gmail.com", "email_verified": True, "sub": "g-123"}
    jwt = "h." + base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=") + ".s"
    monkeypatch.setattr(auth_extra, "exchange_code", lambda code, verifier, redirect: jwt)
    with TestClient(api.app, follow_redirects=False) as c:
        start = c.get("/api/v1/auth/google/start")
        assert start.status_code in (302, 307) and "accounts.google.com" in start.headers["location"] and "code_challenge" in start.headers["location"]
        state = c.cookies.get("cq_oauth").split(".")[0]
        assert c.get("/api/v1/auth/google/callback", params={"code": "x", "state": "wrong"}).headers["location"].startswith("/?error=")
        ok = c.get("/api/v1/auth/google/callback", params={"code": "x", "state": state})
        assert ok.headers["location"] == "/home" and c.get("/api/v1/auth/me").json()["username"] == "sam"
        c.post("/api/v1/auth/logout")
        start = c.get("/api/v1/auth/google/start"); state = c.cookies.get("cq_oauth").split(".")[0]
        c.get("/api/v1/auth/google/callback", params={"code": "x", "state": state})
        assert api.rows("SELECT COUNT(*) AS n FROM users WHERE google_sub='g-123'")[0]["n"] == 1
