"""The web server: every URL the browser and the connector use (login, servers, live traffic, review, budget plan, pages).

Run with:  uvicorn src.api:app   (or python serve.py)
"""
from typing import Literal
import json
import os
import hashlib
import secrets
from hmac import compare_digest
from datetime import timedelta
from datetime import datetime, timezone
from pathlib import Path
from fastapi import FastAPI, HTTPException, Query, Header, Request, Response, Cookie
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from contextlib import asynccontextmanager
from threading import Lock
from pydantic import BaseModel, Field
from .database import connection, initialize
from .bootstrap import bootstrap_templates
from .asset_risk.ingestion import ingest_nvd_zip, import_asset_findings
from .asset_risk.risk import calculate_asset_risk
from .asset_risk.optimizer import optimize
from .settings import ROOT, MODEL_VERSION, INGEST_DIR
from .asset_risk.threat_detection import classify_event
from . import incident_store as istore
from .engine import ATTACK_TYPES
from .engine.cve_link import ATTACK_CWE, ATTACK_KEYWORDS, keyword_sql
from .engine.model import Classifier, REPORT_PATH as WEB_MODEL_REPORT
from .engine.review import VALID

CLASSIFIER: Classifier | None = None
ENGINES: dict[int, object] = {}
ENGINE_LOCK = Lock()          # detection engines hold per-server sliding windows; process batches one at a time

def classifier() -> Classifier:
    global CLASSIFIER
    if CLASSIFIER is None: CLASSIFIER = Classifier()          # trains on first start if no saved model exists
    return CLASSIFIER

def engine_for(con, server_id: int):
    if server_id not in ENGINES: ENGINES[server_id] = istore.build_engine(con, server_id, classifier())
    return ENGINES[server_id]

@asynccontextmanager
async def lifespan(_app):
    classifier(); bootstrap_templates()
    yield

app = FastAPI(title="Cyber Risk Quantification Platform", version="0.2.0", lifespan=lifespan)

class OptimizeRequest(BaseModel): budget_inr: float = Field(gt=0, le=100_000_000)
class IngestRequest(BaseModel): zip_path: str; limit: int | None = Field(default=None, gt=0, le=100000)
class FindingsRequest(BaseModel): csv_path: str
class AssessmentRequest(BaseModel): asset_id: str
class ScenarioRequest(BaseModel): name: str = Field(min_length=2, max_length=80); budget_inr: float = Field(gt=0); action_ids: list[str] = []
class LoginRequest(BaseModel): username: str = Field(min_length=1, max_length=80); password: str = Field(min_length=1, max_length=256)
class LoginLimitRequest(BaseModel): login_limit_per_hour: int = Field(ge=1, le=500)
class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=40, pattern=r"^[A-Za-z0-9._-]+$")
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=256)
class PasswordRequest(BaseModel): current_password: str = Field(min_length=1, max_length=256); new_password: str = Field(min_length=12, max_length=256)
class ServerCreateRequest(BaseModel): display_name: str = Field(min_length=2, max_length=80); hostname: str = Field(min_length=2, max_length=255); sector: str = Field(min_length=2, max_length=80)
class ServerEvent(BaseModel): event_at: datetime; request_method: str | None = Field(default=None, max_length=12); request_path: str | None = Field(default=None, max_length=500); response_status: int | None = Field(default=None, ge=100, le=599); source_ip: str | None = Field(default=None, max_length=64); threat_type: str | None = Field(default=None, max_length=80); severity: str | None = Field(default=None, max_length=20); detector_confidence: float | None = Field(default=None, ge=0, le=1); metadata: dict = Field(default_factory=dict)
class TelemetryBatch(BaseModel): events: list[ServerEvent] = Field(min_length=1, max_length=1000)
class ServerBudgetRequest(BaseModel):
    budget_inr: float = Field(gt=0, le=100_000_000)
    period_days: float | None = Field(default=None, gt=0, le=3650)            # days the incident counts were observed over
    target_reduction: float | None = Field(default=None, gt=0, le=1)          # also find the cheapest plan reaching this reduction
    impact_inr: dict[str, float] | None = None                                # loss per successful incident, by attack type
    success_probability: dict[str, float] | None = None                       # share of incidents that succeed, by attack type
class IncidentReviewRequest(BaseModel):
    decision: str = Field(pattern="^(genuine|attack)$")
    handling: str = Field(pattern="^(one_time|allow_similar|prioritize_similar|block_source)$")
    note: str | None = Field(default=None, max_length=500)
class ServerAssetRequest(BaseModel): asset_id: str | None = Field(default=None, max_length=80)

SESSION_COOKIE = "cyberquant_session"
SESSION_HOURS = 12


def rows(q, values=()):
    with connection() as con: return [dict(x) for x in con.execute(q, values)]

def now(): return datetime.now(timezone.utc)
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"{salt.hex()}${digest.hex()}"
def password_matches(password: str, stored: str) -> bool:
    try:
        salt_hex, expected = stored.split("$", 1)
        actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1).hex()
        return compare_digest(actual, expected)
    except (ValueError, TypeError): return False
def client_ip(request: Request) -> str:
    # Trust a proxy header only when the deployment is configured to do so.
    if os.getenv("CYBERQUANT_TRUST_PROXY") == "1":
        return request.headers.get("x-forwarded-for", "").split(",")[0].strip() or "unknown"
    return request.client.host if request.client else "unknown"
def current_user(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not token: raise HTTPException(401, "Sign in required")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    result = rows("""SELECT u.* FROM user_sessions s JOIN users u ON u.id=s.user_id
        WHERE s.token_hash=? AND s.expires_at>? AND u.is_active=1""", (token_hash, now().isoformat()))
    if not result: raise HTTPException(401, "Your session has expired. Please sign in again.")
    with connection() as con: con.execute("UPDATE user_sessions SET last_seen_at=? WHERE token_hash=?", (now().isoformat(), token_hash))
    return result[0]

@app.middleware("http")
async def require_dashboard_login(request: Request, call_next):
    path = request.url.path
    public = {"/", "/api/v1/health", "/api/v1/auth/login", "/api/v1/auth/me", "/api/v1/auth/register", "/api/v1/auth/config", "/api/v1/auth/forgot", "/api/v1/auth/reset", "/api/v1/auth/google/start", "/api/v1/auth/google/callback"}
    if path.startswith("/api/") and path not in public and not path.startswith("/api/v1/telemetry/"):
        try:
            user = current_user(request)
            if user.get("must_change_password") and path not in {"/api/v1/auth/password", "/api/v1/auth/logout"}:
                return JSONResponse({"detail": "Password change required: open /settings and choose a new password first."}, status_code=403)
        except HTTPException as exc: return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    return await call_next(request)

def asset_risk(asset_id):
    assets = rows("SELECT * FROM assets WHERE asset_id=?", (asset_id,))
    if not assets: raise HTTPException(404, "Asset not found")
    vulns = rows("""SELECT v.*, s.epss_score, s.kev_listed FROM asset_vulnerabilities av JOIN vulnerabilities v ON v.cve_id=av.cve_id
     LEFT JOIN threat_intelligence_snapshots s ON s.cve_id=v.cve_id WHERE av.asset_id=? AND av.finding_status='open'""", (asset_id,))
    result = calculate_asset_risk(assets[0], vulns)
    return {"asset": assets[0], "vulnerabilities": vulns, "event_probability": result.probability, "inherent_expected_loss_inr": result.inherent_loss_inr, "residual_expected_loss_inr": result.residual_loss_inr, "assumptions": result.assumptions}

def investment_category(action_name: str) -> str:
    """Stable reporting taxonomy; costs remain template assumptions until evidence is supplied."""
    name = action_name.lower()
    if "patch" in name or "upgrade" in name: return "Vulnerability patching"
    if "identity" in name or "access" in name: return "Identity and access"
    if "backup" in name or "recovery" in name: return "Backup and recovery"
    if "endpoint" in name or "monitor" in name: return "Monitoring and response"
    return "Cloud and application security"

def write_audit(event_type: str, resource_type: str, resource_id: str | None, metadata: dict):
    with connection() as con:
        con.execute("INSERT INTO audit_events(event_at,actor,event_type,resource_type,resource_id,result,metadata_json) VALUES(?,?,?,?,?,?,?)", (datetime.now(timezone.utc).isoformat(), "local-security-analyst", event_type, resource_type, resource_id, "success", json.dumps(metadata)))

def safe_ingest_path(raw: str, suffix: str) -> Path:
    """Admin import files must live inside CYBERQUANT_INGEST_DIR (default data/raw): no arbitrary server-side file reads."""
    path = Path(raw).expanduser().resolve()
    if INGEST_DIR != path and INGEST_DIR not in path.parents:
        raise HTTPException(422, f"File must be inside the configured import folder: {INGEST_DIR}")
    if not path.is_file() or path.suffix.lower() != suffix: raise HTTPException(422, f"path must be an existing {suffix} file")
    return path

def require_admin(x_admin_token: str | None):
    """LAN deployments must set CYBERQUANT_ADMIN_TOKEN; local development remains frictionless."""
    expected = os.getenv("CYBERQUANT_ADMIN_TOKEN")
    if expected and x_admin_token != expected:
        raise HTTPException(401, "Administrator token required for this operation")

SIGNUPS: dict = {}
def password_problem(pw: str):
    if len(pw) < 12: return "Use at least 12 characters."
    if not (any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw)):
        return "Mix upper-case, lower-case and a number."
    if pw.lower() in {"password1234", "changeme!123", "qwerty123456"}: return "That password is too common."
    return None

@app.get("/api/v1/auth/config")
def auth_config():
    from . import auth_extra
    return {"signup_enabled": os.getenv("CYBERQUANT_ALLOW_SIGNUP", "1") != "0", "min_password_length": 12, **auth_extra.extra_config()}

@app.post("/api/v1/auth/register")
def register(payload: RegisterRequest, request: Request, response: Response):
    if os.getenv("CYBERQUANT_ALLOW_SIGNUP", "1") == "0": raise HTTPException(403, "Account creation is switched off for this deployment. Ask an administrator.")
    ip = client_ip(request); t = now().timestamp()
    recent = [x for x in SIGNUPS.get(ip, []) if t - x < 3600]
    if len(recent) >= 5: raise HTTPException(429, "Too many accounts created from this IP address. Try again later.")
    problem = password_problem(payload.password)
    if problem: raise HTTPException(422, problem)
    from .auth_extra import normalize_email
    email = normalize_email(payload.email)
    if rows("SELECT 1 FROM users WHERE username=?", (payload.username,)): raise HTTPException(409, "That user ID is taken. Pick another.")
    if rows("SELECT 1 FROM users WHERE lower(email)=?", (email,)): raise HTTPException(409, "That email already has an account. Sign in or use Forgot password.")
    SIGNUPS[ip] = recent + [t]
    with connection() as con:
        cur = con.execute("INSERT INTO users(username,password_hash,created_at,must_change_password,email) VALUES(?,?,?,0,?)", (payload.username, hash_password(payload.password), now().isoformat(), email))
        uid = cur.lastrowid
    issue_session(response, uid)
    write_audit("account_created", "user", str(uid), {"ip_address": ip})
    return {"username": payload.username, "must_change_password": False}

def issue_session(response: Response, user_id: int):
    raw_token = secrets.token_urlsafe(32)
    expiry = now() + timedelta(hours=SESSION_HOURS)
    with connection() as con:
        con.execute("INSERT INTO user_sessions VALUES(?,?,?,?,?)", (hashlib.sha256(raw_token.encode()).hexdigest(), user_id, expiry.isoformat(), now().isoformat(), now().isoformat()))
    response.set_cookie(SESSION_COOKIE, raw_token, max_age=SESSION_HOURS*3600, httponly=True, samesite="lax", secure=os.getenv("CYBERQUANT_COOKIE_SECURE") == "1")

@app.post("/api/v1/auth/login")
def login(payload: LoginRequest, request: Request, response: Response):
    ip = client_ip(request)
    user = rows("SELECT * FROM users WHERE username=?", (payload.username,))
    account = user[0] if user else None
    window_start = (now() - timedelta(hours=1)).isoformat()
    limit = account["login_limit_per_hour"] if account else int(os.getenv("CYBERQUANT_UNKNOWN_LOGIN_LIMIT", "10"))
    attempts = rows("SELECT COUNT(*) AS n FROM login_attempts WHERE ip_address=? AND attempted_at>=?", (ip, window_start))[0]["n"]
    if attempts >= limit:
        raise HTTPException(429, "Too many login attempts from this IP address. Try again later.")
    valid = bool(account and account["is_active"] and password_matches(payload.password, account["password_hash"]))
    with connection() as con:
        con.execute("INSERT INTO login_attempts(attempted_at,username,ip_address,success,user_id) VALUES(?,?,?,?,?)", (now().isoformat(), payload.username, ip, int(valid), account["id"] if account else None))
    if not valid: raise HTTPException(401, "Invalid user ID or password")
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expiry = now() + timedelta(hours=SESSION_HOURS)
    with connection() as con:
        con.execute("DELETE FROM user_sessions WHERE expires_at<?", (now().isoformat(),))
        con.execute("INSERT INTO user_sessions VALUES(?,?,?,?,?)", (token_hash, account["id"], expiry.isoformat(), now().isoformat(), now().isoformat()))
    response.set_cookie(SESSION_COOKIE, raw_token, max_age=SESSION_HOURS*3600, httponly=True, samesite="lax", secure=os.getenv("CYBERQUANT_COOKIE_SECURE") == "1")
    write_audit("login", "user", str(account["id"]), {"ip_address": ip})
    return {"username": account["username"], "login_limit_per_hour": account["login_limit_per_hour"], "must_change_password": bool(account.get("must_change_password"))}

@app.get("/api/v1/auth/me")
def me(request: Request):
    try:
        user = current_user(request)
        return {"authenticated": True, "username": user["username"], "login_limit_per_hour": user["login_limit_per_hour"], "must_change_password": bool(user.get("must_change_password"))}
    except HTTPException:
        return {"authenticated": False}

@app.post("/api/v1/auth/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        with connection() as con: con.execute("DELETE FROM user_sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))
    response.delete_cookie(SESSION_COOKIE)
    return {"ok": True}

@app.put("/api/v1/auth/login-limit")
def update_login_limit(payload: LoginLimitRequest, request: Request):
    user = current_user(request)
    with connection() as con: con.execute("UPDATE users SET login_limit_per_hour=? WHERE id=?", (payload.login_limit_per_hour, user["id"]))
    write_audit("login_limit_updated", "user", str(user["id"]), {"login_limit_per_hour": payload.login_limit_per_hour})
    return {"login_limit_per_hour": payload.login_limit_per_hour}

@app.put("/api/v1/auth/password")
def update_password(payload: PasswordRequest, request: Request):
    user = current_user(request)
    if not password_matches(payload.current_password, user["password_hash"]): raise HTTPException(401, "Current password is incorrect")
    if payload.new_password == payload.current_password: raise HTTPException(422, "Choose a new password that differs from the current one")
    with connection() as con:
        con.execute("UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?", (hash_password(payload.new_password), user["id"]))
        con.execute("DELETE FROM user_sessions WHERE user_id=?", (user["id"],))
    return {"ok": True, "message": "Password changed. Please sign in again."}

def server_or_404(server_id: int):
    record = rows("SELECT * FROM monitored_servers WHERE id=? AND is_active=1", (server_id,))
    if not record: raise HTTPException(404, "Connected server not found")
    return record[0]

@app.get("/api/v1/servers")
def servers(request: Request):
    current_user(request)
    return rows("""SELECT s.id,s.display_name,s.hostname,s.sector,s.created_at,s.last_event_at,
        COUNT(e.id) AS events_received, SUM(CASE WHEN e.threat_type IS NOT NULL THEN 1 ELSE 0 END) AS threat_events
        FROM monitored_servers s LEFT JOIN server_events e ON e.server_id=s.id GROUP BY s.id ORDER BY s.id DESC""")

@app.post("/api/v1/servers")
def create_server(payload: ServerCreateRequest, request: Request):
    user = current_user(request); raw_token = secrets.token_urlsafe(32)
    with connection() as con:
        cur = con.execute("INSERT INTO monitored_servers(display_name,hostname,sector,created_at,agent_token_hash) VALUES(?,?,?,?,?)", (payload.display_name, payload.hostname, payload.sector, now().isoformat(), hashlib.sha256(raw_token.encode()).hexdigest()))
    write_audit("server_connected", "server", str(cur.lastrowid), {"hostname": payload.hostname, "sector": payload.sector, "by_user": user["username"]})
    return {"server_id": cur.lastrowid, "agent_token": raw_token, "notice": "Copy this token now; it is only displayed once. Install an agent or webhook integration that sends metadata-only events to the telemetry endpoint."}

@app.post("/api/v1/telemetry/{server_id}")
def ingest_server_telemetry(server_id: int, payload: TelemetryBatch, x_agent_token: str | None = Header(default=None)):
    server = server_or_404(server_id)
    if not x_agent_token or not compare_digest(hashlib.sha256(x_agent_token.encode()).hexdigest(), server["agent_token_hash"]): raise HTTPException(401, "Valid X-Agent-Token required")
    alerts = 0
    with ENGINE_LOCK, connection() as con:
        engine = engine_for(con, server_id)
        for item in sorted(payload.events, key=lambda e: e.event_at.timestamp() if e.event_at.tzinfo else e.event_at.replace(tzinfo=timezone.utc).timestamp()):
            event = item.model_dump()
            if event["event_at"].tzinfo is None: event["event_at"] = event["event_at"].replace(tzinfo=timezone.utc)
            if item.threat_type: event["metadata"] = {**event["metadata"], "collector_hint": {"threat_type": item.threat_type, "severity": item.severity}}   # advisory only
            result = engine.process(event)                 # features -> rules + ML -> incident grouping -> learned review patterns
            alerts += int(result["alert"])
            istore.record_event(con, server_id, event, result)
        con.execute("UPDATE monitored_servers SET last_event_at=? WHERE id=?", (now().isoformat(), server_id))
    return {"accepted": len(payload.events), "alerts_raised": alerts}

@app.get("/api/v1/telemetry/{server_id}/blocklist")
def agent_blocklist(server_id: int, x_agent_token: str | None = Header(default=None)):
    """Connector-readable list of sources an analyst marked for blocking. The platform never changes your firewall itself."""
    server = server_or_404(server_id)
    if not x_agent_token or not compare_digest(hashlib.sha256(x_agent_token.encode()).hexdigest(), server["agent_token_hash"]): raise HTTPException(401, "Valid X-Agent-Token required")
    with connection() as con: return {"blocklist": istore.load_memory(con, server_id).blocklist()}

GUIDANCE = {"Brute force": "Enable MFA, rate-limit authentication, lock accounts temporarily after repeated failures, and block repeat source IPs.",
            "SQL injection": "Use parameterized queries, validate input, apply WAF rules and patch the application.",
            "DDoS": "Apply CDN/WAF rate limiting, autoscaling, upstream filtering and an incident runbook."}
POLICY = {"SQL injection": "Alert when a request target/query matches an SQL-injection signature, or the ML model scores it highly.",
          "Brute force": "Alert at 5 failed logins from one IP in 5 minutes, 10 failures on one account from 5+ IPs (distributed), or one IP failing against 5+ accounts; the ML model adds or tempers confidence.",
          "DDoS": "Alert at 150+ requests/minute from 15+ IPs when traffic is concentrated on one path or user-agent. A diverse surge of real users is not flagged."}

@app.get("/api/v1/servers/{server_id}/analytics")
def server_analytics(server_id: int, request: Request):
    current_user(request); server = server_or_404(server_id)
    monthly = rows("""SELECT substr(event_at,1,7) AS month, COUNT(*) AS requests,
        SUM(CASE WHEN threat_type IS NOT NULL THEN 1 ELSE 0 END) AS threats FROM server_events
        WHERE server_id=? GROUP BY substr(event_at,1,7) ORDER BY month""", (server_id,))
    types = rows("""SELECT threat_type, COUNT(*) AS count, ROUND(AVG(COALESCE(detector_confidence,0)),3) AS average_confidence FROM server_events
        WHERE server_id=? AND threat_type IS NOT NULL GROUP BY threat_type ORDER BY count DESC""", (server_id,))
    incident_types = rows("""SELECT threat_type, COUNT(*) AS incidents FROM incidents WHERE server_id=? AND status IN ('open','closed','reviewed_attack')
        GROUP BY threat_type ORDER BY incidents DESC""", (server_id,))
    sectors = rows("""SELECT s.sector, e.threat_type, COUNT(*) AS count FROM server_events e JOIN monitored_servers s ON s.id=e.server_id
        WHERE e.threat_type IS NOT NULL GROUP BY s.sector,e.threat_type ORDER BY count DESC""")
    with connection() as con:
        traffic = istore.traffic_summary(con, server_id)
        queue = [istore.public_incident(r) for r in con.execute("SELECT * FROM incidents WHERE server_id=? AND status IN ('open','closed') ORDER BY last_at DESC LIMIT 50", (server_id,))]
        reviewed = [istore.public_incident(r) for r in con.execute("SELECT * FROM incidents WHERE server_id=? AND status IN ('reviewed_genuine','reviewed_attack') ORDER BY reviewed_at DESC LIMIT 20", (server_id,))]
        auto = [istore.public_incident(r) for r in con.execute("SELECT * FROM incidents WHERE server_id=? AND status='auto_allowed' ORDER BY last_at DESC LIMIT 20", (server_id,))]
        patterns = [dict(r) for r in con.execute("SELECT * FROM review_patterns WHERE server_id=? ORDER BY id DESC LIMIT 30", (server_id,))]
        blocklist = istore.load_memory(con, server_id).blocklist()
    demo_notice = " This selected server holds SYNTHETIC simulated traffic for demonstration; it is not live security evidence." if server["hostname"] == "demo.cyberquant.local" else ""
    return {"server": {key: server[key] for key in ("id","display_name","hostname","sector","last_event_at","asset_id")}, "monthly": monthly,
            "threat_types": types, "incident_types": incident_types, "sector_breakdown": sectors, "traffic": traffic,
            "incidents": queue, "reviewed_incidents": reviewed, "auto_allowed": auto, "review_patterns": patterns, "blocklist": blocklist,
            "detection_policy": POLICY,
            "mitigation_guidance": [{"threat_type": t["threat_type"], "guidance": GUIDANCE.get(t["threat_type"], "Investigate and harden.")} for t in types],
            "privacy_notice": "Only metadata is stored: request method/path, response code, source IP, user-agent, optional hashed account id and detector output. Request bodies and credentials must never be sent." + demo_notice}

@app.get("/api/v1/servers/{server_id}/charts")
def server_charts(server_id: int, request: Request, tz: int = 0, day: str | None = None):
    """Live minute series, monthly attack counts and a day-by-hour view. tz is JavaScript's getTimezoneOffset()."""
    current_user(request); server_or_404(server_id)
    with connection() as con: return istore.charts(con, server_id, max(-840, min(840, tz)), day)

@app.get("/api/v1/servers/{server_id}/live")
def server_live(server_id: int, request: Request, hours: float = 1, tz: int = 0):
    """Status banner, live feed, top endpoints, attack regions and hour-by-weekday heatmap for the Live traffic page."""
    current_user(request); server_or_404(server_id)
    with connection() as con: return istore.live(con, server_id, hours, max(-840, min(840, tz)))

class SimulateRequest(BaseModel):
    attack: Literal["Brute force", "SQL injection", "DDoS"]

@app.post("/api/v1/servers/{server_id}/simulate")
def simulate_attack(server_id: int, payload: SimulateRequest, request: Request):
    """DEMO ONLY: inject a short burst of clearly labelled SIMULATED attack traffic through the real detection engine."""
    current_user(request); server_or_404(server_id)
    import random
    from datetime import timedelta
    from .engine.simulator import Simulator
    start = datetime.now(timezone.utc) - timedelta(seconds=100)
    sim = Simulator(random.randint(1, 10**6), start=start)
    sim.genuine_background(1.5, 20)
    {"Brute force": lambda: sim.brute_force_single(1.7, 28), "SQL injection": lambda: sim.sql_injection(1.7, 14),
     "DDoS": lambda: sim.ddos(1.7, 1.0, 420)}[payload.attack]()
    events = sorted(sim.events, key=lambda e: e["event_at"]); alerts = 0
    with ENGINE_LOCK, connection() as con:
        engine = engine_for(con, server_id)
        for ev in events:
            ev["metadata"]["demo_simulated"] = True
            result = engine.process(ev); alerts += int(result["alert"]); istore.record_event(con, server_id, ev, result)
        con.execute("UPDATE monitored_servers SET last_event_at=? WHERE id=?", (now().isoformat(), server_id))
    return {"simulated": len(events), "alerts_raised": alerts, "note": "Simulated traffic for demonstration; it is labelled synthetic in the event metadata."}

@app.post("/api/v1/servers/{server_id}/incidents/{incident_id}/review")
def review_incident(server_id: int, incident_id: int, payload: IncidentReviewRequest, request: Request):
    """Analyst marks an incident genuine or an attack. The decision is remembered as a pattern for future matching traffic
    and stored as a labelled example for the next model retrain. It never changes a firewall."""
    user = current_user(request); server_or_404(server_id)
    with ENGINE_LOCK, connection() as con:
        try: pattern = istore.review_incident(con, ENGINES.get(server_id), server_id, incident_id, user["id"], payload.decision, payload.handling, payload.note)
        except LookupError as exc: raise HTTPException(404, str(exc))
        except ValueError as exc: raise HTTPException(422, str(exc))
    write_audit("incident_review", "incident", str(incident_id), {"decision": payload.decision, "handling": payload.handling, "server_id": server_id})
    effect = {"allow_similar": "Similar activity from the same source/endpoint will be auto-allowed while it stays within the volume you reviewed (it re-alerts if it grows).",
              "prioritize_similar": "Similar activity will be raised in severity.", "block_source": "The source IP was added to the recommended blocklist (your connector or firewall must enforce it).",
              "one_time": "Only this incident was labelled."}[payload.handling]
    return {"ok": True, "pattern_id": pattern["id"], "message": "Review saved. " + effect}

@app.get("/api/v1/servers/{server_id}/blocklist")
def server_blocklist(server_id: int, request: Request):
    current_user(request); server_or_404(server_id)
    with connection() as con: return {"blocklist": istore.load_memory(con, server_id).blocklist()}

@app.put("/api/v1/servers/{server_id}/asset")
def link_server_asset(server_id: int, payload: ServerAssetRequest, request: Request):
    """Link a monitored server to an asset so open CVEs on that asset raise the modelled exposure in the budget plan."""
    current_user(request); server_or_404(server_id)
    if payload.asset_id and not rows("SELECT 1 FROM assets WHERE asset_id=?", (payload.asset_id,)): raise HTTPException(404, "Asset not found")
    with connection() as con: con.execute("UPDATE monitored_servers SET asset_id=? WHERE id=?", (payload.asset_id, server_id))
    return {"server_id": server_id, "asset_id": payload.asset_id}

@app.post("/api/v1/servers/{server_id}/budget-plan")
def server_budget_plan(server_id: int, payload: ServerBudgetRequest, request: Request):
    """Choose controls that minimise expected loss for the budget, from this server's detected (and reviewed) incidents."""
    current_user(request); server_or_404(server_id)
    with connection() as con:
        plan = istore.budget_plan(con, server_id, payload.budget_inr, payload.impact_inr, payload.success_probability, payload.period_days, payload.target_reduction)
        cur = con.execute("INSERT INTO server_budget_plans(server_id,created_at,budget_inr,allocated_inr,estimated_loss_avoided_inr,plan_json) VALUES(?,?,?,?,?,?)",
                          (server_id, now().isoformat(), payload.budget_inr, plan["allocated_inr"], plan["loss_avoided_inr"], json.dumps({k: plan[k] for k in ("selected", "per_attack")})))
    plan["plan_id"] = cur.lastrowid
    return plan

@app.get("/api/v1/attacks/{attack}/cves")
def attack_cves(attack: str, limit: int = Query(10, ge=1, le=50)):
    """Highest-CVSS NVD records whose description matches the attack's weakness keywords (heuristic link, not an affected-asset claim)."""
    if attack not in ATTACK_KEYWORDS: raise HTTPException(404, "Unknown attack type")
    clause, params = keyword_sql(attack)
    return {"attack": attack, "cwe": ATTACK_CWE[attack], "match": "description keywords (heuristic)",
            "cves": rows(f"SELECT cve_id,cvss_score,substr(description,1,240) AS description FROM vulnerabilities WHERE {clause} ORDER BY COALESCE(cvss_score,0) DESC LIMIT ?", params + [limit])}

@app.get("/api/v1/model/report")
def web_model_report():
    if not WEB_MODEL_REPORT.exists(): raise HTTPException(404, "No training report saved yet")
    return json.loads(WEB_MODEL_REPORT.read_text(encoding="utf-8"))

@app.post("/api/v1/model/retrain")
def retrain_model(x_admin_token: str | None = Header(default=None)):
    """Retrain with analyst-reviewed examples (genuine -> Normal, attack -> its type) weighted above synthetic rows."""
    require_admin(x_admin_token)
    global CLASSIFIER
    with ENGINE_LOCK, connection() as con: summary = istore.retrain_from_reviews(con)
    if summary.get("status") == "no_reviewed_examples": return summary
    CLASSIFIER = Classifier(auto_train=False)
    for engine in ENGINES.values(): engine.classifier = CLASSIFIER
    return {k: summary[k] for k in ("trained_at", "training_rows", "reviewed_examples_used", "false_positive_rate_ml", "per_class_ml")}

@app.get("/api/v1/health")
def health(): return {"status":"ok", "model_version":MODEL_VERSION, "time":datetime.now(timezone.utc).isoformat()}

@app.get("/api/v1/assets")
def assets(): return rows("SELECT * FROM assets ORDER BY asset_id")

@app.get("/api/v1/assets/{asset_id}/risk")
def risk(asset_id: str): return asset_risk(asset_id)

@app.get("/api/v1/vulnerabilities")
def vulnerabilities(q: str = Query("", max_length=100), limit: int = Query(50, le=200)):
    like=f"%{q}%"; return rows("SELECT * FROM vulnerabilities WHERE cve_id LIKE ? OR description LIKE ? ORDER BY cvss_score DESC LIMIT ?",(like,like,limit))

@app.get("/api/v1/vulnerabilities/{cve_id}")
def vulnerability(cve_id: str):
    record=rows("SELECT * FROM vulnerabilities WHERE cve_id=?",(cve_id,))
    if not record: raise HTTPException(404,"CVE not found")
    return {"vulnerability":record[0],"snapshots":rows("SELECT * FROM threat_intelligence_snapshots WHERE cve_id=? ORDER BY snapshot_at DESC",(cve_id,))}

@app.get("/api/v1/overview")
def overview():
    results=[asset_risk(x["asset_id"]) for x in rows("SELECT asset_id FROM assets")]
    return {"assets":len(results),"open_normalized_vulnerabilities":sum(len(x["vulnerabilities"]) for x in results),"residual_expected_loss_inr":sum(x["residual_expected_loss_inr"] for x in results),"data_note":"Asset and action values are synthetic templates until replaced; NVD data is observed source data when ingested.","assets_by_risk":sorted(({"asset_id":x["asset"]["asset_id"],"asset_name":x["asset"]["asset_name"],"residual_expected_loss_inr":x["residual_expected_loss_inr"]} for x in results),key=lambda x:x["residual_expected_loss_inr"],reverse=True)}

@app.get("/api/v1/dashboard/overview")
def dashboard_overview(): return overview()

@app.get("/api/v1/dashboard/trends")
def dashboard_trends():
    return rows("SELECT assessed_at, SUM(residual_loss_inr) AS residual_loss_inr, COUNT(*) AS assets_assessed FROM risk_assessments GROUP BY assessed_at ORDER BY assessed_at")

@app.get("/api/v1/dashboard/threat-priorities")
def threat_priorities(limit: int = Query(5, ge=1, le=25)):
    """Rank verified organization findings; public CVEs alone are never treated as affected."""
    findings = rows("""SELECT v.cve_id, v.cvss_score, a.asset_id, a.asset_name, a.internet_exposed,
        a.business_criticality, a.estimated_loss_inr, a.existing_control_strength, s.epss_score, s.kev_listed
        FROM asset_vulnerabilities av JOIN vulnerabilities v ON v.cve_id=av.cve_id
        JOIN assets a ON a.asset_id=av.asset_id LEFT JOIN threat_intelligence_snapshots s ON s.cve_id=v.cve_id
        WHERE av.finding_status='open'""")
    ranked = []
    for finding in findings:
        risk = calculate_asset_risk(finding, [finding])
        likelihood = finding.get("epss_score") or min(.95, (finding.get("cvss_score") or 0) / 40)
        score = risk.residual_loss_inr * (1.25 if finding.get("kev_listed") else 1) * (1 + likelihood)
        ranked.append({"cve_id": finding["cve_id"], "asset_name": finding["asset_name"], "cvss_score": finding["cvss_score"], "kev_listed": bool(finding.get("kev_listed")), "priority_score": round(score, 2), "reason": "Known exploited vulnerability" if finding.get("kev_listed") else "Highest contextual expected loss"})
    return sorted(ranked, key=lambda item: item["priority_score"], reverse=True)[:limit]

@app.get("/api/v1/intrusion-detection/report")
def intrusion_detection_report():
    report = ROOT / "data" / "models" / "unsw_nb15_report.json"
    if not report.exists(): raise HTTPException(404, "No trained intrusion model report is available. Run python -m src.asset_risk.intrusion_model.")
    return json.loads(report.read_text(encoding="utf-8"))

@app.get("/api/v1/assets/{asset_id}")
def asset_detail(asset_id: str):
    risk_result = asset_risk(asset_id)
    risk_result["history"] = rows("SELECT * FROM risk_assessments WHERE asset_id=? ORDER BY assessed_at DESC", (asset_id,))
    return risk_result

@app.post("/api/v1/risk/assess")
def assess(request: AssessmentRequest):
    result = asset_risk(request.asset_id)
    at = datetime.now(timezone.utc).isoformat()
    with connection() as con:
        cur = con.execute("INSERT INTO risk_assessments(asset_id,assessed_at,model_version,inherent_loss_inr,residual_loss_inr,event_probability,assumptions_json) VALUES(?,?,?,?,?,?,?)", (request.asset_id,at,MODEL_VERSION,result["inherent_expected_loss_inr"],result["residual_expected_loss_inr"],result["event_probability"],json.dumps(result["assumptions"])))
    write_audit("risk_assessment","asset",request.asset_id,{"assessment_id":cur.lastrowid,"model_version":MODEL_VERSION})
    return {"assessment_id":cur.lastrowid,"assessed_at":at,**result}

@app.get("/api/v1/risk/assessments/{assessment_id}")
def assessment(assessment_id: int):
    result=rows("SELECT * FROM risk_assessments WHERE id=?",(assessment_id,))
    if not result: raise HTTPException(404,"Assessment not found")
    return result[0]

@app.post("/api/v1/optimization")
def run_optimization(request: OptimizeRequest):
    assessments=[asset_risk(x["asset_id"]) for x in rows("SELECT asset_id FROM assets")]
    result=optimize(rows("SELECT * FROM remediation_actions"),{x["asset"]["asset_id"]:x["residual_expected_loss_inr"] for x in assessments},request.budget_inr)
    with connection() as con:
        cur=con.execute("INSERT INTO optimization_runs(run_at,budget_inr,selected_cost_inr,modeled_reduction_inr,assumptions_json) VALUES(?,?,?,?,?)",(datetime.now(timezone.utc).isoformat(),request.budget_inr,result["cost_inr"],result["risk_reduction_inr"],json.dumps({"cost_effectiveness":"illustrative template assumptions","overlap":"multiplicative residual calculation"})))
        for a in result["selected"]: con.execute("INSERT INTO optimization_selections VALUES(?,?)",(cur.lastrowid,a["action_id"]))
    write_audit("optimization_run","optimization",str(cur.lastrowid),{"budget_inr":request.budget_inr,"selected_actions":len(result["selected"])})
    return {**result,"run_id":cur.lastrowid,"remaining_budget_inr":request.budget_inr-result["cost_inr"],"assumption_notice":"Recommendation is a simulated decision aid; effectiveness and costs are labeled illustrative assumptions."}

@app.post("/api/v1/optimization/run")
def optimization_run(request: OptimizeRequest): return run_optimization(request)

@app.post("/api/v1/scenarios")
def create_scenario(request: ScenarioRequest):
    assessments=[asset_risk(x["asset_id"]) for x in rows("SELECT asset_id FROM assets")]
    baseline=sum(x["residual_expected_loss_inr"] for x in assessments)
    actions=rows("SELECT * FROM remediation_actions")
    selected=[a for a in actions if a["action_id"] in request.action_ids]
    cost=sum(a["cost_inr"] for a in selected)
    if cost > request.budget_inr: raise HTTPException(422,"Selected actions exceed scenario budget")
    result=optimize(selected,{x["asset"]["asset_id"]:x["residual_expected_loss_inr"] for x in assessments},request.budget_inr)
    residual=baseline-result["risk_reduction_inr"]
    with connection() as con:
        cur=con.execute("INSERT INTO scenarios(name,created_at,budget_inr,action_ids_json,baseline_loss_inr,residual_loss_inr,assumptions_json) VALUES(?,?,?,?,?,?,?)",(request.name,datetime.now(timezone.utc).isoformat(),request.budget_inr,json.dumps(request.action_ids),baseline,residual,json.dumps({"mode":"temporary simulation","action_effectiveness":"illustrative template assumptions"})))
    write_audit("scenario_created","scenario",str(cur.lastrowid),{"name":request.name})
    return {"scenario_id":cur.lastrowid,"name":request.name,"cost_inr":result["cost_inr"],"baseline_loss_inr":baseline,"residual_loss_inr":residual,"risk_reduction_inr":result["risk_reduction_inr"],"note":"Simulation does not modify actual asset or finding status."}

@app.post("/api/v1/scenarios/{scenario_id}/run")
def run_scenario(scenario_id: int):
    scenario=rows("SELECT * FROM scenarios WHERE id=?",(scenario_id,))
    if not scenario: raise HTTPException(404,"Scenario not found")
    return scenario[0]

@app.get("/api/v1/audit-events")
def audit_events(limit: int = Query(50, le=200)):
    return rows("SELECT * FROM audit_events ORDER BY event_at DESC LIMIT ?",(limit,))

@app.get("/api/v1/integrations/status")
def integrations_status():
    latest=rows("SELECT source,finished_at,records_seen,records_upserted,status,message FROM ingestion_runs ORDER BY id DESC LIMIT 10")
    return {"nvd":{"records":rows("SELECT COUNT(*) AS n FROM vulnerabilities")[0]["n"],"latest_runs":[x for x in latest if x["source"].startswith("NVD")]},"epss":{"status":"not_loaded","note":"No EPSS snapshot supplied."},"kev":{"status":"not_loaded","note":"No CISA KEV snapshot supplied."}}

@app.get("/api/v1/model-metrics")
def model_metrics(): return rows("SELECT * FROM model_versions")

@app.get("/api/v1/investment/utilization")
def investment_utilization():
    """Return the persisted latest optimizer run, never an invented allocation percentage."""
    latest = rows("SELECT * FROM optimization_runs ORDER BY id DESC LIMIT 1")
    categories = ["Vulnerability patching", "Identity and access", "Endpoint and network", "Cloud and application security", "Backup and recovery", "Monitoring and response"]
    if not latest:
        return {"status":"no_optimization_run", "budget_inr":0, "allocated_inr":0, "remaining_inr":0, "modeled_reduction_inr":0, "categories":[{"name":x,"allocated_inr":0,"actions":[]} for x in categories], "note":"Run the optimizer to create a persisted budget allocation."}
    run = latest[0]
    selected = rows("""SELECT a.action_id,a.action_name,a.cost_inr,a.effectiveness_estimate FROM optimization_selections s
        JOIN remediation_actions a ON a.action_id=s.action_id WHERE s.run_id=?""", (run["id"],))
    grouped = {x:{"name":x,"allocated_inr":0,"actions":[]} for x in categories}
    for action in selected:
        category = investment_category(action["action_name"])
        grouped[category]["allocated_inr"] += action["cost_inr"]
        grouped[category]["actions"].append(action)
    return {"status":"saved_run", "run_id":run["id"], "run_at":run["run_at"], "budget_inr":run["budget_inr"], "allocated_inr":run["selected_cost_inr"], "remaining_inr":run["budget_inr"]-run["selected_cost_inr"], "modeled_reduction_inr":run["modeled_reduction_inr"], "categories":list(grouped.values()), "note":"Allocation is derived from the latest saved optimization selection. Costs and effectiveness may be illustrative assumptions."}

@app.post("/api/v1/admin/ingest/nvd")
def ingest(request: IngestRequest, x_admin_token: str | None = Header(default=None)):
    # Deployment should place this endpoint behind authentication.
    require_admin(x_admin_token); path = safe_ingest_path(request.zip_path, ".zip")
    return ingest_nvd_zip(path,request.limit)

@app.post("/api/v1/admin/import-findings")
def import_findings(request: FindingsRequest, x_admin_token: str | None = Header(default=None)):
    require_admin(x_admin_token); path = safe_ingest_path(request.csv_path, ".csv")
    try: return import_asset_findings(path)
    except ValueError as exc: raise HTTPException(422,str(exc))

@app.get("/")
def login_page(): return FileResponse(ROOT / "web" / "login.html")

def page(request: Request, name: str, allow_default_password: bool = False):
    try: user = current_user(request)
    except HTTPException: return RedirectResponse("/")
    if user.get("must_change_password") and not allow_default_password: return RedirectResponse("/settings")
    return FileResponse(ROOT / "web" / name)

@app.get("/theme.css")
def theme_css(): return FileResponse(ROOT / "web" / "theme.css", media_type="text/css")

@app.get("/home")
def home_page(request: Request): return page(request, "home.html")

@app.get("/dashboard")
def dashboard(request: Request): return page(request, "risk_overview.html")

@app.get("/portfolio")
def portfolio_page(request: Request): return page(request, "index.html")

@app.get("/settings")
def settings_page(request: Request): return page(request, "settings.html", allow_default_password=True)

@app.get("/detections")
def detections_page(request: Request): return page(request, "detections.html")

@app.get("/servers")
def servers_page(request: Request): return RedirectResponse("/home")

@app.get("/threat-center")
def threat_center_page(request: Request): return page(request, "threat_center.html")

@app.get("/server-ai")
def server_ai_page(request: Request): return page(request, "server_ai.html")

from . import auth_extra as _auth_extra
app.include_router(_auth_extra.router)
