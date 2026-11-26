"""Forgot-password (email reset link) and Sign in with Google (OAuth 2.0 authorization code + PKCE).

Configuration comes from environment variables, or from a local .env file next to the project:
  CYBERQUANT_BASE_URL         public address of the app, e.g. http://127.0.0.1:8000 (used in links and the Google redirect)
  GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET   from Google Cloud Console > APIs & Services > Credentials (Web application)
  CYBERQUANT_SMTP_HOST / _PORT / _USER / _PASSWORD / _FROM   mail server used to send reset links (Gmail: smtp.gmail.com, 587, app password)
"""
import base64, hashlib, json, logging, os, re, secrets, smtplib, urllib.parse, urllib.request
from email.message import EmailMessage
from datetime import timedelta
from hmac import compare_digest
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field
from .settings import ROOT
from .database import connection

log = logging.getLogger("uvicorn.error")
router = APIRouter()
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")
RESET_MINUTES = 30
HITS: dict = {}

def _load_env_file():
    f = ROOT / ".env"
    if not f.is_file(): return
    for line in f.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1); os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
_load_env_file()

def _api():
    from . import api          # imported lazily: api.py includes this router at its end
    return api

def google_enabled(): return bool(os.getenv("GOOGLE_CLIENT_ID") and os.getenv("GOOGLE_CLIENT_SECRET"))
def smtp_enabled(): return bool(os.getenv("CYBERQUANT_SMTP_HOST"))
def extra_config(): return {"google_enabled": google_enabled(), "reset_email_enabled": smtp_enabled()}

def normalize_email(value: str) -> str:
    value = (value or "").strip().lower()
    if not EMAIL_RE.match(value) or len(value) > 254: raise HTTPException(422, "Enter a valid email address.")
    return value

def throttle(key: str, limit: int, seconds: int = 3600):
    import time; t = time.time(); recent = [x for x in HITS.get(key, []) if t - x < seconds]
    if len(recent) >= limit: raise HTTPException(429, "Too many requests. Try again later.")
    HITS[key] = recent + [t]

def base_url(request: Request) -> str:
    return (os.getenv("CYBERQUANT_BASE_URL") or str(request.base_url)).rstrip("/")

def send_mail(to: str, subject: str, body: str) -> bool:
    if not smtp_enabled(): return False
    msg = EmailMessage(); msg["To"] = to; msg["Subject"] = subject
    msg["From"] = os.getenv("CYBERQUANT_SMTP_FROM") or os.getenv("CYBERQUANT_SMTP_USER") or "no-reply@localhost"
    msg.set_content(body)
    host, port = os.getenv("CYBERQUANT_SMTP_HOST"), int(os.getenv("CYBERQUANT_SMTP_PORT", "587"))
    try:
        smtp = smtplib.SMTP_SSL(host, port, timeout=15) if port == 465 else smtplib.SMTP(host, port, timeout=15)
        with smtp:
            if port != 465: smtp.starttls()
            if os.getenv("CYBERQUANT_SMTP_USER"): smtp.login(os.getenv("CYBERQUANT_SMTP_USER"), os.getenv("CYBERQUANT_SMTP_PASSWORD", ""))
            smtp.send_message(msg)
        return True
    except Exception as exc:
        log.error("Could not send password-reset email: %s", exc); return False

class ForgotRequest(BaseModel): identifier: str = Field(min_length=1, max_length=254)
class ResetRequest(BaseModel):
    token: str = Field(min_length=10, max_length=200)
    new_password: str = Field(min_length=12, max_length=256)
class EmailRequest(BaseModel): email: str = Field(max_length=254)

@router.get("/reset-password")
def reset_page(): return FileResponse(ROOT / "web" / "reset.html")

@router.post("/api/v1/auth/forgot")
def forgot(payload: ForgotRequest, request: Request):
    a = _api(); ip = a.client_ip(request); throttle("forgot:" + ip, 5)
    ident = payload.identifier.strip()
    found = a.rows("SELECT * FROM users WHERE is_active=1 AND (lower(email)=lower(?) OR username=?)", (ident, ident))
    out = {"message": "If that account has an email address, a reset link is on its way. The link works for 30 minutes."}
    if not found or not found[0].get("email"): return out        # same answer either way: never reveal which accounts exist
    user = found[0]; throttle(f"forgot-user:{user['id']}", 3)
    token = secrets.token_urlsafe(32)
    with connection() as con:
        con.execute("DELETE FROM password_resets WHERE expires_at<? OR used_at IS NOT NULL", (a.now().isoformat(),))
        con.execute("INSERT INTO password_resets(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)",
                    (hashlib.sha256(token.encode()).hexdigest(), user["id"], (a.now() + timedelta(minutes=RESET_MINUTES)).isoformat(), a.now().isoformat()))
    link = f"{base_url(request)}/reset-password?token={token}"
    sent = send_mail(user["email"], "Reset your CyberQuant AI password",
        f"Hello {user['username']},\n\nUse this link to choose a new password. It works once and expires in {RESET_MINUTES} minutes:\n\n{link}\n\nIf you did not ask for this, ignore this email; your password stays the same.\n")
    a.write_audit("password_reset_requested", "user", str(user["id"]), {"ip_address": ip, "emailed": sent})
    local = ip in {"127.0.0.1", "::1", "localhost"} or os.getenv("CYBERQUANT_DEV_RESET_LINKS") == "1"
    if not sent and local:
        log.warning("Email is not configured. Password reset link for %s: %s", user["username"], link)
        out["dev_link"] = link; out["dev_note"] = "Email sending is not configured, so the link is shown here (local use only)."
    return out

@router.post("/api/v1/auth/reset")
def reset(payload: ResetRequest, request: Request):
    a = _api(); throttle("reset:" + a.client_ip(request), 20)
    problem = a.password_problem(payload.new_password)
    if problem: raise HTTPException(422, problem)
    h = hashlib.sha256(payload.token.encode()).hexdigest()
    row = a.rows("SELECT * FROM password_resets WHERE token_hash=? AND used_at IS NULL AND expires_at>?", (h, a.now().isoformat()))
    if not row: raise HTTPException(400, "This reset link is invalid or has expired. Ask for a new one.")
    uid = row[0]["user_id"]
    with connection() as con:
        con.execute("UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?", (a.hash_password(payload.new_password), uid))
        con.execute("UPDATE password_resets SET used_at=? WHERE token_hash=?", (a.now().isoformat(), h))
        con.execute("DELETE FROM user_sessions WHERE user_id=?", (uid,))
        con.execute("DELETE FROM login_attempts WHERE user_id=?", (uid,))
    a.write_audit("password_reset_completed", "user", str(uid), {})
    return {"ok": True, "message": "Password changed. Sign in with your new password."}

@router.get("/api/v1/auth/account")
def account(request: Request):
    u = _api().current_user(request)
    return {"username": u["username"], "email": u.get("email"), "google_linked": bool(u.get("google_sub")), "google_enabled": google_enabled()}

@router.put("/api/v1/auth/email")
def set_email(payload: EmailRequest, request: Request):
    a = _api(); u = a.current_user(request); email = normalize_email(payload.email)
    if a.rows("SELECT 1 FROM users WHERE lower(email)=? AND id<>?", (email, u["id"])): raise HTTPException(409, "That email is already used by another account.")
    with connection() as con: con.execute("UPDATE users SET email=? WHERE id=?", (email, u["id"]))
    a.write_audit("email_updated", "user", str(u["id"]), {})
    return {"email": email}

# ---------- Sign in with Google ----------
def _b64(b: bytes) -> str: return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def decode_jwt_payload(token: str) -> dict:
    part = token.split(".")[1]; return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))

def verify_id_token(id_token: str, client_id: str, now_ts: float | None = None) -> dict:
    """The token arrives straight from Google's token endpoint over TLS, so claims are checked, not the signature (Google's documented approach)."""
    import time; claims = decode_jwt_payload(id_token)
    if claims.get("aud") != client_id: raise ValueError("wrong audience")
    if claims.get("iss") not in ("accounts.google.com", "https://accounts.google.com"): raise ValueError("wrong issuer")
    if float(claims.get("exp", 0)) < (now_ts or time.time()): raise ValueError("token expired")
    if not claims.get("email") or claims.get("email_verified") not in (True, "true"): raise ValueError("email not verified by Google")
    return claims

def exchange_code(code: str, verifier: str, redirect_uri: str) -> str:
    data = urllib.parse.urlencode({"code": code, "client_id": os.getenv("GOOGLE_CLIENT_ID"), "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
        "redirect_uri": redirect_uri, "grant_type": "authorization_code", "code_verifier": verifier}).encode()
    with urllib.request.urlopen(urllib.request.Request("https://oauth2.googleapis.com/token", data=data), timeout=15) as r:
        return json.load(r)["id_token"]

@router.get("/api/v1/auth/google/start")
def google_start(request: Request, link: int = 0):
    if not google_enabled():
        return JSONResponse({"detail": "Google sign-in is not set up. Add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET to .env (see README)."}, status_code=503)
    host = urllib.parse.urlparse(base_url(request))
    if host.scheme != "https" and host.hostname not in {"127.0.0.1", "localhost"}:
        # Google only accepts http redirect addresses on localhost, not on a Wi-Fi address like 192.168.x.x
        return RedirectResponse("/login.html?error=google_network")
    if link:
        try: _api().current_user(request)
        except HTTPException: return RedirectResponse("/")
    state, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    q = urllib.parse.urlencode({"client_id": os.getenv("GOOGLE_CLIENT_ID"), "redirect_uri": base_url(request) + "/api/v1/auth/google/callback",
        "response_type": "code", "scope": "openid email profile", "state": state, "prompt": "select_account",
        "code_challenge": _b64(hashlib.sha256(verifier.encode()).digest()), "code_challenge_method": "S256"})
    resp = RedirectResponse("https://accounts.google.com/o/oauth2/v2/auth?" + q)
    resp.set_cookie("cq_oauth", f"{state}.{verifier}.{int(bool(link))}", max_age=600, httponly=True, samesite="lax", secure=os.getenv("CYBERQUANT_COOKIE_SECURE") == "1")
    return resp

def _unique_username(base: str) -> str:
    a = _api(); base = re.sub(r"[^A-Za-z0-9._-]", "", base)[:30] or "user"; name, n = base, 1
    while a.rows("SELECT 1 FROM users WHERE username=?", (name,)): n += 1; name = f"{base}{n}"
    return name

@router.get("/api/v1/auth/google/callback")
def google_callback(request: Request, code: str = "", state: str = "", error: str = ""):
    a = _api(); fail = lambda why: RedirectResponse("/?error=" + why)
    cookie = request.cookies.get("cq_oauth", "").split(".")
    if error or not code or len(cookie) != 3 or not compare_digest(cookie[0], state): return fail("google_cancelled")
    try:
        claims = verify_id_token(exchange_code(code, cookie[1], base_url(request) + "/api/v1/auth/google/callback"), os.getenv("GOOGLE_CLIENT_ID", ""))
    except Exception as exc:
        log.error("Google sign-in failed: %s", exc); return fail("google_failed")
    sub, email = claims["sub"], claims["email"].lower()
    if cookie[2] == "1":                                           # linking from Settings
        try: u = a.current_user(request)
        except HTTPException: return RedirectResponse("/")
        if a.rows("SELECT 1 FROM users WHERE (google_sub=? OR lower(email)=?) AND id<>?", (sub, email, u["id"])): return RedirectResponse("/settings?google=taken")
        with connection() as con: con.execute("UPDATE users SET google_sub=?, email=COALESCE(email, ?) WHERE id=?", (sub, email, u["id"]))
        a.write_audit("google_linked", "user", str(u["id"]), {}); return RedirectResponse("/settings?google=linked")
    found = a.rows("SELECT * FROM users WHERE is_active=1 AND google_sub=?", (sub,)) or a.rows("SELECT * FROM users WHERE is_active=1 AND lower(email)=?", (email,))
    if found:
        uid = found[0]["id"]
        if not found[0].get("google_sub"):
            with connection() as con: con.execute("UPDATE users SET google_sub=? WHERE id=?", (sub, uid))
    else:
        if os.getenv("CYBERQUANT_ALLOW_SIGNUP", "1") == "0": return fail("signup_disabled")
        with connection() as con:
            uid = con.execute("INSERT INTO users(username,password_hash,created_at,must_change_password,email,google_sub) VALUES(?,?,?,0,?,?)",
                (_unique_username(email.split("@")[0]), a.hash_password(secrets.token_urlsafe(32)), a.now().isoformat(), email, sub)).lastrowid
        a.write_audit("account_created", "user", str(uid), {"via": "google"})
    resp = RedirectResponse("/home"); a.issue_session(resp, uid); resp.delete_cookie("cq_oauth")
    a.write_audit("login", "user", str(uid), {"via": "google"})
    return resp
