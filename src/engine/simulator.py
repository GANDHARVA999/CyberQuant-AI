"""Synthetic web-traffic generator with ground-truth labels.

Includes hard negatives on purpose: forgetful users, offices behind one NAT, genuine
traffic surges and searches containing quotes. Everything produced here is SYNTHETIC and is
labelled as such wherever it is stored; it is a stand-in until real server logs are connected.
"""
from __future__ import annotations
import random
from datetime import datetime, timedelta, timezone

BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) Safari/605.1",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/127.0", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5) Mobile Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14) Chrome/126.0 Mobile", "Mozilla/5.0 (Windows NT 10.0) Edg/126.0",
    "Mozilla/5.0 (iPad; CPU OS 17_5) Safari/604.1", "Mozilla/5.0 (Windows NT 6.1) Firefox/115.0",
]
BOT_UAS = ["python-requests/2.31", "curl/8.4.0", "Go-http-client/2.0", "Mozilla/5.0 (compatible; bot/1.0)"]
GENUINE_PATHS = ["/", "/products", "/products/12", "/products/48", "/cart", "/about", "/api/items", "/checkout",
                 "/static/app.js", "/static/site.css", "/contact", "/blog/post-1", "/blog/post-2", "/account"]
GENUINE_QUERIES = ["shoes", "o'brien", "select shoes", "red dress", "books - fiction", "50% off", "laptop 15\"", "tom & jerry"]
SQLI_PAYLOADS = ["' OR '1'='1", "1 OR 1=1", "' UNION SELECT username,password FROM users--", "1; DROP TABLE users--",
                 "' OR 1=1--", "admin'--", "1 UNION ALL SELECT NULL,table_name FROM information_schema.tables--",
                 "'; WAITFOR DELAY '0:0:5'--", "1 AND SLEEP(5)", "%27%20OR%20%271%27=%271", "' AND 1=1 --", "x' OR 'a'='a"]
SQLI_TARGETS = ["/search", "/products", "/api/items", "/login", "/account"]
DDOS_PATHS = ["/", "/api/items", "/products", "/search?q=a"]


def _ip(rng: random.Random) -> str:
    return f"{rng.choice([37, 49, 82, 103, 117, 138, 157, 176, 185, 203, 41, 59])}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


class Simulator:
    def __init__(self, seed: int = 0, start: datetime | None = None):
        self.rng = random.Random(seed)
        self.start = start or datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)
        self.events: list[dict] = []
        self.ips = [_ip(self.rng) for _ in range(400)]
        self.users = [f"u{self.rng.randint(10000, 99999)}" for _ in range(300)]

    def _add(self, t: float, method, path, status, ip, ua, label, account=None, scenario="genuine"):
        meta = {"user_agent": ua, "synthetic": True, "scenario": scenario}
        if account: meta["account"] = account
        self.events.append({"event_at": self.start + timedelta(seconds=t), "request_method": method,
                            "request_path": path, "response_status": status, "source_ip": ip,
                            "metadata": meta, "label": label})

    # ---- genuine traffic -------------------------------------------------------------
    def genuine_background(self, minutes: float, rate_per_min: float = 25):
        t, end, r = 0.0, minutes * 60, self.rng
        while True:
            t += r.expovariate(rate_per_min / 60)
            if t > end: break
            ip = r.choices(self.ips, weights=[1 / (i + 3) for i in range(len(self.ips))])[0]
            if r.random() < 0.06:
                q = r.choice(GENUINE_QUERIES); path = f"/search?q={q.replace(' ', '+')}"
            else:
                path = r.choice(GENUINE_PATHS)
            status = r.choices([200, 304, 404, 500], weights=[88, 6, 5, 1])[0]
            self._add(t, "GET", path, status, ip, r.choice(BROWSER_UAS), "Normal")

    def genuine_logins(self, minutes: float, n: int):
        r = self.rng
        for _ in range(n):
            t0, ip, user, ua = r.uniform(0, minutes * 60 - 120), r.choice(self.ips), r.choice(self.users), r.choice(BROWSER_UAS)
            fails = r.choices([0, 1, 2, 3, 4, 5, 6], weights=[50, 15, 10, 8, 7, 6, 4])[0]   # forgetful users
            t = t0
            for _ in range(fails):
                self._add(t, "POST", "/login", 401, ip, ua, "Normal", user, "forgetful_user"); t += r.uniform(4, 25)
            self._add(t, "POST", "/login", r.choice([200, 302]), ip, ua, "Normal", user, "forgetful_user")

    def forgetful_login(self, at_s: float, fails: int, succeed: bool = True, ip: str | None = None, user: str | None = None):
        """One genuine user mistyping a password `fails` times (optionally ending in a successful login)."""
        r = self.rng; ip, user, ua, t = ip or r.choice(self.ips), user or r.choice(self.users), r.choice(BROWSER_UAS), at_s
        for _ in range(fails):
            self._add(t, "POST", "/login", 401, ip, ua, "Normal", user, "forgetful_user"); t += r.uniform(8, 25)
        if succeed: self._add(t, "POST", "/login", 200, ip, ua, "Normal", user, "forgetful_user")
        return ip, user

    def office_nat(self, minutes: float):
        """Several employees behind one public IP, each mistyping a password once or twice."""
        r = self.rng
        ip, t0 = r.choice(self.ips), r.uniform(0, max(1, minutes * 60 - 200))
        for user in r.sample(self.users, r.randint(2, 4)):
            ua, t = r.choice(BROWSER_UAS), t0 + r.uniform(0, 120)
            for _ in range(r.randint(1, 2)):
                self._add(t, "POST", "/login", 401, ip, ua, "Normal", user, "office_nat"); t += r.uniform(5, 30)
            self._add(t, "POST", "/login", 200, ip, ua, "Normal", user, "office_nat")

    def flash_crowd(self, minutes: float, duration_min: float = 3, rate_per_min: float = 180):
        """Genuine surge (sale, viral link): high volume, but diverse paths and user-agents."""
        r = self.rng; t0 = r.uniform(0, max(1, minutes * 60 - duration_min * 60)); t = t0
        while t < t0 + duration_min * 60:
            t += r.expovariate(rate_per_min / 60)
            self._add(t, "GET", r.choice(GENUINE_PATHS), r.choices([200, 304, 503], weights=[92, 6, 2])[0],
                      r.choice(self.ips), r.choice(BROWSER_UAS), "Normal", scenario="flash_crowd")

    # ---- attacks ---------------------------------------------------------------------
    def brute_force_single(self, minutes: float, attempts: int | None = None):
        r = self.rng; ip, t = _ip(r), r.uniform(0, max(1, minutes * 60 - 180)); ua = r.choice(BOT_UAS + BROWSER_UAS[:2])
        target = r.choice(self.users)
        for i in range(attempts or r.randint(9, 80)):
            t += r.uniform(0.3, 6)
            self._add(t, "POST", "/login", r.choices([401, 403, 429], weights=[85, 5, 10])[0], ip, ua, "Brute force",
                      target if r.random() < 0.7 else r.choice(self.users), "brute_single")

    def brute_force_distributed(self, minutes: float, ips: int | None = None):
        r = self.rng; target = r.choice(self.users); t0 = r.uniform(0, max(1, minutes * 60 - 280))
        pool = [_ip(r) for _ in range(ips or r.randint(15, 80))]; ua = r.choice(BOT_UAS)
        for ip in pool:
            for _ in range(r.randint(1, 3)):
                self._add(t0 + r.uniform(0, 270), "POST", "/login", 401, ip, ua if r.random() < .6 else r.choice(BROWSER_UAS),
                          "Brute force", target, "brute_distributed")

    def credential_stuffing(self, minutes: float):
        r = self.rng; ip, t = _ip(r), r.uniform(0, max(1, minutes * 60 - 150)); ua = r.choice(BOT_UAS)
        for user in r.sample(self.users, r.randint(12, 60)):
            t += r.uniform(0.5, 4)
            self._add(t, "POST", "/login", 401, ip, ua, "Brute force", user, "credential_stuffing")

    def sql_injection(self, minutes: float, requests: int | None = None):
        r = self.rng; ip, t = _ip(r), r.uniform(0, max(1, minutes * 60 - 60)); ua = r.choice(BOT_UAS + BROWSER_UAS[:2])
        for _ in range(requests or r.randint(3, 40)):
            t += r.uniform(0.5, 8)
            payload = r.choice(SQLI_PAYLOADS).replace(" ", r.choice(["%20", "+", " "]))
            self._add(t, "GET", f"{r.choice(SQLI_TARGETS)}?q={payload}&id={r.randint(1, 99)}",
                      r.choices([200, 403, 500], weights=[40, 40, 20])[0], ip, ua, "SQL injection", scenario="sqli")

    def ddos(self, minutes: float, duration_min: float = 2, rate_per_min: float | None = None):
        r = self.rng; t0 = r.uniform(0, max(1, minutes * 60 - duration_min * 60)); t = t0
        rate = rate_per_min or r.uniform(220, 600)
        bots = [_ip(r) for _ in range(r.randint(40, 300))]
        uas = r.sample(BOT_UAS + BROWSER_UAS[:2], r.randint(1, 3)); paths = r.sample(DDOS_PATHS, r.randint(1, 3))
        while t < t0 + duration_min * 60:
            t += r.expovariate(rate / 60)
            self._add(t, "GET", r.choice(paths), r.choices([200, 429, 503], weights=[30, 25, 45])[0],
                      r.choice(bots), r.choice(uas), "DDoS", scenario="ddos")

    # ---- assembly --------------------------------------------------------------------
    def session(self, minutes: float = 30, attacks: dict | None = None, rate: float = 25):
        """attacks: counts per scenario, e.g. {'brute_single':1,'sqli':1,'ddos':1,'brute_distributed':1}."""
        attacks = attacks if attacks is not None else {
            k: self.rng.choice([0, 1, 1, 2]) for k in ("brute_single", "brute_distributed", "credential_stuffing", "sqli", "ddos")}
        self.genuine_background(minutes, rate)
        self.genuine_logins(minutes, int(minutes * 0.8))
        for _ in range(self.rng.choice([0, 1, 2])): self.office_nat(minutes)
        for _ in range(self.rng.choice([0, 0, 1])): self.flash_crowd(minutes)
        fn = {"brute_single": self.brute_force_single, "brute_distributed": self.brute_force_distributed,
              "credential_stuffing": self.credential_stuffing, "sqli": self.sql_injection, "ddos": self.ddos}
        for name, count in attacks.items():
            for _ in range(count): fn[name](minutes)
        self.events.sort(key=lambda e: e["event_at"])
        return self.events
