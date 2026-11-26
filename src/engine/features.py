"""Sliding-window feature extraction from request metadata (no bodies, no credentials).

All counters are updated incrementally, so each event costs O(1) amortised even
during a flood. The same extractor is used for training, simulation and live traffic,
which guarantees the model sees identical features in all three places.
"""
from __future__ import annotations
import re
from collections import Counter, defaultdict, deque
from urllib.parse import unquote_plus, urlsplit

AUTH_MARKERS = ("/login", "/signin", "/auth", "/session", "/token")
FAILED_STATUSES = (401, 403, 429)

SQLI_PATTERNS = [re.compile(p, re.I) for p in (
    r"union\s+(all\s+)?select", r"\bor\b\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+", r"\band\b\s+\d+\s*=\s*\d+",
    r"'\s*or\s*'", r"\"\s*or\s*\"", r";\s*(drop|delete|insert|update|truncate|exec)\b", r"--(\s|$|\+)", r"/\*.*?\*/",
    r"information_schema", r"xp_cmdshell", r"\bsleep\s*\(\s*\d", r"\bbenchmark\s*\(", r"waitfor\s+delay",
    r"load_file\s*\(", r"into\s+(out|dump)file", r"select\s+.+?\s+from\s+\w", r"'\s*;\s*$", r"0x[0-9a-f]{6,}",
)]
SPECIAL = set("'\";-=()/*#%")

FEATURE_NAMES = [
    "ip_req_60", "ip_auth_fail_300", "ip_distinct_accounts_300", "acct_fail_300", "acct_distinct_ips_300",
    "srv_req_60", "srv_unique_ips_60", "srv_path_share_60", "srv_ua_share_60", "ip_share_60",
    "sqli_hits", "special_ratio", "query_len", "is_auth_path", "is_failed_auth", "is_auth_success",
    "is_4xx", "is_5xx",
]


def split_path(raw_path: str | None, metadata: dict | None = None) -> tuple[str, str]:
    """Return (lower-cased path without query, decoded query text)."""
    parts = urlsplit(raw_path or "")
    query = parts.query
    extra = (metadata or {}).get("query") or (metadata or {}).get("query_string") or ""
    text = unquote_plus(unquote_plus(f"{query} {extra}".strip()))
    return (parts.path or "/").lower(), text


def sqli_stats(path: str, query: str) -> tuple[int, float, int, list[str]]:
    text = f"{unquote_plus(unquote_plus(path))} {query}".lower()
    hits = [p.pattern for p in SQLI_PATTERNS if p.search(text)]
    qlen = len(query)
    ratio = sum(1 for c in query if c in SPECIAL) / qlen if qlen else 0.0
    return len(hits), ratio, qlen, hits


class FeatureExtractor:
    """Per-server sliding windows: 60 s for volume/diversity, 300 s for authentication failures."""

    def __init__(self):
        self.w60: deque = deque()
        self.c_ip, self.c_path, self.c_ua = Counter(), Counter(), Counter()
        self.w300: deque = deque()
        self.f_ip, self.f_acct = Counter(), Counter()
        self.ip_accts: dict[str, Counter] = defaultdict(Counter)
        self.acct_ips: dict[str, Counter] = defaultdict(Counter)

    @staticmethod
    def _dec(counter: Counter, key):
        counter[key] -= 1
        if counter[key] <= 0:
            del counter[key]

    def _evict(self, now: float):
        while self.w60 and self.w60[0][0] < now - 60:
            _, ip, path, ua = self.w60.popleft()
            self._dec(self.c_ip, ip); self._dec(self.c_path, path); self._dec(self.c_ua, ua)
        while self.w300 and self.w300[0][0] < now - 300:
            _, ip, acct = self.w300.popleft()
            self._dec(self.f_ip, ip)
            self._dec(self.ip_accts[ip], acct or "")
            if not self.ip_accts[ip]: del self.ip_accts[ip]
            if acct:
                self._dec(self.f_acct, acct)
                self._dec(self.acct_ips[acct], ip)
                if not self.acct_ips[acct]: del self.acct_ips[acct]

    def update(self, ev: dict) -> dict:
        """ev keys: t (epoch seconds), ip, account, path, query, ua, status. Returns the feature dict."""
        t, ip, acct = ev["t"], ev.get("ip") or "unknown", ev.get("account")
        path, ua, status = ev.get("path") or "/", ev.get("ua") or "", ev.get("status") or 0
        self._evict(t)
        self.w60.append((t, ip, path, ua)); self.c_ip[ip] += 1; self.c_path[path] += 1; self.c_ua[ua] += 1
        is_auth = any(m in path for m in AUTH_MARKERS)
        failed_auth = is_auth and status in FAILED_STATUSES
        if failed_auth:
            self.w300.append((t, ip, acct)); self.f_ip[ip] += 1
            self.ip_accts[ip][acct or ""] += 1
            if acct:
                self.f_acct[acct] += 1; self.acct_ips[acct][ip] += 1
        total = len(self.w60)
        hits, ratio, qlen, hit_patterns = sqli_stats(path, ev.get("query") or "")
        return {
            "ip_req_60": self.c_ip[ip], "ip_auth_fail_300": self.f_ip.get(ip, 0),
            "ip_distinct_accounts_300": len(self.ip_accts.get(ip, {})),
            "acct_fail_300": self.f_acct.get(acct, 0) if acct else 0,
            "acct_distinct_ips_300": len(self.acct_ips.get(acct, {})) if acct else 0,
            "srv_req_60": total, "srv_unique_ips_60": len(self.c_ip),
            "srv_path_share_60": self.c_path[path] / total, "srv_ua_share_60": self.c_ua[ua] / total,
            "ip_share_60": self.c_ip[ip] / total,
            "sqli_hits": hits, "special_ratio": round(ratio, 4), "query_len": qlen,
            "is_auth_path": int(is_auth), "is_failed_auth": int(failed_auth),
            "is_auth_success": int(is_auth and 200 <= status < 400),
            "is_4xx": int(400 <= status < 500), "is_5xx": int(status >= 500),
            "_sqli_patterns": hit_patterns,
        }

    def recent_failures(self, ip: str, account: str | None) -> tuple[int, int, int]:
        """(failed attempts from ip, distinct accounts tried by ip, distinct ips failing this account)."""
        return (self.f_ip.get(ip, 0), len(self.ip_accts.get(ip, {})),
                len(self.acct_ips.get(account, {})) if account else 0)


def vector(features: dict) -> list[float]:
    return [float(features[name]) for name in FEATURE_NAMES]
