"""Explainable, conservative classifiers for the three in-scope web threats.

These rules identify *suspected* activity from metadata only.  A match is an
alert for investigation, not proof that a compromise or outage occurred.
"""
from __future__ import annotations

from urllib.parse import unquote_plus

SQLI_MARKERS = (
    "union select", "union%20select", "' or '", "\" or \"", "or 1=1",
    "--", ";--", "/*", "*/", "information_schema", "xp_cmdshell",
    " sleep(", "benchmark(", "waitfor delay",
)
LOGIN_PATH_MARKERS = ("/login", "/signin", "/auth", "/session")


def _text(event: dict) -> str:
    """Only use request metadata; request bodies and credentials are excluded."""
    metadata = event.get("metadata") or {}
    values = [event.get("request_path") or ""]
    for key in ("query", "query_string", "parameter_names", "user_agent"):
        value = metadata.get(key)
        if value is not None:
            values.append(str(value))
    return unquote_plus(" ".join(values)).lower()


def classify_event(event: dict, *, failed_logins_5m: int = 0,
                   requests_1m: int = 0, unique_sources_1m: int = 0) -> dict:
    """Return a classification, severity, confidence, and human-readable basis."""
    text = _text(event)
    path = (event.get("request_path") or "").lower()

    matched = [marker for marker in SQLI_MARKERS if marker in text]
    if matched:
        return {
            "threat_type": "SQL injection",
            "severity": "critical" if event.get("response_status", 0) >= 500 else "high",
            "confidence": 0.92 if len(matched) > 1 else 0.82,
            "alert": True,
            "basis": ["SQL-injection signature matched: " + ", ".join(repr(x) for x in matched[:2]),
                      "Request target or approved query metadata contained SQL syntax; no request body was stored."],
        }

    login_target = any(marker in path for marker in LOGIN_PATH_MARKERS)
    failed = event.get("response_status") in (401, 403, 429)
    if login_target and failed and failed_logins_5m >= 5:
        source = event.get("source_ip") or "unknown source IP"
        return {
            "threat_type": "Brute force",
            "severity": "high" if failed_logins_5m < 15 else "critical",
            "confidence": min(0.98, 0.70 + failed_logins_5m / 100),
            "alert": True,
            "basis": [f"Source IP: {source}",
                      f"{failed_logins_5m} failed authentication responses from this source IP in the preceding 5 minutes (alert threshold: 5)",
                      f"Authentication endpoint observed: {event.get('request_path') or 'unknown'}"],
        }

    # DDoS requires both volume and distribution; a single busy client is not enough.
    if requests_1m >= 100 and unique_sources_1m >= 10:
        return {
            "threat_type": "DDoS",
            "severity": "critical" if requests_1m >= 500 else "high",
            "confidence": min(0.95, 0.65 + requests_1m / 2000),
            "alert": True,
            "basis": [f"{requests_1m} requests observed for this server in the preceding 1 minute (alert threshold: 100)",
                      f"Traffic came from {unique_sources_1m} unique source IPs (alert threshold: 10)"],
        }

    return {"threat_type": None, "severity": None, "confidence": None, "alert": False,
            "basis": ["No SQL-injection signature, repeated failed-login pattern, or distributed traffic-volume threshold matched."]}
