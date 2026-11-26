"""Turns one raw request record into the clean event the engine reads (time, IP, endpoint, status, user)."""
from __future__ import annotations
from datetime import datetime, timezone
from .features import split_path


def to_epoch(value) -> float:
    if isinstance(value, datetime):
        return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).timestamp()
    if isinstance(value, (int, float)):
        return float(value)
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()


def prepare(event: dict) -> dict:
    """Normalise a telemetry event (API model dump, DB row or simulator row) for the extractor."""
    meta = event.get("metadata") or {}
    path, query = split_path(event.get("request_path"), meta)
    return {"t": to_epoch(event.get("event_at")), "ip": event.get("source_ip"),
            "account": meta.get("account") or meta.get("account_hash"), "path": path, "query": query,
            "ua": meta.get("user_agent") or "", "status": event.get("response_status") or 0,
            "method": event.get("request_request_method") or event.get("request_method") or "GET"}
