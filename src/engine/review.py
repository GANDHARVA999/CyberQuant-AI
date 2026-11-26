"""Analyst-review memory: what a reviewer taught the system about *this server's* traffic patterns.

A pattern says: for this attack type, on this endpoint, from this IP (or account / the server as a whole),
the analyst judged the activity genuine (or an attack), reviewed at a given volume. Future matches are
auto-allowed (only while the volume stays within a tolerance of what was reviewed), prioritised, or
recommended for blocking. Nothing here touches a firewall; it only changes triage and the recommended blocklist.
"""
from __future__ import annotations

VALID = {"genuine": {"one_time", "allow_similar"}, "attack": {"one_time", "prioritize_similar", "block_source"}}


def allow_limit(volume: int) -> int:
    """Largest volume still treated as 'like the reviewed genuine case'. 5 reviewed attempts -> up to 10."""
    return max(2 * int(volume), int(volume) + 5)


class ReviewMemory:
    def __init__(self, patterns: list[dict] | None = None):
        self.patterns: list[dict] = list(patterns or [])

    def add(self, pattern: dict):
        self.patterns.append(pattern)

    def match(self, threat_type: str, key_kind: str, ip: str | None, account: str | None, path: str | None) -> dict | None:
        """Most recent applicable pattern (later reviews override earlier ones)."""
        for p in reversed(self.patterns):
            if p["threat_type"] != threat_type or p["handling"] == "one_time":
                continue
            if p["key_kind"] == "server" and key_kind == "server":
                return p
            if p["key_kind"] == "account" and key_kind == "account" and account and p.get("account") == account and p.get("path") == path:
                return p
            if p["key_kind"] == "ip" and key_kind == "ip" and ip and p.get("source_ip") == ip and p.get("path") == path:
                return p
        return None

    def blocklist(self) -> list[dict]:
        seen, out = set(), []
        for p in reversed(self.patterns):
            if p["handling"] == "block_source" and p.get("source_ip") and p["source_ip"] not in seen:
                seen.add(p["source_ip"]); out.append({"source_ip": p["source_ip"], "threat_type": p["threat_type"]})
        return out


def effect_of(pattern: dict | None) -> str | None:
    if not pattern: return None
    if pattern["decision"] == "genuine" and pattern["handling"] == "allow_similar": return "allow"
    if pattern["decision"] == "attack" and pattern["handling"] == "prioritize_similar": return "prioritize"
    if pattern["decision"] == "attack" and pattern["handling"] == "block_source": return "block"
    return None
