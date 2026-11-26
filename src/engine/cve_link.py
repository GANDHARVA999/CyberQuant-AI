"""Link detected attack types to the NVD vulnerabilities that make them succeed.

SQLi -> CWE-89, brute force -> CWE-307/521/798 (improper authentication limits, weak/hard-coded credentials),
DDoS -> CWE-400/770 (uncontrolled resource consumption). The local NVD table has descriptions and CVSS but not CWE ids,
so matching is on description keywords: a heuristic, reported as such, never a claim that a CVE affects the server.
"""
from __future__ import annotations

ATTACK_CWE = {"SQL injection": ["CWE-89"], "Brute force": ["CWE-307", "CWE-521", "CWE-798"], "DDoS": ["CWE-400", "CWE-770"]}
ATTACK_KEYWORDS = {
    "SQL injection": ["sql injection", "sqli", "sql command"],
    "Brute force": ["brute force", "brute-force", "weak password", "default credential", "hard-coded password", "hardcoded password",
                    "improper restriction of excessive authentication attempts", "authentication bypass", "missing authentication"],
    "DDoS": ["denial of service", "denial-of-service", "resource exhaustion", "uncontrolled resource consumption", "dos "],
}


def attack_for_description(description: str | None) -> list[str]:
    d = (description or "").lower() + " "
    return [a for a, words in ATTACK_KEYWORDS.items() if any(w in d for w in words)]


def keyword_sql(attack: str) -> tuple[str, list[str]]:
    words = ATTACK_KEYWORDS[attack]
    return " OR ".join("LOWER(description) LIKE ?" for _ in words), [f"%{w}%" for w in words]


def exposure_multiplier(attack: str, open_vulns: list[dict]) -> tuple[float, list[dict]]:
    """1.0 with no linked vulnerabilities; up to 1.5 when a CVSS-10 matching CVE is open on the server's asset."""
    matching = [v for v in open_vulns if attack in attack_for_description(v.get("description"))]
    if not matching: return 1.0, []
    top = max(float(v.get("cvss_score") or 0) for v in matching)
    return round(1.0 + 0.5 * top / 10, 3), [{"cve_id": v["cve_id"], "cvss_score": v.get("cvss_score")}
                                              for v in sorted(matching, key=lambda v: -(v.get("cvss_score") or 0))[:5]]
