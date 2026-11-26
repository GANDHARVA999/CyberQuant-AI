"""Explainable rule layer. Each hit carries its evidence; thresholds are configurable."""
from __future__ import annotations

DEFAULTS = {
    "brute_ip_failures": 5,          # failed logins from one IP in 5 minutes
    "brute_account_failures": 10,    # failed logins against one account in 5 minutes ...
    "brute_account_ips": 5,          # ... from at least this many distinct IPs (distributed attack)
    "stuffing_accounts": 5,          # one IP failing against this many different accounts
    "ddos_requests_1m": 150, "ddos_unique_ips": 15, "ddos_path_share": 0.5, "ddos_ua_share": 0.6,
}


def evaluate(f: dict, cfg: dict | None = None) -> list[dict]:
    """Return rule hits: {type, rule, confidence, key_kind, basis[]}."""
    c = {**DEFAULTS, **(cfg or {})}
    hits = []
    if f["sqli_hits"] >= 1:
        hits.append({"type": "SQL injection", "rule": "sqli-signature", "key_kind": "ip",
                     "confidence": 0.92 if f["sqli_hits"] > 1 else 0.82,
                     "basis": [f"{f['sqli_hits']} SQL-injection signature(s) matched in the request target/query",
                               f"Special-character ratio in query: {f['special_ratio']:.2f}"]})
    if f["is_failed_auth"]:
        if f["ip_distinct_accounts_300"] >= c["stuffing_accounts"] and f["ip_auth_fail_300"] >= c["brute_ip_failures"]:
            hits.append({"type": "Brute force", "rule": "credential-stuffing", "key_kind": "ip",
                         "confidence": min(0.98, 0.78 + f["ip_distinct_accounts_300"] / 60),
                         "basis": [f"One source IP failed against {f['ip_distinct_accounts_300']} different accounts in 5 minutes",
                                   f"{f['ip_auth_fail_300']} failed authentication responses from this IP"]})
        elif f["acct_fail_300"] >= c["brute_account_failures"] and f["acct_distinct_ips_300"] >= c["brute_account_ips"]:
            hits.append({"type": "Brute force", "rule": "distributed-account-attack", "key_kind": "account",
                         "confidence": min(0.98, 0.80 + f["acct_distinct_ips_300"] / 200),
                         "basis": [f"{f['acct_fail_300']} failed logins against one account from {f['acct_distinct_ips_300']} different IPs in 5 minutes",
                                   "Many IPs targeting a single account indicates a distributed brute-force attack"]})
        elif f["ip_auth_fail_300"] >= c["brute_ip_failures"]:
            n = f["ip_auth_fail_300"]
            hits.append({"type": "Brute force", "rule": "single-ip-repeated-failure", "key_kind": "ip",
                         "confidence": min(0.97, 0.62 + n / 40),
                         "basis": [f"{n} failed authentication responses from one source IP in 5 minutes (threshold {c['brute_ip_failures']})"]})
    if (f["srv_req_60"] >= c["ddos_requests_1m"] and f["srv_unique_ips_60"] >= c["ddos_unique_ips"]
            and (f["srv_path_share_60"] >= c["ddos_path_share"] or f["srv_ua_share_60"] >= c["ddos_ua_share"])):
        hits.append({"type": "DDoS", "rule": "distributed-concentrated-flood", "key_kind": "server",
                     "confidence": min(0.96, 0.66 + f["srv_req_60"] / 2000),
                     "basis": [f"{f['srv_req_60']} requests in the last minute from {f['srv_unique_ips_60']} unique IPs",
                               f"{f['srv_path_share_60']:.0%} of traffic hits this path and {f['srv_ua_share_60']:.0%} share one user-agent "
                               "(a genuine traffic surge is usually diverse)"]})
    return hits
