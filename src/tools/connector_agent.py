"""Connector agent: tail an nginx/Apache 'combined' access log and forward METADATA-ONLY events to CyberQuant.

    python -m src.tools.connector_agent --url http://127.0.0.1:8000 --server-id 2 --token <TOKEN> --log /var/log/nginx/access.log --follow

Sent per request: time, method, path+query, status, source IP, user-agent, and (optionally) a salted hash of the account name.
Never sent: request bodies, cookies, Authorization headers, passwords. Standard library only, so it runs on any server with Python 3.
"""
from __future__ import annotations
import argparse, hashlib, json, re, sys, time, urllib.request
from datetime import datetime, timezone

LINE = re.compile(r'(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" (?P<status>\d{3}) \S+(?: "[^"]*" "(?P<ua>[^"]*)")?')


def parse_line(line: str, account_regex: str | None = None, salt: str = "") -> dict | None:
    m = LINE.match(line)
    if not m: return None
    try: when = datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
    except ValueError: return None
    account = None
    if m["user"] not in ("-", ""): account = m["user"]
    elif account_regex:
        found = re.search(account_regex, m["path"])
        account = found.group(1) if found else None
    meta = {"user_agent": m["ua"] or ""}
    if account: meta["account"] = hashlib.sha256((salt + account).encode()).hexdigest()[:16]    # pseudonymised before leaving the server
    return {"event_at": when.isoformat(), "request_method": m["method"], "request_path": m["path"][:500], "response_status": int(m["status"]),
            "source_ip": m["ip"], "metadata": meta}


def post(url: str, server_id: int, token: str, events: list[dict]) -> dict:
    req = urllib.request.Request(f"{url.rstrip('/')}/api/v1/telemetry/{server_id}", data=json.dumps({"events": events}).encode(),
                                 headers={"Content-Type": "application/json", "X-Agent-Token": token}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r: return json.load(r)


def blocklist(url: str, server_id: int, token: str) -> list[dict]:
    req = urllib.request.Request(f"{url.rstrip('/')}/api/v1/telemetry/{server_id}/blocklist", headers={"X-Agent-Token": token})
    with urllib.request.urlopen(req, timeout=30) as r: return json.load(r)["blocklist"]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", required=True); ap.add_argument("--server-id", type=int, required=True); ap.add_argument("--token", required=True)
    ap.add_argument("--log", required=True); ap.add_argument("--follow", action="store_true", help="keep tailing the log")
    ap.add_argument("--account-regex", help=r"regex with one group that extracts the login name from the request path, e.g. 'user=([^&]+)'")
    ap.add_argument("--salt", default="", help="secret salt for hashing account names"); ap.add_argument("--batch", type=int, default=500)
    a = ap.parse_args(argv)
    batch, sent, skipped = [], 0, 0
    def flush():
        nonlocal batch, sent
        if batch:
            r = post(a.url, a.server_id, a.token, batch); sent += len(batch); batch = []
            if r.get("alerts_raised"): print(f"  {r['alerts_raised']} new alert(s) raised", file=sys.stderr)
    with open(a.log, encoding="utf-8", errors="replace") as fh:
        while True:
            line = fh.readline()
            if not line:
                flush()
                if not a.follow: break
                time.sleep(1); continue
            ev = parse_line(line, a.account_regex, a.salt)
            if ev: batch.append(ev)
            else: skipped += 1
            if len(batch) >= a.batch: flush()
    print(f"sent {sent} event(s); skipped {skipped} unparseable line(s)", file=sys.stderr)


if __name__ == "__main__":
    main()
