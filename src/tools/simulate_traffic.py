"""Send SIMULATED traffic (genuine users + brute force / SQLi / DDoS) to a running CyberQuant server, for live demos.

    python -m src.tools.simulate_traffic --url http://127.0.0.1:8000 --server-id 2 --token <TOKEN> --minutes 20
"""
import argparse
from datetime import datetime, timedelta, timezone
from .connector_agent import post
from ..engine.simulator import Simulator


def main(argv=None):
    ap = argparse.ArgumentParser(); ap.add_argument("--url", required=True); ap.add_argument("--server-id", type=int, required=True)
    ap.add_argument("--token", required=True); ap.add_argument("--minutes", type=int, default=20); ap.add_argument("--seed", type=int, default=5)
    a = ap.parse_args(argv)
    start = datetime.now(timezone.utc) - timedelta(minutes=a.minutes + 1)
    sim = Simulator(a.seed, start=start)
    sim.forgetful_login(60, fails=6, succeed=True)
    events = sim.session(a.minutes, attacks={"brute_single": 1, "brute_distributed": 1, "sqli": 1, "ddos": 1}, rate=12)
    out = [{"event_at": e["event_at"].isoformat(), "request_method": e["request_method"], "request_path": e["request_path"],
            "response_status": e["response_status"], "source_ip": e["source_ip"], "metadata": e["metadata"]} for e in events]
    alerts = 0
    for i in range(0, len(out), 500): alerts += post(a.url, a.server_id, a.token, out[i:i + 500]).get("alerts_raised", 0)
    print(f"sent {len(out)} simulated events; {alerts} alert(s) raised. Open /threat-center to review.")


if __name__ == "__main__":
    main()
