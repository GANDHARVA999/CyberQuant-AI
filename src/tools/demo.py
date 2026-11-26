"""End-to-end demonstration on SIMULATED traffic. Run:  python -m src.tools.demo   (writes output/demo_report.html)

1. a server sends traffic (genuine users, forgetful users, an office behind one IP, brute force, SQLi, DDoS)
2. every request is classified genuine / Brute force / SQL injection / DDoS and grouped into incidents
3. an analyst reviews incidents; the system learns the pattern (same IP, same endpoint, same volume = genuine)
4. the attack history drives a budget plan: which controls to buy to cut the most expected loss per rupee
"""
from __future__ import annotations
import html, json, sys, tempfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from .. import database, incident_store as st
from ..engine.detector import DetectionEngine
from ..engine.model import Classifier
from ..engine.simulator import Simulator
from ..settings import ROOT

CHECK = "✓"


def run(out_path: Path | None = None, quiet: bool = False) -> dict:
    say = (lambda *a: None) if quiet else print
    tmp = Path(tempfile.mkdtemp()) / "demo.db"; database.DB_PATH = tmp; database.initialize()
    clf = Classifier()
    report: dict = {}
    with database.connection() as con:
        con.execute("INSERT INTO monitored_servers(display_name,hostname,sector,created_at,agent_token_hash) VALUES('Demo shop','shop.example','E-commerce',?,'x')", (st.now_iso(),))
        engine = DetectionEngine(1, clf)
        start = datetime(2026, 3, 2, 9, 0, tzinfo=timezone.utc)
        sim = Simulator(21, start=start)
        genuine_ip, genuine_user = sim.forgetful_login(300, fails=5, succeed=False, ip="198.51.100.23", user="priya")     # the 'genuine but flagged' case
        sim.forgetful_login(900, fails=6, succeed=True)
        events = sim.session(30, attacks={"brute_single": 1, "brute_distributed": 1, "credential_stuffing": 1, "sqli": 1, "ddos": 1}, rate=18)

        say("\n=== 1. TRAFFIC IN: classify every request ===")
        truth, pred = [], []
        for ev in events:
            res = engine.process(ev); st.record_event(con, 1, ev, res)
            truth.append(ev["label"]); pred.append(res["threat_type"] or "Normal")
        tp = sum(1 for t, p in zip(truth, pred) if t != "Normal" and p == t)
        attacks = sum(1 for t in truth if t != "Normal"); fp = sum(1 for t, p in zip(truth, pred) if t == "Normal" and p != "Normal")
        summary = st.traffic_summary(con, 1)
        say(f"requests: {summary['total']}  genuine: {summary['genuine']}  flagged: {summary['flagged']}  {summary['by_type']}")
        say(f"vs ground truth -> attack requests caught: {tp}/{attacks} ({tp / attacks:.1%}); genuine requests wrongly flagged: {fp}/{truth.count('Normal')} ({fp / truth.count('Normal'):.2%})")
        incs = [dict(r) for r in con.execute("SELECT * FROM incidents ORDER BY first_at")]
        say(f"incidents: {len(incs)}")
        for r in incs:
            i = st.public_incident(r)
            say(f"  #{i['id']:<2} {i['threat_type']:<14} {i['severity']:<8} conf {i['confidence']:.2f}  {i['event_count']:>4} req  {i['source_count']:>3} IP(s)  [{i['suggestion']['label']}]")
        report.update(summary=summary, events=len(events), caught=tp, attacks=attacks, false_positives=fp, genuine_total=truth.count("Normal"),
                      incidents=[st.public_incident(r) for r in incs])

        say("\n=== 2. REVIEW & LEARN ===")
        forgot = next(r for r in incs if r["threat_type"] == "Brute force" and "198.51.100.23" in json.loads(r["source_ips_json"]))
        fi = st.public_incident(forgot)
        say(f"flagged: {fi['threat_type']} from 198.51.100.23, {fi['volume']} failed logins on /login -> suggestion: {fi['suggestion']['label']}")
        st.review_incident(con, engine, 1, fi["id"], None, "genuine", "allow_similar", "Priya forgot her password")
        say(f"analyst: GENUINE, treat similar as genuine  {CHECK} pattern saved")
        dist = next(r for r in incs if r["threat_type"] == "Brute force" and r["key_kind"] == "account")
        st.review_incident(con, engine, 1, dist["id"], None, "attack", "block_source", "distributed attack on one account")
        say(f"analyst: ATTACK on incident #{dist['id']} (many IPs, one account) {CHECK} source added to blocklist")
        next_day = start + timedelta(days=1)
        sim2 = Simulator(99, start=next_day)
        sim2.forgetful_login(60, fails=5, succeed=True, ip="198.51.100.23", user="priya")
        res = [engine.process(e) for e in sorted(sim2.events, key=lambda e: e["event_at"])]
        same = not any(r["alert"] for r in res) and any(r["state"] == "auto_allowed" for r in res)
        say(f"next day, same IP fails 5 times again -> alert raised? {'NO (auto-allowed, learned)' if same else 'yes'}")
        sim3 = Simulator(100, start=next_day + timedelta(hours=1))
        for k in range(40):
            sim3._add(k * 2.0, "POST", "/login", 401, "198.51.100.23", "python-requests/2.31", "Brute force", "priya")
        esc = [engine.process(e) for e in sim3.events]
        say(f"same IP now fails 40 times in ~80 s -> alert raised? {'YES (exceeds the volume you approved)' if any(r['alert'] for r in esc) else 'no'}")
        other = Simulator(101, start=next_day + timedelta(hours=2)); other.forgetful_login(30, fails=5, succeed=False, ip="203.0.113.77", user="raj")
        oth = [engine.process(e) for e in sorted(other.events, key=lambda e: e["event_at"])]
        say(f"a different IP fails 5 times -> alert raised? {'yes (the learned pattern is specific to the reviewed source)' if any(r['alert'] for r in oth) else 'no'}")
        report["learning"] = {"auto_allowed_same_pattern": same, "escalated_at_40": any(r["alert"] for r in esc), "different_ip_alerts": any(r["alert"] for r in oth)}
        report["blocklist"] = engine.memory.blocklist()

        say("\n=== 3. BUDGET: where should the security fund go? ===")
        plans = {}
        for budget in (100_000, 300_000, 600_000):
            p = st.budget_plan(con, 1, budget, period_days=30, target_reduction=0.7); plans[budget] = p
            say(f"budget Rs {budget:>9,}: spend Rs {p['allocated_inr']:>9,.0f}  avoids Rs {p['loss_avoided_inr']:>12,.0f}/yr ({p['reduction_pct']:.0%})  -> " + ", ".join(c["name"].split(" (")[0] for c in p["selected"]))
        say(f"cheapest plan to cut loss by 70%: Rs {plans[300_000]['min_cost_for_target']['cost_inr']:,.0f}" if plans[300_000]["min_cost_for_target"] else "70% not reachable")
        report["plans"] = {str(k): v for k, v in plans.items()}
    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True); out_path.write_text(render_html(report), encoding="utf-8")
        say(f"\nreport written: {out_path}")
    return report


def inr(v): return "₹" + format(round(v), ",")


def render_html(r: dict) -> str:
    E = html.escape; s = r["summary"]
    bars = "".join(f'<div class="b"><span>{E(k)}</span><div><i style="width:{v / max(s["flagged"], 1) * 100:.0f}%"></i></div><b>{v}</b></div>' for k, v in s["by_type"].items())
    inc_rows = "".join(f'<tr><td>#{i["id"]}</td><td>{E(i["threat_type"])}</td><td>{E(i["severity"])}</td><td>{i["confidence"]:.2f}</td><td>{i["event_count"]}</td><td>{i["source_count"]}</td><td>{E(i["suggestion"]["label"].replace("_", " "))}</td><td>{E(i["status"].replace("_", " "))}</td></tr>' for i in r["incidents"])
    plan_blocks = ""
    for budget, p in r["plans"].items():
        rows = "".join(f'<tr><td>{E(c["name"])}</td><td>{inr(c["cost_inr"])}</td><td>{E(", ".join(f"{k} {int(v * 100)}%" for k, v in c["effect"].items()))}</td></tr>' for c in p["selected"])
        att = "".join(f'<tr><td>{E(a["attack"])}</td><td>{inr(a["baseline_loss_inr"])}</td><td>{inr(a["residual_loss_inr"])}</td><td>{a["reduction_pct"]:.0%}</td></tr>' for a in p["per_attack"])
        plan_blocks += f'<div class="card"><h3>Budget {inr(float(budget))}: avoids {inr(p["loss_avoided_inr"])}/yr ({p["reduction_pct"]:.0%})</h3><p class="m">Spend {inr(p["allocated_inr"])}; {inr(p["unallocated_inr"])} unspent; {p["return_per_rupee"]:.0f}× return per ₹1 (illustrative assumptions)</p><table><tr><th>Control</th><th>Cost</th><th>Covers</th></tr>{rows}</table><table><tr><th>Attack</th><th>Loss before</th><th>After</th><th>Cut</th></tr>{att}</table></div>'
    L = r["learning"]; tick = lambda b: "✓" if b else "✗"
    return f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CyberQuant AI demo report</title>
<style>body{{max-width:980px;margin:36px auto;padding:0 20px;font:15px/1.5 system-ui;background:#111516;color:#e8eeee}}.card{{padding:16px 20px;margin:16px 0;border:1px solid #ffffff18;border-radius:8px;background:#1a2021}}
table{{width:100%;border-collapse:collapse;margin:8px 0}}td,th{{padding:6px;border-top:1px solid #ffffff14;text-align:left}}th{{color:#aab5b5;font-weight:500}}.m{{color:#aab5b5;font-size:13px}}
.b{{display:grid;grid-template-columns:130px 1fr 60px;gap:10px;align-items:center;margin:6px 0}}.b div{{background:#ffffff14;height:10px;border-radius:5px}}.b i{{display:block;height:100%;background:#db7d83;border-radius:5px}}
.k{{display:inline-block;margin:4px 18px 4px 0}}.k b{{font-size:24px;display:block}}.note{{border-left:3px solid #d7b978;background:#44391d55;padding:10px 14px;color:#eadcb9}}</style>
<h1>CyberQuant AI: end-to-end demo</h1><p class="note">All traffic here is <b>simulated</b> (src/engine/simulator.py). Detection numbers measure how well the system finds simulated attacks; they are not a real-world detection rate. Money figures use illustrative assumptions.</p>
<div class="card"><h2>1. Traffic classified</h2><span class="k"><b>{s["total"]:,}</b>requests</span><span class="k"><b>{s["genuine"]:,}</b>genuine</span><span class="k"><b>{s["flagged"]:,}</b>flagged attack traffic</span>
<span class="k"><b>{r["caught"]}/{r["attacks"]}</b>attack requests caught</span><span class="k"><b>{r["false_positives"]}/{r["genuine_total"]}</b>genuine wrongly flagged</span>{bars}
<h3>Incidents (one attack = one incident)</h3><table><tr><th>ID</th><th>Type</th><th>Severity</th><th>Conf.</th><th>Requests</th><th>IPs</th><th>Suggestion</th><th>Status</th></tr>{inc_rows}</table></div>
<div class="card"><h2>2. Review &amp; learning</h2><p class="m">An analyst marked a 5-failed-login incident from one IP as genuine ("treat similar as genuine") and a many-IPs-one-account incident as an attack with source blocking.</p>
<table><tr><td>Next day, same IP fails 5 times again: no alert (learned)</td><td>{tick(L["auto_allowed_same_pattern"])}</td></tr><tr><td>Same IP fails 40 times: alert raised again (exceeds reviewed volume)</td><td>{tick(L["escalated_at_40"])}</td></tr><tr><td>Different IP fails 5 times: still alerts (pattern is source-specific)</td><td>{tick(L["different_ip_alerts"])}</td></tr></table></div>
<div class="card"><h2>3. Budget optimisation</h2><p class="m">Chosen by exact search over all control combinations; controls on the same attack combine multiplicatively.</p></div>{plan_blocks}</html>"""


if __name__ == "__main__":
    run(ROOT / "output" / "demo_report.html")
