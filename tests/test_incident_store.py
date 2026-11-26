import json
import pytest
from datetime import datetime, timedelta, timezone
from src import database, incident_store as st
from src.engine.detector import DetectionEngine
from tests.test_engine import ev, run, alerts


@pytest.fixture()
def con(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "t.db")
    database.initialize()
    with database.connection() as c:
        c.execute("INSERT INTO monitored_servers(display_name,hostname,sector,created_at,agent_token_hash) VALUES('s','h','retail','2026-01-01','x')")
        yield c


def feed(con, engine, events):
    return [st.record_event(con, 1, e, engine.process(e)) for e in events]


def test_events_incidents_and_traffic_summary_persist(con):
    eng = DetectionEngine(1)
    feed(con, eng, [ev(i, f"1.1.1.{i}", "/", 200, None, method="GET") for i in range(1, 30)])           # genuine browsing
    feed(con, eng, [ev(100 + i * 10, "5.5.5.5") for i in range(7)])                                       # repeated failures
    s = st.traffic_summary(con, 1)
    assert s["total"] == 36 and s["flagged"] >= 3 and s["genuine"] + s["flagged"] == 36
    inc = con.execute("SELECT * FROM incidents").fetchall()
    assert len(inc) == 1 and inc[0]["status"] == "open" and inc[0]["event_count"] >= 3
    linked = con.execute("SELECT COUNT(*) n FROM server_events WHERE incident_id=?", (inc[0]["id"],)).fetchone()["n"]
    assert linked == inc[0]["event_count"]


def test_review_flow_learns_and_survives_engine_restart(con):
    eng = DetectionEngine(1)
    feed(con, eng, [ev(i * 20, "5.5.5.5") for i in range(5)])
    iid = con.execute("SELECT id FROM incidents").fetchone()["id"]
    with pytest.raises(ValueError): st.review_incident(con, eng, 1, iid, None, "genuine", "block_source")     # invalid combination
    pattern = st.review_incident(con, eng, 1, iid, None, "genuine", "allow_similar", "forgot password")
    assert pattern["decision"] == "genuine" and con.execute("SELECT status FROM incidents WHERE id=?", (iid,)).fetchone()["status"] == "reviewed_genuine"
    sample = con.execute("SELECT label FROM review_samples").fetchone(); assert sample["label"] == "Normal"
    # a brand-new engine (as after an app restart) rebuilds its memory from the database
    fresh = st.build_engine(con, 1, None)
    res = run(fresh, [ev(86400 + i * 20, "5.5.5.5") for i in range(5)])
    assert not alerts(res) and res[-1]["state"] == "auto_allowed"
    feed(con, fresh, [ev(90000 + i * 20, "5.5.5.5") for i in range(1)])
    # reviewed-genuine and auto-allowed incidents do not count as risk
    assert st.incident_counts(con, 1) == {}


def test_budget_plan_uses_confirmed_and_open_incidents_only(con):
    eng = DetectionEngine(1)
    feed(con, eng, [ev(i * 2, f"30.0.{i // 200}.{i % 200 + 1}", "/login", 401, "victim") for i in range(60)])   # distributed attack
    assert st.incident_counts(con, 1).get("Brute force") == 1
    plan = st.budget_plan(con, 1, 300_000, period_days=30)
    assert plan["allocated_inr"] <= 300_000 and plan["loss_avoided_inr"] > 0
    assert {c["id"] for c in plan["selected"]} & {"C-MFA", "C-RATE", "C-BOT"}
    bigger = st.budget_plan(con, 1, 900_000, period_days=30)
    assert bigger["loss_avoided_inr"] >= plan["loss_avoided_inr"]


def test_retrain_from_reviews_adds_labelled_examples(con, monkeypatch, tmp_path):
    from src.engine import model
    monkeypatch.setattr(model, "MODEL_PATH", tmp_path / "m.joblib"); monkeypatch.setattr(model, "REPORT_PATH", tmp_path / "r.json")
    eng = DetectionEngine(1)
    feed(con, eng, [ev(i * 20, "5.5.5.5") for i in range(5)])
    st.review_incident(con, eng, 1, con.execute("SELECT id FROM incidents").fetchone()["id"], None, "genuine", "allow_similar")
    monkeypatch.setattr(model, "train", lambda **kw: {"reviewed_examples_used": len(kw["extra"][1]), "extra": kw["extra"]})
    out = st.retrain_from_reviews(con)
    assert out["reviewed_examples_used"] == 1 and out["extra"][1][0] == "Normal"


def test_connector_parses_combined_log_and_hashes_account():
    from src.tools.connector_agent import parse_line
    line = '203.0.113.9 - - [01/Mar/2026:09:00:05 +0000] "POST /login?user=alice HTTP/1.1" 401 512 "-" "Mozilla/5.0 (X11)"'
    e = parse_line(line, account_regex=r"user=([^&]+)", salt="s")
    assert e["source_ip"] == "203.0.113.9" and e["response_status"] == 401 and e["request_method"] == "POST"
    assert e["metadata"]["account"] != "alice" and len(e["metadata"]["account"]) == 16 and "password" not in json.dumps(e)
    assert parse_line("garbage") is None


def test_blocking_a_distributed_attack_blocklists_every_recorded_source(con):
    eng = DetectionEngine(1)
    feed(con, eng, [ev(i * 2, f"30.0.{i // 200}.{i % 200 + 1}", "/login", 401, "victim") for i in range(60)])
    iid = con.execute("SELECT id FROM incidents").fetchone()["id"]
    st.review_incident(con, eng, 1, iid, None, "attack", "block_source")
    blocked = st.load_memory(con, 1).blocklist()
    assert len(blocked) >= 5 and len({b["source_ip"] for b in blocked}) == len(blocked)


def test_charts_move_with_review_and_history(con):
    from src.demo_seed import seed_history
    eng = DetectionEngine(1)
    feed(con, eng, [ev(i, f"1.1.1.{i}", "/", 200, None, method="GET") for i in range(1, 30)])
    feed(con, eng, [ev(100 + i * 10, "5.5.5.5") for i in range(7)])
    c = st.charts(con, 1, tz_offset_min=-330)
    assert c["realtime"]["flagged"]["Brute force"] >= 3 and len(c["realtime"]["series"]) == 60
    assert c["realtime"]["confirmed"]["Brute force"] == 0
    iid = con.execute("SELECT id FROM incidents").fetchone()["id"]
    st.review_incident(con, eng, 1, iid, None, "attack", "one_time")
    c2 = st.charts(con, 1, -330)
    assert c2["realtime"]["confirmed"]["Brute force"] >= 3                      # confirmed attacks rise after the decision
    st.review_incident(con, eng, 1, iid, None, "genuine", "one_time")
    c3 = st.charts(con, 1, -330)
    assert c3["realtime"]["flagged"]["Brute force"] == 0                        # marked genuine: requests return to genuine
    seed_history(con, 1)
    c4 = st.charts(con, 1, -330)
    assert len(c4["monthly"]) == 12 and sum(m["total"] for m in c4["monthly"]) > 40
    d = c4["day"]
    assert len(d["hours"]) == 24 and d["date"] in d["available_days"]
    assert sum(sum(h[a] for a in ("Brute force", "SQL injection", "DDoS")) for h in d["hours"]) > 0 and d["incidents"]
    assert st.charts(con, 1, 0, day="not-a-date")["day"]["date"]


def test_budget_plan_carries_researched_guidance():
    from src.engine import knowledge as K
    from src.engine.budget import expected_losses, optimise
    l = expected_losses({"Brute force": 10, "SQL injection": 1, "DDoS": 1}, 7)
    r = optimise(l, budget=300000)
    ap = K.action_plan(r["selected"], {"Brute force": 10, "SQL injection": 1, "DDoS": 1})
    assert ap and ap[0]["tier"] == "urgent" and all(a["options"] and a["sources"] and a["steps"] for a in ap)
    assert all(c["id"] in K.BY_ID for c in r["selected"])
    steps = K.frontier_story(optimise(l, budget=1e9)["frontier"], r["baseline_loss_inr"])
    assert steps == sorted(steps, key=lambda s: s["cost_inr"]) and K.diminishing_point(steps)["cost_inr"] <= steps[-1]["cost_inr"]
    assert abs(K.gordon_loeb(100.0)["cap_inr"] - 36.79) < 0.01
    assert set(K.attack_intel()) == {"Brute force", "SQL injection", "DDoS"}


def test_live_view_and_simulated_burst(tmp_path):
    import random
    from datetime import datetime, timedelta, timezone
    from src import database, bootstrap, incident_store as st
    from src.engine.simulator import Simulator
    from src.engine.geo import region_of
    database.DB_PATH = tmp_path / "l.db"; database.initialize(); bootstrap.bootstrap_templates()
    with database.connection() as con:
        sid = con.execute("SELECT id FROM monitored_servers WHERE hostname='demo.cyberquant.local'").fetchone()[0]
        v = st.live(con, sid, 1, -330)
        assert set(v) >= {"status", "feed", "endpoints", "share", "dots", "regions", "heatmap", "rate"} and len(v["heatmap"]) == 7 and len(v["heatmap"][0]) == 24
        assert v["feed"] and v["endpoints"] and v["share"]["genuine"] > 0 and sum(v["share"].values()) > 0
        assert v["dots"] and all(-90 <= d["lat"] <= 90 for d in v["dots"])
        # a simulated DDoS burst injected through the real engine shows up as an attack on the status banner
        sim = Simulator(7, start=datetime.now(timezone.utc) - timedelta(seconds=100)); sim.ddos(1.7, 1.0, 420)
        engine = st.build_engine(con, sid, None)
        for ev in sorted(sim.events, key=lambda e: e["event_at"]): st.record_event(con, sid, ev, engine.process(ev))
        v2 = st.live(con, sid, 1, -330)
        assert v2["status"]["state"] == "attack" and v2["status"]["attack"] == "DDoS" and v2["share"]["DDoS"] > v["share"]["DDoS"]
    assert region_of("103.1.2.3")["registry"] == "APNIC" and region_of("41.1.1.1")["registry"] == "AFRINIC" and region_of("185.1.1.1")["registry"] == "RIPE"
