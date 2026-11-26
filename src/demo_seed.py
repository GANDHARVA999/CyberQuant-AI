"""Seed the demo server by running SIMULATED traffic through the real detection engine (nothing is hand-written)."""
from datetime import datetime, timedelta, timezone
from . import incident_store as istore
from .engine.simulator import Simulator


def seed_demo(con, server_id: int, classifier, minutes: int = 30, seed: int = 11):
    start = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=minutes + 1)
    sim = Simulator(seed, start=start)
    sim.forgetful_login(120, fails=6, succeed=True)                 # -> flagged, then suggested 'likely genuine'
    sim.forgetful_login(400, fails=5, succeed=False)               # -> flagged, stays 'needs review'
    events = sim.session(minutes, attacks={"brute_single": 1, "brute_distributed": 1, "sqli": 2, "ddos": 2}, rate=12)
    engine = istore.build_engine(con, server_id, classifier)
    for ev in events:
        ev["metadata"]["synthetic_demo"] = True
        istore.record_event(con, server_id, ev, engine.process(ev), received_at=ev["event_at"].isoformat())
    return engine


def seed_history(con, server_id: int, months: int = 11, seed: int = 5):
    """SIMULATED history so the monthly and per-day graphs have something to show. Each past incident is a closed attack with a
    handful of flagged requests at a realistic hour (brute force clusters at night, DDoS in the afternoon, SQL injection anytime)."""
    import json, random
    rng = random.Random(seed)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    hour_w = {"Brute force": [5, 6, 6, 5, 4, 3, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 3, 4, 4, 5],
              "DDoS": [1, 1, 1, 1, 1, 1, 1, 2, 2, 3, 3, 4, 5, 6, 6, 6, 5, 4, 3, 3, 2, 2, 1, 1],
              "SQL injection": [3, 3, 3, 3, 3, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3]}
    paths = {"Brute force": "/login", "DDoS": "/", "SQL injection": "/products"}
    sev = {"Brute force": "medium", "DDoS": "high", "SQL injection": "critical"}
    for back in range(months, -1, -1):
        month_start = now - timedelta(days=30 * back)
        count = int(rng.uniform(8, 16) * (0.7 + 0.12 * (months - back)))             # attacks slowly grow over the year
        if back == 0: count = 15                                                       # the last month is always well populated
        for k in range(count):
            t = list(hour_w)[k % 3] if back <= 1 else rng.choice(list(hour_w))         # last two months: all three attack types in equal turn
            day = month_start - timedelta(days=rng.randint(1 if back == 0 else 0, 28))
            if day > now - timedelta(days=1): day = now - timedelta(days=rng.randint(1, 3))
            hour = rng.choices(range(24), weights=hour_w[t])[0]
            first = day.replace(hour=hour, minute=rng.randint(0, 45), second=rng.randint(0, 59))
            n = rng.randint(12, 40) if t == "Brute force" else rng.randint(30, 140) if t == "DDoS" else rng.randint(4, 14)
            last = first + timedelta(seconds=rng.randint(40, 600))
            ips = [f"{rng.randint(11, 220)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}" for _ in range(1 if t != "DDoS" else 4)]
            cur = con.execute("""INSERT INTO incidents(server_id,threat_type,key,key_kind,status,severity,confidence,first_at,last_at,event_count,volume,source_count,
                source_ips_json,path,basis_json,detection_source) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (server_id, t, f"hist-{first.isoformat()}", "ip", "closed", sev[t], round(rng.uniform(.78, .98), 2), first.isoformat(), last.isoformat(), n, n,
                 len(ips), json.dumps(ips), paths[t], json.dumps(["Simulated historical incident (demo data)"]), "simulated_history"))
            span = max(1, int((last - first).total_seconds()))
            for _e in range(min(n, 60)):
                at = first + timedelta(seconds=rng.randint(0, span))
                con.execute("""INSERT INTO server_events(server_id,event_at,received_at,request_method,request_path,response_status,source_ip,threat_type,severity,
                    detector_confidence,metadata_json,incident_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (server_id, at.isoformat(), at.isoformat(), "POST" if t == "Brute force" else "GET", paths[t], 401 if t == "Brute force" else 200,
                     rng.choice(ips), t, sev[t], .9, json.dumps({"synthetic_history": True}), cur.lastrowid))
            for h in {first.hour, (first.hour + 1) % 24}:                                   # a little genuine background around the incident
                for _g in range(rng.randint(3, 8)):
                    at = first.replace(hour=h, minute=rng.randint(0, 59), second=rng.randint(0, 59))
                    con.execute("""INSERT INTO server_events(server_id,event_at,received_at,request_method,request_path,response_status,source_ip,metadata_json)
                        VALUES(?,?,?,?,?,?,?,?)""", (server_id, at.isoformat(), at.isoformat(), "GET", rng.choice(["/", "/products", "/cart"]), 200,
                                                      f"49.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}", json.dumps({"synthetic_history": True})))


def ensure_history(con, server_id: int, days: int = 35, minimum: int = 3):
    """Make sure the last month holds a mix of all three attack types. Older demo databases were seeded with mostly brute force:
    when any type has fewer than `minimum` incidents in the window, the SIMULATED history (only) is replaced."""
    cut = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    have = {r[0]: r[1] for r in con.execute("SELECT threat_type,COUNT(*) FROM incidents WHERE server_id=? AND detection_source='simulated_history' AND first_at>=? GROUP BY threat_type", (server_id, cut))}
    if all(have.get(t, 0) >= minimum for t in ("Brute force", "SQL injection", "DDoS")): return False
    con.execute("DELETE FROM server_events WHERE server_id=? AND metadata_json LIKE '%synthetic_history%'", (server_id,))
    con.execute("DELETE FROM incidents WHERE server_id=? AND detection_source='simulated_history'", (server_id,))
    seed_history(con, server_id)
    return True
