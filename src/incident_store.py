"""Persistence glue between the framework-free engine and SQLite (used by the API, the demo and the tests)."""
from __future__ import annotations
import json
from datetime import datetime, timedelta, timezone
from .engine import ATTACK_TYPES
from .engine.budget import expected_losses, optimise
from .engine.cve_link import exposure_multiplier
from .engine.detector import DetectionEngine
from .engine.events import to_epoch
from .engine.features import FEATURE_NAMES
from .engine.review import VALID, ReviewMemory


def iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---- incident <-> row ----------------------------------------------------------------------------
def row_to_incident(r) -> dict:
    return {"id": r["id"], "server_id": r["server_id"], "threat_type": r["threat_type"], "key": r["key"], "key_kind": r["key_kind"],
            "status": r["status"], "severity": r["severity"], "confidence": r["confidence"], "first_at": to_epoch(r["first_at"]),
            "last_at": to_epoch(r["last_at"]), "event_count": r["event_count"], "volume": r["volume"], "source_count": r["source_count"],
            "source_ips": json.loads(r["source_ips_json"]), "account": r["account"], "path": r["path"], "basis": json.loads(r["basis_json"]),
            "rules": json.loads(r["rules_json"]), "source": r["detection_source"], "suggestion": json.loads(r["suggestion_json"]),
            "review_effect": r["review_effect"], "pattern_id": r["pattern_id"], "head_features": json.loads(r["head_features_json"])}


def public_incident(r) -> dict:
    """Incident as shown to the UI/API."""
    d = dict(r); out = {k: d[k] for k in ("id", "threat_type", "status", "severity", "confidence", "event_count", "volume", "source_count",
                                         "account", "path", "detection_source", "review_effect", "review_decision", "review_handling",
                                         "review_note", "reviewed_at")}
    out.update(first_at=d["first_at"], last_at=d["last_at"], source_ips=json.loads(d["source_ips_json"]), basis=json.loads(d["basis_json"]),
               rules=json.loads(d["rules_json"]), suggestion=json.loads(d["suggestion_json"]))
    return out


def save_incident(con, inc: dict):
    values = (inc["threat_type"], inc["key"], inc["key_kind"], inc["status"], inc["severity"], inc["confidence"], iso(inc["first_at"]),
              iso(inc["last_at"]), inc["event_count"], inc["volume"], inc["source_count"], json.dumps(inc["source_ips"]), inc["account"],
              inc["path"], json.dumps(inc["basis"]), json.dumps(inc["rules"]), inc["source"], json.dumps(inc["suggestion"]),
              inc["review_effect"], inc.get("pattern_id"), json.dumps(inc["head_features"]))
    if inc["id"] is None:
        cur = con.execute("""INSERT INTO incidents(server_id,threat_type,key,key_kind,status,severity,confidence,first_at,last_at,event_count,
            volume,source_count,source_ips_json,account,path,basis_json,rules_json,detection_source,suggestion_json,review_effect,pattern_id,head_features_json)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (inc["server_id"],) + values)
        inc["id"] = cur.lastrowid
    else:
        con.execute("""UPDATE incidents SET threat_type=?,key=?,key_kind=?,status=?,severity=?,confidence=?,first_at=?,last_at=?,event_count=?,
            volume=?,source_count=?,source_ips_json=?,account=?,path=?,basis_json=?,rules_json=?,detection_source=?,suggestion_json=?,
            review_effect=?,pattern_id=?,head_features_json=? WHERE id=?""", values + (inc["id"],))


def record_event(con, server_id: int, event: dict, result: dict, received_at: str | None = None) -> int:
    """Persist one processed event (and its incident, if it changed). Returns the server_events id."""
    inc = result["incident"]
    if inc is not None and result["incident_changed"]: save_incident(con, inc)
    meta = dict(event.get("metadata") or {})
    meta.pop("label", None)
    meta["detection"] = {"state": result["state"], "source": result["source"], "needs_review": result["needs_review"],
                         "ml_probs": result["ml_probs"], "review_effect": result["review_effect"]}
    event_at = event["event_at"]
    event_at = event_at.astimezone(timezone.utc).isoformat() if isinstance(event_at, datetime) else str(event_at)
    cur = con.execute("""INSERT INTO server_events(server_id,event_at,received_at,request_method,request_path,response_status,source_ip,
        threat_type,severity,detector_confidence,metadata_json,incident_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
        (server_id, event_at, received_at or now_iso(), event.get("request_method"), event.get("request_path"), event.get("response_status"),
         event.get("source_ip"), result["threat_type"], result["severity"], result["confidence"], json.dumps(meta),
         inc["id"] if inc is not None and result["state"] in ("alert", "attached", "auto_allowed") else None))
    return cur.lastrowid


# ---- engine lifecycle ----------------------------------------------------------------------------
def load_memory(con, server_id: int) -> ReviewMemory:
    rows = con.execute("SELECT * FROM review_patterns WHERE server_id=? ORDER BY id", (server_id,)).fetchall()
    return ReviewMemory([dict(r) for r in rows])


def build_engine(con, server_id: int, classifier) -> DetectionEngine:
    cutoff = iso(datetime.now(timezone.utc).timestamp() - 3600)
    open_rows = con.execute("SELECT * FROM incidents WHERE server_id=? AND status IN ('open','auto_allowed') AND last_at>=?", (server_id, cutoff)).fetchall()
    return DetectionEngine(server_id, classifier, load_memory(con, server_id), incidents=[row_to_incident(r) for r in open_rows])


# ---- analyst review ------------------------------------------------------------------------------
def review_incident(con, engine: DetectionEngine | None, server_id: int, incident_id: int, user_id: int | None,
                    decision: str, handling: str, note: str | None = None) -> dict:
    if decision not in VALID: raise ValueError("decision must be 'genuine' or 'attack'")
    if handling not in VALID[decision]:
        raise ValueError(f"handling '{handling}' is not valid for a '{decision}' decision; choose one of {sorted(VALID[decision])}")
    row = con.execute("SELECT * FROM incidents WHERE id=? AND server_id=?", (incident_id, server_id)).fetchone()
    if not row: raise LookupError("Incident not found on this server")
    inc = row_to_incident(row)
    source_ip = inc["source_ips"][0] if inc["source_ips"] else None
    cur = con.execute("""INSERT INTO review_patterns(server_id,incident_id,user_id,threat_type,key_kind,decision,handling,source_ip,account,path,volume,note,created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""", (server_id, incident_id, user_id, inc["threat_type"], inc["key_kind"], decision, handling,
                                                source_ip, inc["account"], inc["path"], inc["volume"], note, now_iso()))
    pattern = dict(con.execute("SELECT * FROM review_patterns WHERE id=?", (cur.lastrowid,)).fetchone())
    extra_patterns = []
    if handling == "block_source":                       # a distributed attack has many sources: recommend blocking every one we recorded
        for ip in inc["source_ips"][1:25]:
            c2 = con.execute("""INSERT INTO review_patterns(server_id,incident_id,user_id,threat_type,key_kind,decision,handling,source_ip,account,path,volume,note,created_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""", (server_id, incident_id, user_id, inc["threat_type"], inc["key_kind"], decision, handling, ip, inc["account"], inc["path"], inc["volume"], note, now_iso()))
            extra_patterns.append(dict(con.execute("SELECT * FROM review_patterns WHERE id=?", (c2.lastrowid,)).fetchone()))
    status = "reviewed_genuine" if decision == "genuine" else "reviewed_attack"
    con.execute("UPDATE incidents SET status=?,review_decision=?,review_handling=?,review_note=?,reviewed_by=?,reviewed_at=? WHERE id=?",
                (status, decision, handling, note, user_id, now_iso(), incident_id))
    # training example for the model: genuine -> Normal, attack -> its attack type
    if inc["head_features"] and all(k in inc["head_features"] for k in FEATURE_NAMES):
        con.execute("INSERT INTO review_samples(server_id,incident_id,features_json,label,created_at) VALUES(?,?,?,?,?)",
                    (server_id, incident_id, json.dumps(inc["head_features"]), "Normal" if decision == "genuine" else inc["threat_type"], now_iso()))
    if engine is not None:
        engine.memory.add(pattern)
        for extra in extra_patterns: engine.memory.add(extra)
        engine.open.pop((inc["threat_type"], inc["key"]), None)
    return pattern


def retrain_from_reviews(con) -> dict:
    """Retrain the classifier with analyst-reviewed examples (weighted above synthetic rows)."""
    import numpy as np
    from .engine.model import train
    rows = con.execute("SELECT features_json,label FROM review_samples").fetchall()
    if not rows: return {"status": "no_reviewed_examples"}
    X = np.array([[float(json.loads(r["features_json"])[k]) for k in FEATURE_NAMES] for r in rows])
    summary = train(extra=(X, np.array([r["label"] for r in rows])))
    summary.pop("_model", None)
    return summary


# ---- reporting -----------------------------------------------------------------------------------
def traffic_summary(con, server_id: int) -> dict:
    """Requests, genuine vs flagged, per-minute series for the most recent 60 minutes of data."""
    last = con.execute("SELECT MAX(event_at) m FROM server_events WHERE server_id=?", (server_id,)).fetchone()["m"]
    if not last: return {"total": 0, "genuine": 0, "flagged": 0, "by_type": {}, "series": [], "window_start": None, "window_end": None}
    end = to_epoch(last); start = iso(end - 3600)
    rows = con.execute("SELECT event_at, threat_type FROM server_events WHERE server_id=? AND event_at>=?", (server_id, start)).fetchall()
    minutes: dict[str, dict] = {}
    by_type = {t: 0 for t in ATTACK_TYPES}
    for r in rows:
        m = r["event_at"][:16]; slot = minutes.setdefault(m, {"minute": m, "genuine": 0, **{t: 0 for t in ATTACK_TYPES}})
        if r["threat_type"] in by_type: slot[r["threat_type"]] += 1; by_type[r["threat_type"]] += 1
        else: slot["genuine"] += 1
    flagged = sum(by_type.values())
    return {"total": len(rows), "genuine": len(rows) - flagged, "flagged": flagged, "by_type": by_type, "window_start": start,
            "window_end": iso(end), "series": [minutes[k] for k in sorted(minutes)]}


def incident_counts(con, server_id: int) -> dict:
    """Incidents that count towards risk: unreviewed or confirmed attacks (genuine/auto-allowed are excluded)."""
    rows = con.execute("""SELECT threat_type, COUNT(*) n FROM incidents WHERE server_id=? AND status IN ('open','closed','reviewed_attack')
                          GROUP BY threat_type""", (server_id,)).fetchall()
    return {r["threat_type"]: r["n"] for r in rows}


def observation_days(con, server_id: int) -> float:
    r = con.execute("SELECT MIN(event_at) a, MAX(event_at) b FROM server_events WHERE server_id=?", (server_id,)).fetchone()
    return max((to_epoch(r["b"]) - to_epoch(r["a"])) / 86400, 0.0) if r["a"] else 0.0


def budget_plan(con, server_id: int, budget: float, impact: dict | None = None, success: dict | None = None,
                period_days: float | None = None, target_reduction: float | None = None) -> dict:
    counts = incident_counts(con, server_id)
    span = observation_days(con, server_id)
    days = period_days if period_days else max(span, 7.0)
    exposure, linked = {}, {}
    asset = con.execute("SELECT asset_id FROM monitored_servers WHERE id=?", (server_id,)).fetchone()["asset_id"]
    if asset:
        vulns = [dict(r) for r in con.execute("""SELECT v.cve_id,v.description,v.cvss_score FROM asset_vulnerabilities av JOIN vulnerabilities v ON v.cve_id=av.cve_id
                                                   WHERE av.asset_id=? AND av.finding_status='open'""", (asset,))]
        for attack in ATTACK_TYPES:
            exposure[attack], linked[attack] = exposure_multiplier(attack, vulns)
    losses = expected_losses({a: counts.get(a, 0) for a in ATTACK_TYPES}, days, impact, exposure, success)
    result = optimise(losses, budget=budget, target_reduction=target_reduction)
    from .engine import knowledge as K
    base = result["baseline_loss_inr"]; ids = [c["id"] for c in result["selected"]]
    steps = K.frontier_story(result["frontier"], base)
    result.update(attack_intel=K.attack_intel(), allocation=K.allocation(result["selected"], budget),
                  action_plan=K.action_plan(result["selected"], counts), catalogue=K.catalogue_with_marginal(ids, losses),
                  protection_curve=steps, diminishing_point=K.diminishing_point(steps), gordon_loeb=K.gordon_loeb(base),
                  sources=K.all_sources(), usd_inr=K.USD_INR, layers=[{'id': i, 'name': n} for i, n in K.LAYERS])
    result.update(incident_counts=counts, period_days=days, observed_span_days=span, linked_cves=linked, linked_asset=asset,
                  period_note=(f"Incident counts were annualised from a {days:g}-day window"
                               + ("" if period_days or span >= 7 else f" (only {span:.2f} days of data observed; a 7-day minimum is assumed)")
                               + ". Change the observation period if your data covers a different span."))
    return result


# ---- charts: live minute series, monthly and per-day views ---------------------------------------
_NOT_ATTACK = ("reviewed_genuine", "auto_allowed")


def _local(epoch: float, tz_offset_min: int) -> datetime:
    """UTC epoch -> naive local datetime. tz_offset_min follows JavaScript's getTimezoneOffset (UTC minus local)."""
    return datetime.fromtimestamp(epoch - tz_offset_min * 60, timezone.utc).replace(tzinfo=None)


def charts(con, server_id: int, tz_offset_min: int = 0, day: str | None = None, now: float | None = None) -> dict:
    """Everything the Live traffic graphs need. An event counts as an attack while its incident is open or confirmed;
    once an analyst marks the incident genuine (or a learned pattern auto-allows it) its requests move back to genuine."""
    now = now if now is not None else datetime.now(timezone.utc).timestamp()
    last = con.execute("SELECT MAX(event_at) m FROM server_events WHERE server_id=?", (server_id,)).fetchone()["m"]
    anchor = to_epoch(last) if last else now
    q = """SELECT e.event_at, e.threat_type, i.status AS istatus FROM server_events e
           LEFT JOIN incidents i ON i.id=e.incident_id WHERE e.server_id=? AND e.event_at>=? AND e.event_at<?"""

    def kind(r):
        t, st = r["threat_type"], r["istatus"]
        return t if t in ATTACK_TYPES and st not in _NOT_ATTACK else "genuine"

    # 1) real-time: per-minute for the last 60 minutes of data
    minutes: dict[int, dict] = {}
    start = int(anchor // 60) * 60 - 59 * 60
    for k in range(60): minutes[start + k * 60] = {"t": iso(start + k * 60), "genuine": 0, **{a: 0 for a in ATTACK_TYPES}}
    for r in con.execute(q, (server_id, iso(start), iso(anchor + 60))):
        slot = minutes.get(int(to_epoch(r["event_at"]) // 60) * 60)
        if slot is not None: slot[kind(r)] += 1
    flagged = {a: sum(m[a] for m in minutes.values()) for a in ATTACK_TYPES}
    confirmed = {a: 0 for a in ATTACK_TYPES}
    for r in con.execute("""SELECT i.threat_type, COUNT(*) n FROM server_events e JOIN incidents i ON i.id=e.incident_id
                            WHERE e.server_id=? AND i.status='reviewed_attack' AND e.event_at>=? GROUP BY i.threat_type""", (server_id, iso(start))):
        if r["threat_type"] in confirmed: confirmed[r["threat_type"]] = r["n"]

    # 2) per month (last 12 months): incidents by attack type
    now_local = _local(now, tz_offset_min)
    months = []
    y, m = now_local.year, now_local.month
    for _ in range(12):
        months.append(f"{y:04d}-{m:02d}"); m -= 1
        if m == 0: y, m = y - 1, 12
    months.reverse()
    table = {k: {"month": k, **{a: 0 for a in ATTACK_TYPES}} for k in months}
    for r in con.execute("SELECT threat_type, first_at FROM incidents WHERE server_id=? AND status IN ('open','closed','reviewed_attack')", (server_id,)):
        key = _local(to_epoch(r["first_at"]), tz_offset_min).strftime("%Y-%m")
        if key in table and r["threat_type"] in ATTACK_TYPES: table[key][r["threat_type"]] += 1
    monthly = [{**table[k], "total": sum(table[k][a] for a in ATTACK_TYPES)} for k in months]

    # 2b) last 35 days: incidents per local day by type (the clickable strip above the day view)
    d_end = datetime.strptime(now_local.strftime("%Y-%m-%d"), "%Y-%m-%d")
    dkeys = [(d_end - timedelta(days=k)).strftime("%Y-%m-%d") for k in range(34, -1, -1)]
    dtab = {k: {"date": k, **{a: 0 for a in ATTACK_TYPES}} for k in dkeys}
    for r in con.execute("SELECT threat_type, first_at FROM incidents WHERE server_id=? AND status IN ('open','closed','reviewed_attack') AND first_at>=?",
                         (server_id, iso(now - 37 * 86400))):
        key = _local(to_epoch(r["first_at"]), tz_offset_min).strftime("%Y-%m-%d")
        if key in dtab and r["threat_type"] in ATTACK_TYPES: dtab[key][r["threat_type"]] += 1
    daily = [{**dtab[k], "total": sum(dtab[k][a] for a in ATTACK_TYPES)} for k in dkeys]

    # 3) one day, hour by hour
    days = sorted({_local(to_epoch(r["event_at"]), tz_offset_min).strftime("%Y-%m-%d") for r in con.execute(
        """SELECT e.event_at FROM server_events e LEFT JOIN incidents i ON i.id=e.incident_id WHERE e.server_id=? AND e.threat_type IS NOT NULL
           AND COALESCE(i.status,'') NOT IN ('reviewed_genuine','auto_allowed') AND e.event_at>=?""", (server_id, iso(now - 400 * 86400)))})
    chosen = day if day and len(day) == 10 else (days[-1] if days else now_local.strftime("%Y-%m-%d"))
    try: d0 = datetime.strptime(chosen, "%Y-%m-%d")
    except ValueError: d0 = datetime.strptime(now_local.strftime("%Y-%m-%d"), "%Y-%m-%d"); chosen = d0.strftime("%Y-%m-%d")
    lo = d0.replace(tzinfo=timezone.utc).timestamp() + tz_offset_min * 60
    hours = [{"hour": h, "genuine": 0, **{a: 0 for a in ATTACK_TYPES}} for h in range(24)]
    for r in con.execute(q, (server_id, iso(lo), iso(lo + 86400))):
        hours[_local(to_epoch(r["event_at"]), tz_offset_min).hour][kind(r)] += 1
    inc = [{"id": r["id"], "threat_type": r["threat_type"], "status": r["status"], "severity": r["severity"], "first_at": r["first_at"],
            "last_at": r["last_at"], "events": r["event_count"], "sources": r["source_count"]}
           for r in con.execute("""SELECT * FROM incidents WHERE server_id=? AND status IN ('open','closed','reviewed_attack') AND first_at>=? AND first_at<?
                                   ORDER BY first_at""", (server_id, iso(lo), iso(lo + 86400)))]
    return {"anchor": iso(anchor), "stale_seconds": max(0, int(now - anchor)), "tz_offset_min": tz_offset_min,
            "realtime": {"series": [minutes[k] for k in sorted(minutes)], "flagged": flagged, "confirmed": confirmed},
            "monthly": monthly, "daily": daily, "day": {"date": chosen, "available_days": days[-90:], "hours": hours, "incidents": inc}}


# ---- live view: status, feed, endpoints, regions, hour-by-weekday heatmap ----------------------------
def live(con, server_id: int, hours: float = 1, tz_offset_min: int = 0, now: float | None = None) -> dict:
    """Everything the upgraded Live traffic page needs besides charts(). Attack = effective classification (see charts())."""
    from collections import Counter, defaultdict
    from .engine.geo import region_of
    now = now if now is not None else datetime.now(timezone.utc).timestamp()
    last = con.execute("SELECT MAX(event_at) m FROM server_events WHERE server_id=?", (server_id,)).fetchone()["m"]
    anchor = to_epoch(last) if last else now
    hours = max(1.0, min(float(hours), 24 * 31))
    q = """SELECT e.event_at, e.request_path, e.response_status, e.source_ip, e.threat_type, e.severity, e.detector_confidence, e.metadata_json,
                  i.id AS iid, i.status AS istatus FROM server_events e LEFT JOIN incidents i ON i.id=e.incident_id
           WHERE e.server_id=? AND e.event_at>=? AND e.event_at<? ORDER BY e.event_at DESC"""
    rows = [dict(r) for r in con.execute(q, (server_id, iso(anchor - hours * 3600), iso(anchor + 60)))]

    def kind(r): return r["threat_type"] if r["threat_type"] in ATTACK_TYPES and r["istatus"] not in _NOT_ATTACK else "genuine"
    for r in rows: r["kind"] = kind(r); r["t"] = to_epoch(r["event_at"])
    attacks = [r for r in rows if r["kind"] != "genuine"]
    # status from the most recent five minutes of data
    recent = [r for r in attacks if r["t"] >= anchor - 300]
    stale = max(0.0, now - anchor)
    if recent:
        top = Counter(r["kind"] for r in recent).most_common(1)[0][0]
        sev = max((SEV_RANK.get(r["severity"], 0) for r in recent), default=0)
        status = {"state": "attack", "attack": top, "events_5m": len(recent), "severity": ["low", "low", "medium", "high", "critical"][min(sev, 4)]}
    else:
        status = {"state": "clear", "attack": None, "events_5m": 0, "severity": None}
    status["stale_seconds"] = stale
    minute = Counter(int(r["t"] // 60) for r in rows if r["t"] >= anchor - 3600)
    cur = minute.get(int(anchor // 60), 0); typical = sorted(minute.values())[len(minute) // 2] if minute else 0
    # feed: newest flagged events
    feed, per_kind = [], Counter()
    for r in attacks:                                                  # newest first, at most 14 per type so no single attack hides the others
        if per_kind[r["kind"]] >= 14: continue
        per_kind[r["kind"]] += 1
        meta = json.loads(r["metadata_json"] or "{}"); d = meta.get("detection", {})
        st = {"reviewed_attack": "confirmed attack", "open": "awaiting review", "closed": "closed"}.get(r["istatus"], "flagged")
        feed.append({"t": iso(r["t"]), "type": r["kind"], "ip": r["source_ip"], "path": (r["request_path"] or "").split("?")[0], "status": r["response_status"],
                     "severity": r["severity"], "state": st, "source": d.get("source"), "incident_id": r["iid"]})
    # endpoints
    ep = defaultdict(lambda: {"total": 0, "attack": 0, "types": Counter()})
    for r in rows:
        k = (r["request_path"] or "?").split("?")[0]; ep[k]["total"] += 1
        if r["kind"] != "genuine": ep[k]["attack"] += 1; ep[k]["types"][r["kind"]] += 1
    endpoints = [{"path": k, "total": v["total"], "attack": v["attack"], "types": dict(v["types"])}
                 for k, v in sorted(ep.items(), key=lambda kv: (-kv[1]["attack"], -kv[1]["total"]))[:8]]
    share = Counter(r["kind"] for r in rows)
    # regions / dots
    per_ip = defaultdict(Counter)
    for r in attacks:
        if r["source_ip"]: per_ip[r["source_ip"]][r["kind"]] += 1
    dots = []
    for ip, c in sorted(per_ip.items(), key=lambda kv: -sum(kv[1].values()))[:120]:
        g = region_of(ip); dots.append({"ip": ip, "lat": g["lat"], "lon": g["lon"], "region": g["region"], "count": sum(c.values()), "type": c.most_common(1)[0][0]})
    regions = defaultdict(lambda: {"count": 0, "ips": set()})
    for ip, c in per_ip.items():
        g = region_of(ip); regions[g["region"]]["count"] += sum(c.values()); regions[g["region"]]["ips"].add(ip)
    regs = sorted(({"region": k, "count": v["count"], "ips": len(v["ips"])} for k, v in regions.items()), key=lambda x: -x["count"])
    # heatmap: weekday x hour over the last 28 days of data (local time)
    heat = [[0] * 24 for _ in range(7)]
    for r in con.execute(q, (server_id, iso(anchor - 28 * 86400), iso(anchor + 60))):
        r = dict(r)
        if kind(r) == "genuine": continue
        d = _local(to_epoch(r["event_at"]), tz_offset_min); heat[d.weekday()][d.hour] += 1
    return {"hours": hours, "anchor": iso(anchor), "status": status, "rate": {"per_min_now": cur, "typical_per_min": typical, "per_sec_now": round(cur / 60, 2)},
            "feed": feed, "endpoints": endpoints, "share": {"genuine": share.get("genuine", 0), **{a: share.get(a, 0) for a in ATTACK_TYPES}},
            "dots": dots, "regions": regs, "heatmap": heat, "heat_max": max((max(r) for r in heat), default=0),
            "geo_note": "Approximate region of the IP's registry block (offline). It shows where an address block was allocated, not the attacker's real location."}


SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
