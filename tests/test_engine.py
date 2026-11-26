from datetime import datetime, timedelta, timezone
from src.engine.budget import expected_losses, optimise
from src.engine.cve_link import attack_for_description, exposure_multiplier
from src.engine.detector import DetectionEngine
from src.engine.features import FeatureExtractor
from src.engine.review import ReviewMemory, allow_limit
from src.engine.simulator import Simulator
from src.optimizer import optimize

T0 = datetime(2026, 3, 1, 9, 0, tzinfo=timezone.utc)


def ev(sec, ip, path="/login", status=401, account="alice", ua="Mozilla/5.0", method="POST"):
    return {"event_at": T0 + timedelta(seconds=sec), "request_method": method, "request_path": path, "response_status": status,
            "source_ip": ip, "metadata": {"user_agent": ua, **({"account": account} if account else {})}}


def run(engine, events):
    return [engine.process(e) for e in events]


def alerts(results):
    return [r for r in results if r["alert"]]


# ---- features / rules --------------------------------------------------------------------------
def test_feature_windows_expire():
    fx = FeatureExtractor()
    for i in range(6):
        f = fx.update({"t": i, "ip": "1.1.1.1", "account": "a", "path": "/login", "ua": "x", "status": 401})
    assert f["ip_auth_fail_300"] == 6
    f = fx.update({"t": 1000, "ip": "1.1.1.1", "account": "a", "path": "/login", "ua": "x", "status": 401})
    assert f["ip_auth_fail_300"] == 1 and f["srv_req_60"] == 1


def test_sqli_signature_rule_fires_and_innocent_quote_does_not():
    eng = DetectionEngine(1)
    assert eng.process(ev(0, "9.9.9.9", "/search?q=%27%20UNION%20SELECT%20password%20FROM%20users--", 200, None, method="GET"))["threat_type"] == "SQL injection"
    assert eng.process(ev(1, "8.8.8.8", "/search?q=o%27brien", 200, None, method="GET"))["threat_type"] is None
    assert eng.process(ev(2, "8.8.8.8", "/search?q=select+shoes", 200, None, method="GET"))["threat_type"] is None


# ---- the two login examples from the brief -----------------------------------------------------
def test_same_ip_five_failures_is_flagged_for_review_and_suggests_genuine_after_success():
    eng = DetectionEngine(1)
    res = run(eng, [ev(i * 30, "5.5.5.5") for i in range(5)])
    assert len(alerts(res)) == 1
    inc = alerts(res)[0]["incident"]
    assert inc["threat_type"] == "Brute force" and inc["suggestion"]["label"] == "needs_review"
    run(eng, [ev(200, "5.5.5.5", status=200)])                     # the user finally logs in
    assert inc["suggestion"]["label"] == "likely_genuine"


def test_fifty_ips_one_account_is_a_distributed_attack_and_one_incident():
    eng = DetectionEngine(1)
    events = [ev(i * 6, f"20.0.{i // 250}.{i % 250 + 1}", account="victim") for i in range(50)]
    res = run(eng, events)
    flagged = [r for r in res if r["threat_type"]]
    assert flagged and {r["threat_type"] for r in flagged} == {"Brute force"}
    assert len(alerts(res)) == 1                                   # grouped, not one alert per IP
    inc = alerts(res)[0]["incident"]
    assert inc["key_kind"] == "account" and inc["suggestion"]["label"] == "likely_attack" and inc["source_count"] >= 5


def test_ddos_ignores_a_diverse_genuine_surge():
    eng = DetectionEngine(1)
    sim = Simulator(5); sim.flash_crowd(6, duration_min=3, rate_per_min=220)
    res = run(eng, sim.events)
    assert not any(r["threat_type"] == "DDoS" for r in res)


def test_ddos_flood_flags_bots_but_not_the_genuine_user_beside_them():
    eng = DetectionEngine(1)
    bots = [f"60.1.{i // 200}.{i % 200 + 1}" for i in range(80)]
    events = [ev(i * 0.2, bots[i % 80], "/", 503, None, "python-requests/2.31", "GET") for i in range(400)]
    events.append(ev(40, "7.7.7.7", "/products/12", 200, None, "Mozilla/5.0 Safari", "GET"))
    events.sort(key=lambda e: e["event_at"])
    res = run(eng, events)
    assert sum(r["threat_type"] == "DDoS" for r in res) > 250 and len(alerts(res)) == 1
    genuine = [r for e, r in zip(events, res) if e["source_ip"] == "7.7.7.7"][0]
    assert genuine["threat_type"] is None


# ---- review learning ---------------------------------------------------------------------------
def test_reviewed_genuine_pattern_is_auto_allowed_then_escalates_if_it_grows():
    eng = DetectionEngine(1)
    first = run(eng, [ev(i * 20, "5.5.5.5") for i in range(5)])
    inc = alerts(first)[0]["incident"]
    inc["id"] = 1
    eng.memory.add({"id": 1, "threat_type": "Brute force", "key_kind": "ip", "decision": "genuine", "handling": "allow_similar",
                    "source_ip": "5.5.5.5", "account": "alice", "path": "/login", "volume": inc["volume"]})
    eng.open.pop(("Brute force", inc["key"]))
    # a day later the same user mistypes five times again: learned, so no alert
    later = run(eng, [ev(86400 + i * 20, "5.5.5.5") for i in range(5)])
    assert not alerts(later) and later[-1]["state"] == "auto_allowed" and later[-1]["threat_type"] is None
    # but forty failures from the same IP exceeds what was reviewed and re-alerts
    more = run(eng, [ev(86400 + 100 + i * 2, "5.5.5.5") for i in range(40)])
    assert alerts(more) and any(r["threat_type"] == "Brute force" for r in more)
    # and a different IP is unaffected by the learned pattern
    other = run(eng, [ev(90000 + i * 20, "6.6.6.6") for i in range(5)])
    assert len(alerts(other)) == 1


def test_confirmed_attack_pattern_raises_severity_and_blocklist():
    mem = ReviewMemory([{"id": 2, "threat_type": "Brute force", "key_kind": "ip", "decision": "attack", "handling": "block_source",
                         "source_ip": "5.5.5.5", "account": None, "path": "/login", "volume": 12}])
    assert mem.blocklist() == [{"source_ip": "5.5.5.5", "threat_type": "Brute force"}]
    eng = DetectionEngine(1, memory=mem)
    res = alerts(run(eng, [ev(i * 20, "5.5.5.5") for i in range(5)]))
    assert res[0]["severity"] == "critical" and res[0]["review_effect"] == "block"


def test_allow_limit_tolerance():
    assert allow_limit(5) == 10 and allow_limit(30) == 60


# ---- budget / cve ------------------------------------------------------------------------------
def test_budget_respects_budget_prerequisites_and_overlap():
    losses = expected_losses({"SQL injection": 4, "Brute force": 10, "DDoS": 3}, period_days=30)
    for budget in (30_000, 100_000, 300_000, 800_000):
        plan = optimise(losses, budget=budget)
        assert plan["allocated_inr"] <= budget + 1e-6
        ids = {c["id"] for c in plan["selected"]}
        assert "C-BLOCK" not in ids or "C-MON" in ids              # prerequisite honoured
    small, large = optimise(losses, budget=100_000), optimise(losses, budget=800_000)
    assert large["loss_avoided_inr"] >= small["loss_avoided_inr"] > 0
    # overlap: stacking two controls on one attack yields less than the sum of their solo benefits
    solo = [optimise(losses, controls=[c], budget=1e9)["loss_avoided_inr"] for c in (
        {"id": "a", "cost_inr": 1, "effect": {"Brute force": 0.5}}, {"id": "b", "cost_inr": 1, "effect": {"Brute force": 0.5}})]
    both = optimise(losses, controls=[{"id": "a", "cost_inr": 1, "effect": {"Brute force": 0.5}}, {"id": "b", "cost_inr": 1, "effect": {"Brute force": 0.5}}], budget=10)
    assert both["loss_avoided_inr"] < sum(solo) and abs(next(a for a in both["per_attack"] if a["attack"] == "Brute force")["reduction_pct"] - 0.75) < 1e-6


def test_budget_min_cost_for_target_and_frontier_monotone():
    losses = expected_losses({"SQL injection": 4, "Brute force": 10, "DDoS": 3}, period_days=30)
    plan = optimise(losses, budget=200_000, target_reduction=0.6)
    assert plan["min_cost_for_target"]["loss_avoided_inr"] >= 0.6 * plan["baseline_loss_inr"] - 1
    f = plan["frontier"]; assert all(a["cost_inr"] <= b["cost_inr"] and a["loss_avoided_inr"] < b["loss_avoided_inr"] for a, b in zip(f, f[1:]))


def test_asset_optimizer_matches_expectation():
    actions = [{"action_id": "A", "cost_inr": 100, "effectiveness_estimate": 0.5, "affected_asset_ids": "X", "prerequisites": ""},
               {"action_id": "B", "cost_inr": 100, "effectiveness_estimate": 0.5, "affected_asset_ids": "X", "prerequisites": "A"}]
    out = optimize(actions, {"X": 1000.0}, 200)
    assert {a["action_id"] for a in out["selected"]} == {"A", "B"} and abs(out["risk_reduction_inr"] - 750) < 1e-6
    assert [a["action_id"] for a in optimize(actions, {"X": 1000.0}, 150)["selected"]] == ["A"]


def test_cve_linking():
    assert attack_for_description("A SQL injection vulnerability in foo") == ["SQL injection"]
    mult, cves = exposure_multiplier("SQL injection", [{"cve_id": "CVE-1", "description": "SQL injection in X", "cvss_score": 9.8}, {"cve_id": "CVE-2", "description": "XSS", "cvss_score": 9}])
    assert 1.4 < mult <= 1.5 and [c["cve_id"] for c in cves] == ["CVE-1"]
    assert exposure_multiplier("DDoS", [])[0] == 1.0


# ---- ML ----------------------------------------------------------------------------------------
def test_ml_model_flags_attacks_on_unseen_traffic_with_low_false_positives(fast_classifier):
    from collections import Counter
    c = Counter()
    for seed in (4001, 4002):
        eng = DetectionEngine(1, fast_classifier)
        for e in Simulator(seed).session(20, attacks={"brute_single": 1, "brute_distributed": 1, "sqli": 1, "ddos": 1}):
            r = eng.process(e); c[(e["label"] != "Normal", r["threat_type"] is not None)] += 1
    tp, fn, fp = c[(True, True)], c[(True, False)], c[(False, True)]
    assert tp / (tp + fn) > 0.9 and fp / max(1, sum(v for (a, _), v in c.items() if not a)) < 0.03
