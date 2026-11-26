"""Detection engine: rules + ML fusion, incident grouping, review-learning and genuine-user suggestions."""
from __future__ import annotations
from .events import prepare
from .features import FeatureExtractor
from .review import ReviewMemory, allow_limit, effect_of
from .rules import evaluate

SEV = ["low", "medium", "high", "critical"]
DEFAULT_KIND = {"SQL injection": "ip", "Brute force": "ip", "DDoS": "server"}
INCIDENT_GAP_S = 300


def _severity(conf: float, count: int, threat: str, status: int) -> str:
    level = 3 if conf >= 0.93 else 2 if conf >= 0.8 else 1
    if count >= 50: level = max(level, 3)
    elif count >= 15: level = max(level, 2)
    if threat == "SQL injection" and status >= 500: level = 3
    return SEV[level]


class DetectionEngine:
    def __init__(self, server_id: int | str = 0, classifier=None, memory: ReviewMemory | None = None,
                 rule_config: dict | None = None, incidents: list[dict] | None = None):
        self.server_id, self.classifier, self.cfg = server_id, classifier, rule_config
        self.memory = memory or ReviewMemory()
        self.fx = FeatureExtractor()
        self.open: dict[tuple, dict] = {}
        for inc in incidents or []:                         # re-attach incidents persisted before a restart
            if inc["status"] in ("open", "auto_allowed"):
                self.open[(inc["threat_type"], inc["key"])] = inc

    # -- helpers ---------------------------------------------------------------------------------
    @staticmethod
    def _volume(threat: str, f: dict) -> int:
        if threat == "Brute force": return max(f["ip_auth_fail_300"], f["acct_fail_300"])
        if threat == "DDoS": return f["srv_req_60"]
        return 1

    def _fuse(self, f: dict):
        hits = evaluate(f, self.cfg)
        best = max(hits, key=lambda h: h["confidence"]) if hits else None
        ml = self.classifier.proba(f) if self.classifier and self.classifier.worth_scoring(f) else None
        ml_top, ml_p = (max(((c, p) for c, p in ml.items() if c != "Normal"), key=lambda cp: cp[1]) if ml else (None, 0))
        if best:
            t, rc = best["type"], best["confidence"]
            basis, review = list(best["basis"]), False
            if ml is None:
                conf, source = rc * 0.9, "rules"
            elif ml.get(t, 0) >= 0.5:
                conf, source = min(0.99, 0.5 * rc + 0.5 * ml[t] + 0.08), "rules+ml"
                basis.append(f"ML model agrees: P({t}) = {ml[t]:.2f}")
            else:
                conf, source, review = rc * 0.8, "rules", True
                basis.append(f"ML model disagrees (P({t}) = {ml.get(t, 0):.2f}, P(Normal) = {ml['Normal']:.2f}): flagged for analyst review")
            return t, conf, source, review, basis, best["key_kind"], [h["rule"] for h in hits], ml
        if ml and ml_p >= 0.9:
            kind = DEFAULT_KIND[ml_top]
            if ml_top == "Brute force" and f["acct_distinct_ips_300"] >= 3: kind = "account"   # many IPs, one account
            return (ml_top, ml_p * 0.85, "ml", False,
                    [f"ML-only detection: P({ml_top}) = {ml_p:.2f}; no fixed rule matched", "Traffic features resemble past labelled attacks"],
                    kind, [], ml)
        return None, 0.0, None, False, ["No rule or ML signal indicated an attack."], None, [], ml

    @staticmethod
    def _suggest(threat: str, rule_names: list[str], f: dict, review: bool) -> dict:
        if threat == "Brute force" and rule_names[:1] == ["single-ip-repeated-failure"] and f["ip_distinct_accounts_300"] <= 2 and f["ip_auth_fail_300"] <= 8:
            return {"label": "needs_review", "reason": "A small number of failed logins from one IP against one account can be a forgotten password. "
                    "It becomes 'likely genuine' automatically if the same user then logs in successfully."}
        if review:
            return {"label": "needs_review", "reason": "Rules and the ML model disagree; please review."}
        return {"label": "likely_attack", "reason": "Pattern matches known attack behaviour (volume, distribution or signature)."}

    # -- main entry point ------------------------------------------------------------------------
    def process(self, event: dict) -> dict:
        ev = prepare(event)
        f = self.fx.update(ev)
        out = {"threat_type": None, "severity": None, "confidence": None, "alert": False, "state": "normal",
               "incident": None, "incident_new": False, "incident_changed": False, "basis": [], "source": None,
               "ml_probs": None, "needs_review": False, "review_effect": None}
        self._success_check(ev, f, out)
        t, conf, source, review, basis, key_kind, rules, ml = self._fuse(f)
        out["ml_probs"] = {k: round(v, 3) for k, v in ml.items()} if ml else None
        if not t:
            out["basis"] = basis
            return out
        key = {"ip": f"ip:{ev['ip']}", "account": f"acct:{ev['account']}", "server": "server"}[key_kind]
        if key_kind == "account" and not ev["account"]: key_kind, key = "ip", f"ip:{ev['ip']}"
        volume = self._volume(t, f)
        inc = self._find_open(t, key, ev)
        if inc and ev["t"] - inc["last_at"] > INCIDENT_GAP_S:
            inc["status"] = "closed" if inc["status"] == "open" else inc["status"]
            self.open.pop((t, inc["key"]), None); inc = None
        out.update(threat_type=t, confidence=round(conf, 3), source=source, needs_review=review, basis=basis)
        if inc is None:
            pattern = self.memory.match(t, key_kind, ev["ip"], ev["account"], ev["path"])
            effect = effect_of(pattern)
            inc = {"id": None, "server_id": self.server_id, "threat_type": t, "key": key, "key_kind": key_kind,
                   "status": "open", "severity": _severity(conf, 1, t, ev["status"]), "confidence": round(conf, 3),
                   "first_at": ev["t"], "last_at": ev["t"], "event_count": 0, "volume": volume,
                   "source_ips": [], "source_count": 0, "account": ev["account"], "path": ev["path"], "basis": basis,
                   "rules": rules, "source": source, "suggestion": self._suggest(t, rules, f, review), "review_effect": effect,
                   "pattern_id": pattern.get("id") if pattern else None, "head_features": {k: v for k, v in f.items() if not k.startswith("_")}}
            self.open[(t, key)] = inc; out["incident_new"] = True
            if effect == "allow":
                inc["status"] = "auto_allowed"
                inc["basis"] = basis + [f"Matches a pattern you reviewed as genuine (reviewed at {pattern['volume']} attempts); not raised as an alert while volume stays within {allow_limit(pattern['volume'])}."]
            elif effect == "prioritize":
                inc["severity"] = SEV[min(3, SEV.index(inc["severity"]) + 1)]
                inc["basis"] = basis + ["Matches a pattern you confirmed as an attack: severity raised."]
            elif effect == "block":
                inc["severity"] = "critical"; inc["suggestion"] = {"label": "likely_attack", "reason": "Source was previously marked for blocking."}
                inc["basis"] = basis + ["Source IP was previously marked for blocking by an analyst; recommended for the blocklist."]
        self._attach(inc, ev, f, conf, volume, out)
        return out

    def _find_open(self, t: str, key: str, ev: dict):
        """Group one attack into one incident: a distributed brute force is one incident, not one per IP."""
        keys = [key]
        if t == "Brute force":
            if ev["account"]: keys.append(f"acct:{ev['account']}")
            keys.append(f"ip:{ev['ip']}")
        for k in keys:
            inc = self.open.get((t, k))
            if inc: return inc
        return None

    def _attach(self, inc: dict, ev: dict, f: dict, conf: float, volume: int, out: dict):
        inc["event_count"] += 1; inc["last_at"] = ev["t"]; inc["volume"] = max(inc["volume"], volume)
        inc["confidence"] = max(inc["confidence"], round(conf, 3))
        if ev["ip"] and ev["ip"] not in inc["source_ips"]:
            inc["source_count"] += 1
            if len(inc["source_ips"]) < 25: inc["source_ips"].append(ev["ip"])
        if inc["status"] == "auto_allowed":
            pattern = next((p for p in self.memory.patterns if p.get("id") == inc.get("pattern_id")), None)
            limit = allow_limit(pattern["volume"]) if pattern else 0
            if inc["volume"] > limit:                       # more activity than the reviewed genuine case: escalate
                inc["status"] = "open"; inc["review_effect"] = None
                inc["basis"] = out["basis"] + [f"Volume {inc['volume']} exceeds the reviewed genuine pattern (limit {limit}): escalated for review."]
                inc["suggestion"] = {"label": "likely_attack", "reason": "Activity exceeds what you previously judged genuine."}
                out.update(alert=True, state="alert", threat_type=inc["threat_type"]); out["incident_new"] = False
            else:
                out.update(threat_type=None, state="auto_allowed", confidence=None, severity=None)
        else:
            if inc["suggestion"]["label"] in ("needs_review", "likely_genuine") and inc["threat_type"] == "Brute force" and (inc["volume"] > 8 or inc["source_count"] > 1):
                inc["suggestion"] = {"label": "likely_attack", "reason": f"Failures grew to {inc['volume']} from {inc['source_count']} source(s): more than a forgotten password."}
            if inc["event_count"] >= 15: inc["severity"] = SEV[max(SEV.index(inc["severity"]), 2)]
            if inc["event_count"] >= 50: inc["severity"] = "critical"
            out["alert"] = out["incident_new"]
            out["state"] = "alert" if out["incident_new"] else "attached"
        out["severity"] = inc["severity"] if out["state"] in ("alert", "attached") else None
        out["incident"], out["incident_changed"] = inc, True
        out["review_effect"] = inc.get("review_effect")

    def _success_check(self, ev: dict, f: dict, out: dict):
        """Failures followed by a successful login from the same IP/account look like a user who finally remembered."""
        if not f["is_auth_success"]: return
        for key in (f"ip:{ev['ip']}", f"acct:{ev['account']}" if ev["account"] else None):
            inc = self.open.get(("Brute force", key)) if key else None
            if inc and inc["status"] == "open" and inc["source_count"] <= 1 and inc["volume"] <= 8:
                inc["suggestion"] = {"label": "likely_genuine", "reason": f"The same user logged in successfully after {inc['volume']} failed attempts, "
                                     "which looks like a forgotten or mistyped password."}
                out["incident"], out["incident_changed"] = inc, True
