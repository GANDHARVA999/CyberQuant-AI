"""Budget optimisation: choose security controls to minimise expected loss within a budget.

Expected annual loss per attack type = incidents/year x success probability x impact x exposure multiplier (from linked CVEs).
Several controls aimed at the same attack combine multiplicatively (residual = product of (1 - effectiveness)), so
overlap is never double-counted. For catalogues up to 20 controls the optimum is found exactly by vectorised enumeration;
larger catalogues fall back to a greedy marginal-benefit heuristic (flagged in the result).
Costs follow published list prices (see knowledge.py); effectiveness values and impacts are ASSUMPTIONS informed by cited evidence - replace with your own figures.
"""
from __future__ import annotations
import numpy as np

DEFAULT_IMPACT_INR = {"SQL injection": 1_500_000, "Brute force": 400_000, "DDoS": 800_000}   # loss per SUCCESSFUL incident
DEFAULT_SUCCESS_PROB = {"SQL injection": 0.15, "Brute force": 0.05, "DDoS": 0.30}            # share of detected incidents that succeed
from .knowledge import CONTROLS as DEFAULT_CONTROLS   # researched catalogue: providers, published prices, evidence
MAX_EXACT = 20


def expected_losses(incidents_per_period: dict, period_days: float, impact: dict | None = None, exposure: dict | None = None,
                    success: dict | None = None) -> dict:
    """Annualised expected loss per attack type. period_days is the observation window the counts came from."""
    impact = {**DEFAULT_IMPACT_INR, **(impact or {})}; exposure = exposure or {}; success = {**DEFAULT_SUCCESS_PROB, **(success or {})}
    out = {}
    for attack, n in incidents_per_period.items():
        if attack not in impact: continue
        per_year = n / max(period_days, 1e-9) * 365
        out[attack] = {"incidents_per_year": per_year, "success_probability": success[attack], "impact_inr": impact[attack],
                       "exposure_multiplier": exposure.get(attack, 1.0),
                       "expected_loss_inr": per_year * success[attack] * impact[attack] * exposure.get(attack, 1.0)}
    return out


def _subset_matrix(n: int) -> np.ndarray:
    idx = np.arange(1 << n, dtype=np.uint32)
    return ((idx[:, None] >> np.arange(n, dtype=np.uint32)) & 1).astype(np.uint8)


def optimise(losses: dict, controls: list[dict] | None = None, budget: float = 0, target_reduction: float | None = None) -> dict:
    controls = controls or DEFAULT_CONTROLS
    attacks = list(losses); base = np.array([losses[a]["expected_loss_inr"] for a in attacks], dtype=float)
    n, cost = len(controls), np.array([c["cost_inr"] for c in controls], dtype=float)
    logs = np.array([[np.log1p(-min(c["effect"].get(a, 0.0), 0.999)) for a in attacks] for c in controls])
    pos = {c["id"]: i for i, c in enumerate(controls)}
    exact = n <= MAX_EXACT
    if exact:
        bits = _subset_matrix(n); feasible = np.ones(len(bits), dtype=bool)
        for i, c in enumerate(controls):
            for pre in c.get("prerequisites", []):
                feasible &= (bits[:, i] == 0) | (bits[:, pos[pre]] == 1)
        total_cost = bits @ cost
        residual = np.exp(bits @ logs) * base                      # per subset per attack
        reduction = base.sum() - residual.sum(axis=1)
        ok = feasible & (total_cost <= budget + 1e-9)
        best = int(np.argmax(np.where(ok, reduction - 1e-9 * total_cost, -np.inf)))   # tie -> cheaper
        chosen = bits[best]
        # efficient frontier: best reduction achievable at each cost level
        order = np.argsort(np.where(feasible, total_cost, np.inf), kind="stable"); frontier, top = [], -1.0
        for k in order:
            if not feasible[k]: break
            if reduction[k] > top + 1e-6:
                top = float(reduction[k]); frontier.append({"cost_inr": float(total_cost[k]), "loss_avoided_inr": top,
                                                           "controls": [controls[i]["id"] for i in range(n) if bits[k, i]]})
        min_cost_plan = None
        if target_reduction is not None and base.sum() > 0:
            need = target_reduction * base.sum(); cand = feasible & (reduction >= need - 1e-9)
            if cand.any():
                k = int(np.argmin(np.where(cand, total_cost, np.inf)))
                min_cost_plan = {"target_reduction": target_reduction, "cost_inr": float(total_cost[k]), "loss_avoided_inr": float(reduction[k]),
                                 "controls": [controls[i]["id"] for i in range(n) if bits[k, i]]}
    else:                                                          # greedy fallback
        chosen = np.zeros(n, dtype=np.uint8); spent = 0.0
        def red(sel): return base.sum() - (np.exp(sel @ logs) * base).sum()
        while True:
            gains = [((red(np.where(np.arange(n) == i, 1, chosen)) - red(chosen)) / cost[i], i) for i in range(n)
                     if not chosen[i] and spent + cost[i] <= budget and all(chosen[pos[p]] for p in controls[i].get("prerequisites", []))]
            gains = [g for g in gains if g[0] > 0]
            if not gains: break
            _, i = max(gains); chosen[i] = 1; spent += cost[i]
        frontier, min_cost_plan = [], None
    sel_cost = float(chosen @ cost); res = np.exp(chosen @ logs) * base
    selected = [{**controls[i], "marginal_note": None} for i in range(n) if chosen[i]]
    per_attack = [{"attack": a, "baseline_loss_inr": float(base[j]), "residual_loss_inr": float(res[j]),
                   "loss_avoided_inr": float(base[j] - res[j]), "reduction_pct": float(1 - res[j] / base[j]) if base[j] else 0.0,
                   **{k: losses[a].get(k) for k in ("incidents_per_year", "success_probability", "impact_inr", "exposure_multiplier")}} for j, a in enumerate(attacks)]
    avoided = float(base.sum() - res.sum())
    return {"solver": "exact enumeration" if exact else "greedy heuristic (catalogue > 20 controls)", "budget_inr": float(budget),
            "allocated_inr": sel_cost, "unallocated_inr": float(budget - sel_cost), "baseline_loss_inr": float(base.sum()),
            "residual_loss_inr": float(res.sum()), "loss_avoided_inr": avoided, "reduction_pct": avoided / base.sum() if base.sum() else 0.0,
            "return_per_rupee": avoided / sel_cost if sel_cost else 0.0, "selected": selected, "per_attack": per_attack,
            "frontier": frontier, "min_cost_for_target": min_cost_plan,
            "assumption_note": "Impacts, control costs and effectiveness are illustrative assumptions; replace them with your organisation's figures."}
