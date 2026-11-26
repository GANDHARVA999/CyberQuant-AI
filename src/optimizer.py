"""Asset-level remediation optimiser (NVD/CVE side). Uses the same exact, overlap-aware engine as the attack budget planner."""
from .engine.budget import optimise


def optimize(actions, asset_risks, budget):
    """actions: remediation rows (action_id, cost_inr, effectiveness_estimate, affected_asset_ids 'A;B', prerequisites 'X;Y').
    Several actions on one asset multiply their residual factors, never add their benefits."""
    losses = {a: {"expected_loss_inr": float(r)} for a, r in asset_risks.items()}
    controls = [{"id": a["action_id"], "cost_inr": float(a["cost_inr"]),
                 "effect": {x: float(a["effectiveness_estimate"]) for x in a["affected_asset_ids"].split(";") if x in losses},
                 "prerequisites": [p for p in (a.get("prerequisites") or "").split(";") if p]} for a in actions]
    if not losses or not controls:
        return {"selected": [], "cost_inr": 0.0, "risk_reduction_inr": 0.0}
    result = optimise(losses, controls, budget)
    chosen = {c["id"] for c in result["selected"]}
    return {"selected": [a for a in actions if a["action_id"] in chosen], "cost_inr": result["allocated_inr"],
            "risk_reduction_inr": result["loss_avoided_inr"]}
