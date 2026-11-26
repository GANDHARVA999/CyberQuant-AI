from src.asset_risk.risk import calculate_asset_risk
from src.asset_risk.optimizer import optimize

def asset(): return {"internet_exposed":1,"business_criticality":5,"estimated_loss_inr":1_000_000,"existing_control_strength":.4}

def test_expected_loss_is_controlled_and_positive():
    result=calculate_asset_risk(asset(),[{"epss_score":.2,"cvss_score":9}])
    assert 0 < result.residual_loss_inr < result.inherent_loss_inr < 1_000_000
    assert result.probability > .2

def test_missing_finding_has_zero_risk():
    assert calculate_asset_risk(asset(),[]).residual_loss_inr == 0

def test_optimizer_respects_budget_and_handles_overlap():
    actions=[{"action_id":"a","cost_inr":100,"effectiveness_estimate":.5,"affected_asset_ids":"x","prerequisites":""},{"action_id":"b","cost_inr":100,"effectiveness_estimate":.5,"affected_asset_ids":"x","prerequisites":""}]
    found=optimize(actions,{"x":1000},200)
    assert found["cost_inr"] == 200
    assert found["risk_reduction_inr"] == 750  # 1-(.5*.5), not 100% additive
