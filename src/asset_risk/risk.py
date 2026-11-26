"""Transparent benchmark risk engine; does not claim independent ML probabilities."""
from dataclasses import dataclass

@dataclass
class RiskResult:
    probability: float
    inherent_loss_inr: float
    residual_loss_inr: float
    assumptions: dict

def calculate_asset_risk(asset: dict, vulnerabilities: list[dict]) -> RiskResult:
    """Expected loss = probability × impact. Inputs lacking EPSS use a disclosed CVSS proxy."""
    if not vulnerabilities:
        return RiskResult(0.0, 0.0, 0.0, {"note": "No open, normalized vulnerabilities linked to asset."})
    probabilities = []
    for vuln in vulnerabilities:
        epss = vuln.get("epss_score")
        if epss is None:
            # Deliberately an illustrative ranking proxy, not a calibrated probability.
            epss = min((float(vuln.get("cvss_score") or 0) / 10) * 0.10, 0.10)
        probabilities.append(float(epss))
    # Union assumes independent routes only as a conservative demo approximation.
    base = 1.0
    for p in probabilities: base *= (1 - max(0, min(p, .99)))
    event_probability = 1 - base
    exposure = 1.25 if asset["internet_exposed"] else 1.0
    criticality = 0.6 + 0.1 * float(asset["business_criticality"])
    control = max(0, min(float(asset["existing_control_strength"] or 0), .95))
    adjusted = min(.99, event_probability * exposure * criticality)
    impact = float(asset["estimated_loss_inr"] or 0)
    inherent = adjusted * impact
    residual = inherent * (1 - control)
    return RiskResult(adjusted, inherent, residual, {"formula": "expected loss = event probability × estimated impact", "probability_input": "EPSS when available; CVSS-derived illustrative proxy otherwise", "correlation_warning": "multiple CVEs are combined as independent attack routes for demo only", "control_strength_source": "synthetic asset template"})
