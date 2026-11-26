# Data dictionary and provenance

| Entity | Key fields | Provenance |
|---|---|---|
| vulnerabilities | CVE ID, CVSS, description | Observed NVD CVE 2.0 local ZIP |
| threat_intelligence_snapshots | EPSS, KEV, timestamp | External snapshot; null means unavailable, not zero |
| assets | criticality, loss, controls | Synthetic starter template |
| remediation_actions | cost, effectiveness | Illustrative starter-template assumptions |
| risk_assessments | probability, inherent/residual loss | Reproducible model output plus assumptions |
| server_events | request metadata, classification, confidence, detection basis | Connected collector telemetry; synthetic events are explicitly labelled |

Expected loss is `event probability × financial impact`. EPSS, when loaded, is kept as an external benchmark score. If absent, the demo applies a visibly documented CVSS-based ranking proxy; it is not an exploitation prediction or calibrated probability.

| incidents | type, key, status, severity, confidence, suggestion, head features | Detection engine output; one attack = one incident |
| review_patterns | type, decision, handling, source, endpoint, reviewed volume | Analyst decisions that shape future triage |
| review_samples | feature vector, label | Analyst-labelled examples for model retraining |

## Detection and review

Server telemetry (metadata only) is classified as genuine, brute force, SQL injection or DDoS by rules plus a random-forest model (see README). Incidents move through
`open` -> `reviewed_genuine` / `reviewed_attack` (or `auto_allowed` when they match a reviewed genuine pattern within its volume tolerance). A match is evidence for investigation, not proof of a successful attack. Request bodies and credentials must never be collected.
