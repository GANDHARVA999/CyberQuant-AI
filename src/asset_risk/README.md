# src/asset_risk/ - vulnerabilities and asset risk

| File | Job |
|---|---|
| `ingestion.py` | Reads the NVD CVE zip and the asset findings CSV into the database. |
| `risk.py` | Expected loss for an asset = probability x impact, with the assumptions shown. |
| `optimizer.py` | Chooses remediation actions within a budget (uses the same engine as `engine/budget.py`). |
| `threat_detection.py` | Simple rule checks for one request (SQLi, brute force, DDoS markers) used by the older API route. |
| `intrusion_model.py` | Offline benchmark on the UNSW-NB15 dataset (a research comparison, not live detection). |
