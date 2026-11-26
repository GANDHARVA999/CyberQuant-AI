# tests/ - automatic checks

Run everything with `pytest -q` (the first run takes about a minute because it trains a small model).

| File | Checks |
|---|---|
| `test_engine.py` | Detection rules, features, review learning, budget optimiser. |
| `test_incident_store.py` | Saving incidents, log parsing, demo seeding. |
| `test_api.py` | Login, sign-up, forgot/reset password, Google sign-in, permissions. |
| `test_investment.py` | Investment category logic. |
| `test_risk.py` | Asset risk and remediation optimiser. |
| `test_ingestion.py` | NVD import. |
| `test_threat_detection.py` | Per-request rule checks. |
| `conftest.py` | Shared test setup (a small fast model). |
