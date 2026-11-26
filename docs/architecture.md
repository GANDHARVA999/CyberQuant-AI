# Architecture

```text
server access log / agent ──► POST /api/v1/telemetry/{id}
        │
        ▼
 features (60 s / 300 s sliding windows per server)         src/engine/features.py
        │
        ├─► rules: SQLi signatures, single-IP / distributed / stuffing brute force, concentrated DDoS   src/engine/rules.py
        └─► ML: random forest, 4 classes, 18 features                                           src/engine/model.py
        ▼
 fusion + incident grouping (one attack = one incident)       src/engine/detector.py
        │   ├─ learned review patterns: auto-allow / prioritise / block        src/engine/review.py
        │   └─ "likely genuine" when failures end in a successful login
        ▼
 SQLite: server_events, incidents, review_patterns, review_samples        src/incident_store.py
        │
        ├─► analyst review queue (/threat-center) ──► review_samples ──► POST /api/v1/model/retrain
        └─► budget planner: incidents × success rate × impact × CVE exposure ──► exact optimiser   src/engine/budget.py, cve_link.py
NVD CVE feed ─► vulnerabilities ─► risk engine (assets) and attack-to-CVE linkage
```

The engine modules are framework-free (no FastAPI imports), so they are unit-tested directly; `api.py` is a thin layer over them.
