# src/ - the application code

| Folder / file | What it does |
|---|---|
| `api.py` | The web server. Defines every URL: login, servers, live traffic, incident review, budget plan, and serves the pages in `web/`. |
| `auth_extra.py` | Forgot password (email reset link) and Sign in with Google. Plugged into `api.py`. |
| `database.py` | Creates the SQLite tables and opens connections. |
| `settings.py` | Paths, database location and model version. |
| `bootstrap.py` | First-run setup: creates the admin account, trains the model, seeds the simulated demo server. |
| `incident_store.py` | Saves detected requests and incidents to the database and builds the numbers shown on the dashboards. |
| `demo_seed.py` | Fills the demo server with simulated traffic by running it through the real detector. |
| `engine/` | The brain: detects attacks, learns from reviews, plans the budget. No web code in here. See `engine/README.md`. |
| `asset_risk/` | The vulnerability (NVD/CVE) side: import CVE data, asset risk, remediation optimiser. See `asset_risk/README.md`. |
| `tools/` | Command-line helpers: log connector, traffic simulator, one-minute demo. See `tools/README.md`. |
