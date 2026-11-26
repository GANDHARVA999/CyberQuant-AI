# CyberQuant AI: Continuous Cyber Risk Quantification and Investment Optimization

SDG 9 (Industry, Innovation and Infrastructure). A user connects a server; the platform shows every incoming request, classifies it as **genuine** or one of
three attacks (**brute force, SQL injection, DDoS**), lets an analyst review borderline cases (and learns from the decision), and then shows
**how to spend the security budget** to cut the most expected loss for the least money.

## Quick start (Windows PowerShell)

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m src.demo                     # 1-minute end-to-end demo -> output\demo_report.html (no server needed)
python -m src.bootstrap                # first run trains the model (~15 s) and seeds a simulated demo server
uvicorn src.api:app --reload           # open http://127.0.0.1:8000  (sign in with admin / Gandharva, or create your own account on the sign-in page)
pytest -q                              # 30+ tests
```

## Forgot password and Sign in with Google

Both are optional and switch on from a local `.env` file (copy `.env.example` to `.env`, which is git-ignored).

**Forgot password.** On the sign-in page, choose *Forgot password?* and enter the email or user ID. A single-use link, valid for 30 minutes, opens `/reset-password`. Every active session of that account is signed out when the password changes. Without mail settings the link is printed in the server console and shown on screen, for local use only. To send real email, set the `CYBERQUANT_SMTP_*` values (for Gmail, create an app password in your Google account security settings).

**Sign in with Google.**
1. In Google Cloud Console, open *APIs & Services > Credentials > Create credentials > OAuth client ID*, type *Web application*.
2. Add this authorised redirect URI exactly: `http://127.0.0.1:8000/api/v1/auth/google/callback` (use your own address in production, with `https`).
3. Put the client ID and secret in `.env` as `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`, then restart.

The first Google sign-in with a verified email either signs in the existing account with that email or creates a new account. Users can also link Google from *Settings*. The server checks the state value, PKCE, the token audience and issuer, and that Google verified the email.

## How it answers the project brief

| Requirement | Where |
|---|---|
| User connects a server and sees requests | `/servers` (token) + `src/connector_agent.py` (tails nginx/Apache logs); `/threat-center` shows live requests per minute, genuine vs attack |
| Genuine or attack? Which attack? | `src/engine`: rules + random-forest ML, 4 classes, one incident per attack |
| Genuine users who mistyped a password | Incidents get a suggestion (likely genuine / needs review / likely attack); failures followed by a successful login become "likely genuine" |
| Analyst review and categorisation for the future | `/threat-center` review queue. "Same IP, 5 failures, genuine" is remembered per source and endpoint; it is auto-allowed next time, but re-alerts if the volume grows (e.g. 40 failures) or a different IP appears. Attack decisions can raise severity or add the source(s) to a recommended blocklist. Reviews are also saved as labelled examples for `POST /api/v1/model/retrain` |
| 50 different IPs against one account | Detected as a distributed brute force, grouped as one incident |
| Budget: stop attacks with minimum spend | `/server-ai`: exact optimiser over security controls (overlap-aware), spend-vs-protection curve, cheapest plan for a target reduction, CVE exposure from linked assets |

## Detection design

- **Features** (18, sliding 60 s/300 s windows): per-IP request and failed-login counts, distinct accounts per IP, distinct IPs per account, server request volume, unique IPs, path/user-agent concentration, SQL-signature hits, special-character ratio, status classes.
- **Rules** are explainable and configurable (`src/engine/rules.py`). **ML** (`src/engine/model.py`) is a random forest trained on *simulated* labelled traffic that includes hard negatives (forgetful users, offices behind one IP, genuine traffic surges, searches containing quotes). Final confidence combines both; when they disagree the incident is flagged for review.
- **DDoS** needs volume, many IPs *and* concentrated traffic, so a genuine sales surge (diverse paths and browsers) is not flagged.
- **Held-out synthetic benchmark** (`python -m src.engine.model`): ML recall DDoS 0.99, brute force 0.98, SQLi 1.00 at 0.8% false positives, versus rules-only DDoS recall 0.46 and SQLi 0.89. **These numbers measure simulated traffic and are not a production detection rate.** Train on real labelled logs (or CIC-IDS2017-style data converted to these features) before relying on them.
- The earlier UNSW-NB15 flow benchmark remains (`/detections`) as a separate, offline experiment.

## Budget model

Expected annual loss per attack = incidents per year x success probability x impact per successful incident x CVE exposure multiplier. Controls (WAF, parameterised queries, rate limiting, MFA, CAPTCHA, CDN scrubbing, monitoring, IP blocking with a prerequisite) reduce it multiplicatively. The best combination within budget is found by exact enumeration (up to 20 controls; greedy beyond). **Impacts, success rates, control costs and effectiveness are illustrative assumptions you should replace**; the UI lets you edit impacts and success rates. Incidents you mark genuine, and auto-allowed ones, are excluded from risk.

## Limits to know

- Simulated data stands in for real traffic until a server is connected; the demo server is labelled simulated.
- Detection state (sliding windows) is in memory; after a restart open incidents reload but windows rebuild from new traffic.
- Throughput is roughly 200 events/second per process (one forest call per interesting event); batch more aggressively or add workers for large sites.
- A web server cannot see remote MAC addresses, so repeat-device detection uses account and IP; add a device fingerprint to `metadata` if you collect one.
- The platform recommends blocks; your connector or firewall must enforce them.

## Workspace modules

The single-page SOC workspace now uses the shared FastAPI and SQLite data store for these modules:

- **Overview:** persisted asset inventory, linked-finding counts, calculated expected loss, latest allocation, and briefing.
- **Threat Center:** searchable table of locally ingested NVD CVE records. An NVD CVE is not treated as an affected asset unless a validated finding is imported.
- **Asset Intelligence:** the supplied synthetic asset inventory and its ownership/exposure context.
- **AI Risk Analysis:** saves transparent benchmark risk assessments. It does not present an untrained XGBoost model as real.
- **Investment Optimizer:** saves selections and category-level budget utilization from each optimizer run.
- **Scenario Lab:** persists non-destructive, temporary simulations.
- **Activity & Audit:** reads append-only local application audit events for assessments, scenarios, and optimizer runs.
- **Integrations & Settings:** reads source status and actual ingestion-run history.
- **Protected analyst access:** password-hashed sign-in, HttpOnly sessions, protected dashboard/API routes, and a configurable rolling per-IP login-attempt limit at `/settings`.
- **Analyst-reviewed threat alerts:** clicking a threat-type bar reveals the triggering source IP and rule basis. Analysts can confirm or allow an alert and set a future-handling preference; those labels feed a transparent online Bayesian calibration for later triage. This records a review preference only—it does not configure a firewall or automatically block traffic.

The full supplied **2025 NVD feed** has been ingested locally (45,397 observed records). EPSS and CISA KEV remain `not_loaded` because snapshots were not supplied; their absence is never interpreted as zero risk.

## Run locally

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m src.bootstrap
uvicorn src.api:app --reload
```

Open `http://127.0.0.1:8000`. The dashboard begins with **synthetic** template assets/actions, as labeled.

### Populate the supplied demo data

The provided NVD archives are real vulnerability data. The starter-pack assets are synthetic and its original finding CSV contains placeholders. To make every module visibly functional, `data/demo_synthetic_asset_findings.csv` provides an explicitly synthetic association from those demo assets to real NVD CVE records. Import it only for a classroom demonstration; it does not claim that those CVEs affect a real organization.

### Run from VS Code

Install the Microsoft **Python** extension, select `.venv\\Scripts\\python.exe` as the interpreter, then open **Run and Debug** and choose **Run CyberQuant dashboard**. Press `F5`; VS Code will start the app with auto-reload at `http://127.0.0.1:8000`.

### Share on your local network

The included VS Code launch profile binds to `0.0.0.0`, so other devices on the same trusted LAN can open `http://YOUR_COMPUTER_IP:8000`. Before using it, copy `.env.example` to `.env` and set `CYBERQUANT_INITIAL_USERNAME` and a unique `CYBERQUANT_INITIAL_PASSWORD` before the first run. The initial account is created only when no user exists. The default local-only account is `admin` / `ChangeMe!123`; change it immediately in `/settings` and never expose it on a network. The login-attempt limit can also be changed at `/settings`. Allow Python through the Windows **Private network** firewall prompt, not public networks.

### Ingest the supplied NVD feeds

Use the authorized API only in a trusted local environment (the endpoint must be protected in a deployment):

```powershell
# copy the ZIP into data\raw first (admin imports are restricted to that folder, or set CYBERQUANT_INGEST_DIR)
Invoke-RestMethod -Method Post http://127.0.0.1:8000/api/v1/admin/ingest/nvd -ContentType application/json -Body '{"zip_path":"C:\\...\\CYBER ATTACK PREVENT\\data\\raw\\nvdcve-2.0-2025.json.zip"}'
```

The supplied asset-finding template contains placeholder CVE IDs. Replace those with CVEs that actually affect the organization before they can be risk-scored from NVD. Do not represent template financial losses, costs, or effectiveness as observed data.

After NVD ingestion, import a corrected organization finding export with the same columns as `asset_vulnerabilities_template.csv`:

```powershell
Invoke-RestMethod -Method Post http://127.0.0.1:8000/api/v1/admin/import-findings -ContentType application/json -Body '{"csv_path":"C:\\path\\to\\validated_asset_findings.csv"}'
```

Rows for an unknown CVE or asset are rejected and counted, so template placeholders cannot quietly become risk findings.

## Tests

```powershell
pytest -q
```

## SDG 9 evidence plan

| SDG 9 contribution | Measurable demonstration |
|---|---|
| Resilient infrastructure | Critical-asset exposure and unresolved high-priority findings |
| Innovation | Compare CVSS-only, EPSS, and contextual ranking once snapshots are loaded |
| Resource efficiency | Modeled residual-risk reduction per ₹ of budget |
| Technology adoption | Ingestion freshness and reassessment turnaround time |

See [architecture](docs/architecture.md) and the [data dictionary](docs/data_dictionary.md). The source templates are retained under `data/starter_pack`.
