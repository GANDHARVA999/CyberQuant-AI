# Project map: what is what

CyberQuant AI watches web traffic, tells genuine requests from brute force, SQL injection and DDoS, lets analysts review borderline cases (and learns from them), and recommends where to spend a security budget.

```
cyberquant_v2/
|-- serve.py                 Start the app for this laptop and the whole Wi-Fi
|-- run_cyberquant.bat       Windows double-click version of serve.py
|-- requirements.txt         Python packages needed
|-- .env.example             Settings template (Google, email, base URL); copy to .env
|-- Dockerfile, docker-compose.yml   Run in a container instead
|-- README.md                Start here: install, run, features
|-- src/                     Application code            -> src/README.md
|   |-- api.py               Web server and all URLs
|   |-- auth_extra.py        Forgot password and Google sign-in
|   |-- database.py          SQLite tables
|   |-- settings.py          Paths and options
|   |-- bootstrap.py         First-run setup
|   |-- incident_store.py    Saves incidents, builds dashboard numbers
|   |-- demo_seed.py         Fills the demo server
|   |-- engine/              Detection, learning, budget -> src/engine/README.md
|   |-- asset_risk/          CVE and asset risk          -> src/asset_risk/README.md
|   `-- tools/               Command-line helpers        -> src/tools/README.md
|-- web/                     Pages and styles            -> web/README.md
|-- tests/                   Automatic checks            -> tests/README.md
|-- data/                    Input data and models       -> data/README.md
|-- docs/                    Written documentation
`-- output/                  Files the demo writes (demo_report.html)
```

## One request, start to finish
1. A server's access log is sent by `src/tools/connector_agent.py` (or by the simulator) to `POST /api/v1/telemetry/{id}` in `api.py`.
2. `engine/events.py` and `engine/features.py` turn it into numbers; `engine/rules.py` and `engine/model.py` classify it; `engine/detector.py` joins requests into one incident per attack.
3. `incident_store.py` saves it. The Threat Center page (`web/threat_center.html`) shows it live.
4. An analyst marks an incident genuine or attack; `engine/review.py` remembers the pattern and applies it next time.
5. `engine/budget.py` takes the attack history and the controls in `engine/knowledge.py` and proposes the cheapest plan for the loss reduction chosen on `web/server_ai.html`.

## Login
Sign in, sign-up, sessions and password change live in `api.py`. Forgot password and Google sign-in live in `auth_extra.py`. Pages: `web/login.html`, `web/reset.html`, `web/settings.html`.

## Other documents
- `docs/architecture.md`: the pipeline in more detail.
- `docs/data_dictionary.md`: every table and column.
- `docs/server_connector.md`: how to connect a real server.
