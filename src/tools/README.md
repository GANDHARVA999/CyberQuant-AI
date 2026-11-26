# src/tools/ - command-line helpers

Run from the project folder with the virtual environment active.

| File | Command | Use |
|---|---|---|
| `demo.py` | `python -m src.tools.demo` | One-minute end-to-end demo with no server; writes `output/demo_report.html`. |
| `connector_agent.py` | `python -m src.tools.connector_agent --url ... --server-id N --token ... --log /var/log/nginx/access.log --follow` | Reads a real web server's access log and sends it to CyberQuant. |
| `simulate_traffic.py` | `python -m src.tools.simulate_traffic --url http://127.0.0.1:8000 --server-id 2 --token ...` | Sends simulated traffic to a running CyberQuant. |
