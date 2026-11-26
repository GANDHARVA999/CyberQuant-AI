# Connecting a server

1. Open **/servers**, register your server, and copy the one-time connector token.
2. On the server, run the connector agent (standard library only, Python 3.9+). It tails an nginx/Apache *combined* access log:

```bash
python -m src.connector_agent --url https://YOUR-CYBERQUANT-HOST --server-id 2 --token <TOKEN> \
       --log /var/log/nginx/access.log --follow --account-regex 'user=([^&]+)' --salt <secret>
```

Sent per request: timestamp, method, path+query, status, source IP, user-agent, and optionally a **salted hash** of the account name
(needed to spot many IPs attacking one account). Never sent: request bodies, cookies, Authorization headers, passwords.
Any other source can post the same JSON itself:

```
POST /api/v1/telemetry/{server_id}      X-Agent-Token: {token}      (up to 1,000 events per call)
{"events":[{"event_at":"2026-10-22T08:30:00Z","request_method":"POST","request_path":"/login","response_status":401,
            "source_ip":"203.0.113.8","metadata":{"user_agent":"Mozilla/5.0","account":"<hashed account id>"}}]}
```

The platform classifies every request (genuine, brute force, SQL injection or DDoS). A `threat_type` supplied by the collector is kept only as an
advisory hint; the engine decides. Open **/threat-center** to see live traffic and review incidents.

**Blocklist:** sources an analyst marks "recommend blocking" are available to your connector at `GET /api/v1/telemetry/{server_id}/blocklist`
(same token). CyberQuant never changes your firewall; your connector or firewall must enforce the list.

**Try it without a server:** `python -m src.simulate_traffic --url http://127.0.0.1:8000 --server-id 2 --token <TOKEN>` sends simulated traffic.
