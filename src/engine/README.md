# src/engine/ - detection, learning and budget logic

Pure Python, no web framework. Data flows top to bottom.

| File | Job |
|---|---|
| `events.py` | Cleans one raw request record into an event. |
| `features.py` | Counts what each IP/user did in the last 60 s and 300 s (18 numbers the model reads). |
| `rules.py` | Readable rules: SQL injection patterns, brute-force and DDoS thresholds. Each hit carries its evidence. |
| `model.py` | Random-forest model: Normal / Brute force / SQL injection / DDoS. Trains on simulated traffic. |
| `detector.py` | Combines rules and model, groups requests into one incident per attack, suggests "likely genuine". |
| `review.py` | Remembers what analysts decided (same user, same IP, same pattern) so it learns. |
| `budget.py` | Picks the controls that cut the most expected loss for the money, within the budget. |
| `knowledge.py` | Researched facts behind the plan: what each attack damages, which controls exist, typical costs. |
| `cve_link.py` | Links attack types to the CVE weaknesses that let them succeed (raises the exposure score). |
| `geo.py` | Offline, approximate region of an IP address. |
| `simulator.py` | Makes realistic fake traffic (genuine, forgetful users, brute force, SQLi, DDoS) with correct labels. |
