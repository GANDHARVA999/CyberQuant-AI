from src.threat_detection import classify_event


def test_sqli_signature_creates_explained_alert():
    result = classify_event({"request_path": "/search?q=union%20select+password+from+users--", "response_status": 403})
    assert result["threat_type"] == "SQL injection"
    assert result["alert"] is True
    assert "signature" in result["basis"][0]


def test_brute_force_requires_repeated_failed_logins():
    event = {"request_path": "/login", "response_status": 401, "source_ip": "203.0.113.8"}
    assert classify_event(event, failed_logins_5m=4)["threat_type"] is None
    result = classify_event(event, failed_logins_5m=5)
    assert result["threat_type"] == "Brute force"
    assert "203.0.113.8" in result["basis"][0]
    assert "threshold: 5" in result["basis"][1]


def test_ddos_requires_volume_and_distribution():
    event = {"request_path": "/"}
    assert classify_event(event, requests_1m=120, unique_sources_1m=9)["threat_type"] is None
    assert classify_event(event, requests_1m=120, unique_sources_1m=10)["threat_type"] == "DDoS"
