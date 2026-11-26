import json, zipfile
from pathlib import Path
from src.asset_risk.ingestion import ingest_nvd_zip
from src.database import initialize, connection

def test_nvd_ingestion_is_idempotent(monkeypatch):
    work = Path("data/raw/test-fixture")
    work.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("src.database.DB_PATH", work / "test.db")
    initialize()
    payload={"vulnerabilities":[{"cve":{"id":"CVE-2099-0001","published":"2099-01-01","lastModified":"2099-01-02","descriptions":[{"lang":"en","value":"test"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":8.1,"vectorString":"CVSS:3.1/AV:N"}}]}}}]}
    archive=work/'nvd.zip'
    with zipfile.ZipFile(archive,'w') as z:z.writestr('nvd.json',json.dumps(payload))
    assert ingest_nvd_zip(archive)["upserted"] == 1
    assert ingest_nvd_zip(archive)["upserted"] == 1
    with connection() as con: assert con.execute("SELECT count(*) FROM vulnerabilities WHERE cve_id='CVE-2099-0001'").fetchone()[0] == 1
