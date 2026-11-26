"""NVD 2.0 ZIP parser with explicit provenance and idempotent upserts."""
import json, zipfile
import csv
from datetime import datetime, timezone
from pathlib import Path
from .database import connection

def now(): return datetime.now(timezone.utc).isoformat()

def _cvss(cve):
    metrics = cve.get("metrics", {})
    for name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(name, [])
        if rows:
            d = rows[0].get("cvssData", {})
            return d.get("baseScore"), d.get("vectorString")
    return None, None

def ingest_nvd_zip(path: str | Path, limit: int | None = None):
    """Read local NVD feed safely; malformed individual records are skipped and counted."""
    path = Path(path)
    started = now(); seen = inserted = skipped = 0
    with connection() as con:
        run = con.execute("INSERT INTO ingestion_runs(source,started_at,status) VALUES (?,?,?)", (f"NVD ZIP: {path.name}", started, "running"))
        run_id = run.lastrowid
        try:
            with zipfile.ZipFile(path) as archive:
                members = [x for x in archive.namelist() if x.endswith(".json")]
                if len(members) != 1: raise ValueError("Expected exactly one JSON file in NVD archive")
                with archive.open(members[0]) as raw:
                    document = json.load(raw)
            for item in document.get("vulnerabilities", []):
                if limit is not None and seen >= limit: break
                seen += 1
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                if not cve_id: skipped += 1; continue
                descriptions = cve.get("descriptions", [])
                desc = next((x.get("value") for x in descriptions if x.get("lang") == "en"), None)
                score, vector = _cvss(cve)
                con.execute("""INSERT INTO vulnerabilities(cve_id,description,published_at,modified_at,cvss_score,cvss_vector,source,source_timestamp)
                VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(cve_id) DO UPDATE SET description=excluded.description,modified_at=excluded.modified_at,cvss_score=excluded.cvss_score,cvss_vector=excluded.cvss_vector,source_timestamp=excluded.source_timestamp""",
                (cve_id, desc, cve.get("published"), cve.get("lastModified"), score, vector, "NVD CVE 2.0 local feed", now()))
                inserted += 1
            con.execute("UPDATE ingestion_runs SET finished_at=?,records_seen=?,records_upserted=?,status=?,message=? WHERE id=?", (now(), seen, inserted, "success", f"skipped={skipped}", run_id))
        except (OSError, ValueError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
            con.execute("UPDATE ingestion_runs SET finished_at=?,records_seen=?,records_upserted=?,status=?,message=? WHERE id=?", (now(), seen, inserted, "failed", str(exc), run_id)); raise
    return {"seen": seen, "upserted": inserted, "skipped": skipped}

def import_asset_findings(path: str | Path):
    """Import only findings whose CVE and asset already exist; reject placeholders explicitly."""
    path = Path(path); accepted = rejected = 0
    with path.open(encoding="utf-8", newline="") as source, connection() as con:
        required = {"asset_id", "cve_id", "finding_status", "discovered_at", "patch_available"}
        if not required.issubset(set((csv.DictReader(source).fieldnames or []))):
            raise ValueError("Finding CSV is missing required columns")
    with path.open(encoding="utf-8", newline="") as source, connection() as con:
        for row in csv.DictReader(source):
            exists = con.execute("SELECT 1 FROM assets WHERE asset_id=?", (row["asset_id"],)).fetchone() and con.execute("SELECT 1 FROM vulnerabilities WHERE cve_id=?", (row["cve_id"],)).fetchone()
            if not exists: rejected += 1; continue
            con.execute("""INSERT INTO asset_vulnerabilities VALUES(?,?,?,?,?) ON CONFLICT(asset_id,cve_id) DO UPDATE SET finding_status=excluded.finding_status,patch_available=excluded.patch_available""", (row["asset_id"],row["cve_id"],row["finding_status"],row["discovered_at"],row["patch_available"]))
            accepted += 1
    return {"accepted":accepted,"rejected":rejected,"note":"Rejected rows reference an unknown asset or CVE; no placeholder CVEs were silently accepted."}
