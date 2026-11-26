"""Load the provided synthetic templates; all rows retain their synthetic provenance."""
import csv, json, os, hashlib, secrets
from datetime import datetime, timezone, timedelta
from .database import connection, initialize
from .settings import STARTER, MODEL_VERSION

def bootstrap_templates():
    initialize()
    with connection() as con:
        for row in csv.DictReader((STARTER / "asset_inventory_template.csv").open(encoding="utf-8")):
            con.execute("""INSERT INTO assets VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(asset_id) DO UPDATE SET asset_name=excluded.asset_name""",
             (row["asset_id"],row["asset_name"],row["asset_type"],int(row["internet_exposed"]),int(row["business_criticality"]),float(row["estimated_loss_inr"]),row["environment"],row["owner_team"],float(row["existing_control_strength"]),"synthetic_template",))
        for row in csv.DictReader((STARTER / "remediation_actions_template.csv").open(encoding="utf-8")):
            con.execute("INSERT INTO remediation_actions VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(action_id) DO UPDATE SET action_name=excluded.action_name", (row["action_id"],row["action_name"],float(row["cost_inr"]),float(row["effectiveness_estimate"]),int(row["implementation_days"]),row["prerequisites"],row["affected_asset_ids"],row["evidence_type"]))
        con.execute("INSERT OR REPLACE INTO model_versions VALUES(?,?,?,?,?)", (MODEL_VERSION,"benchmark_rule_based",datetime.now(timezone.utc).isoformat(),"No independent exploitation model is trained. EPSS can be stored as an external benchmark score.",json.dumps({"metrics_status":"not_applicable: no defensible historical outcome labels supplied"})))
        # A local first-run account. Deployments must provide both environment variables.
        username = os.getenv("CYBERQUANT_INITIAL_USERNAME", "admin")
        password = os.getenv("CYBERQUANT_INITIAL_PASSWORD", "ChangeMe!123")
        if not con.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            salt = secrets.token_bytes(16)
            digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
            default_password = "CYBERQUANT_INITIAL_PASSWORD" not in os.environ        # shipped default: force a change at first sign-in
            con.execute("INSERT INTO users(username,password_hash,created_at,must_change_password) VALUES(?,?,?,?)", (username, f"{salt.hex()}${digest.hex()}", datetime.now(timezone.utc).isoformat(), int(default_password)))
        # Demo telemetry is SIMULATED traffic run through the real detection engine; it is never live server evidence.
        demo = con.execute("SELECT id FROM monitored_servers WHERE hostname='demo.cyberquant.local'").fetchone()
        if not demo:
            from .engine.model import Classifier
            from .demo_seed import seed_demo
            token_hash = hashlib.sha256(b"demo-token-not-for-use").hexdigest()
            cur = con.execute("INSERT INTO monitored_servers(display_name,hostname,sector,created_at,agent_token_hash,last_event_at) VALUES(?,?,?,?,?,?)", ("Demo Commerce API (simulated)", "demo.cyberquant.local", "E-commerce (demo)", datetime.now(timezone.utc).isoformat(), token_hash, datetime.now(timezone.utc).isoformat()))
            seed_demo(con, cur.lastrowid, Classifier())
        demo = con.execute("SELECT id FROM monitored_servers WHERE hostname='demo.cyberquant.local'").fetchone()
        if demo:
            from .demo_seed import ensure_history
            ensure_history(con, demo[0])

if __name__ == "__main__": bootstrap_templates()
