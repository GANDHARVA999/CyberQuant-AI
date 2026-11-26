"""Small SQLite persistence layer. Schema mirrors the PostgreSQL production design."""
import sqlite3
from contextlib import contextmanager
from .settings import DB_PATH

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS vulnerabilities (
 cve_id TEXT PRIMARY KEY, description TEXT, published_at TEXT, modified_at TEXT,
 cvss_score REAL, cvss_vector TEXT, source TEXT NOT NULL, source_timestamp TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS threat_intelligence_snapshots (
 id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT REFERENCES vulnerabilities(cve_id),
 snapshot_at TEXT NOT NULL, epss_score REAL, kev_listed INTEGER, source TEXT NOT NULL,
 UNIQUE(cve_id, snapshot_at, source)
);
CREATE TABLE IF NOT EXISTS assets (
 asset_id TEXT PRIMARY KEY, asset_name TEXT NOT NULL, asset_type TEXT, internet_exposed INTEGER,
 business_criticality INTEGER CHECK(business_criticality BETWEEN 1 AND 5), estimated_loss_inr REAL,
 environment TEXT, owner_team TEXT, existing_control_strength REAL, source_type TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS asset_vulnerabilities (
 asset_id TEXT REFERENCES assets(asset_id), cve_id TEXT REFERENCES vulnerabilities(cve_id),
 finding_status TEXT NOT NULL, discovered_at TEXT, patch_available TEXT,
 PRIMARY KEY(asset_id, cve_id)
);
CREATE TABLE IF NOT EXISTS risk_assessments (
 id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT REFERENCES assets(asset_id), assessed_at TEXT NOT NULL,
 model_version TEXT NOT NULL, inherent_loss_inr REAL, residual_loss_inr REAL, event_probability REAL,
 assumptions_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS remediation_actions (
 action_id TEXT PRIMARY KEY, action_name TEXT NOT NULL, cost_inr REAL NOT NULL,
 effectiveness_estimate REAL NOT NULL, implementation_days INTEGER, prerequisites TEXT,
 affected_asset_ids TEXT NOT NULL, evidence_type TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS optimization_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, run_at TEXT NOT NULL, budget_inr REAL NOT NULL, selected_cost_inr REAL, modeled_reduction_inr REAL, assumptions_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS optimization_selections (run_id INTEGER REFERENCES optimization_runs(id), action_id TEXT REFERENCES remediation_actions(action_id), PRIMARY KEY(run_id, action_id));
CREATE TABLE IF NOT EXISTS ingestion_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT, records_seen INTEGER, records_upserted INTEGER, status TEXT NOT NULL, message TEXT);
CREATE TABLE IF NOT EXISTS model_versions (model_version TEXT PRIMARY KEY, model_type TEXT NOT NULL, created_at TEXT NOT NULL, training_data_note TEXT NOT NULL, metrics_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, event_at TEXT NOT NULL, actor TEXT NOT NULL, event_type TEXT NOT NULL,
 resource_type TEXT NOT NULL, resource_id TEXT, result TEXT NOT NULL, metadata_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scenarios (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, created_at TEXT NOT NULL, budget_inr REAL NOT NULL,
 action_ids_json TEXT NOT NULL, baseline_loss_inr REAL NOT NULL, residual_loss_inr REAL NOT NULL,
 assumptions_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
 password_hash TEXT NOT NULL, created_at TEXT NOT NULL, is_active INTEGER NOT NULL DEFAULT 1,
 login_limit_per_hour INTEGER NOT NULL DEFAULT 10 CHECK(login_limit_per_hour BETWEEN 1 AND 500)
);
CREATE TABLE IF NOT EXISTS user_sessions (
 token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), expires_at TEXT NOT NULL,
 created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS login_attempts (
 id INTEGER PRIMARY KEY AUTOINCREMENT, attempted_at TEXT NOT NULL, username TEXT NOT NULL,
 ip_address TEXT NOT NULL, success INTEGER NOT NULL, user_id INTEGER REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS monitored_servers (
 id INTEGER PRIMARY KEY AUTOINCREMENT, display_name TEXT NOT NULL, hostname TEXT NOT NULL,
 sector TEXT NOT NULL, created_at TEXT NOT NULL, last_event_at TEXT,
 agent_token_hash TEXT NOT NULL UNIQUE, is_active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS server_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, server_id INTEGER NOT NULL REFERENCES monitored_servers(id),
 event_at TEXT NOT NULL, received_at TEXT NOT NULL, request_method TEXT, request_path TEXT,
 response_status INTEGER, source_ip TEXT, threat_type TEXT, severity TEXT,
 detector_confidence REAL, metadata_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS server_budget_plans (
 id INTEGER PRIMARY KEY AUTOINCREMENT, server_id INTEGER NOT NULL REFERENCES monitored_servers(id), created_at TEXT NOT NULL,
 budget_inr REAL NOT NULL, allocated_inr REAL NOT NULL, estimated_loss_avoided_inr REAL NOT NULL, plan_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alert_feedback (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 server_event_id INTEGER NOT NULL REFERENCES server_events(id),
 user_id INTEGER NOT NULL REFERENCES users(id),
 threat_type TEXT NOT NULL,
 source_ip TEXT,
 decision TEXT NOT NULL CHECK(decision IN ('confirmed_threat','allowed_expected')),
 future_handling TEXT NOT NULL CHECK(future_handling IN ('one_time','allow_similar','prioritize_similar','block_source')),
 note TEXT,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 UNIQUE(server_event_id, user_id)
);
CREATE TABLE IF NOT EXISTS incidents (
 id INTEGER PRIMARY KEY AUTOINCREMENT, server_id INTEGER NOT NULL REFERENCES monitored_servers(id),
 threat_type TEXT NOT NULL, key TEXT NOT NULL, key_kind TEXT NOT NULL, status TEXT NOT NULL,
 severity TEXT, confidence REAL, first_at TEXT NOT NULL, last_at TEXT NOT NULL, event_count INTEGER NOT NULL,
 volume INTEGER NOT NULL DEFAULT 0, source_count INTEGER NOT NULL DEFAULT 0, source_ips_json TEXT NOT NULL DEFAULT '[]',
 account TEXT, path TEXT, basis_json TEXT NOT NULL, rules_json TEXT NOT NULL DEFAULT '[]', detection_source TEXT,
 suggestion_json TEXT NOT NULL DEFAULT '{}', review_effect TEXT, pattern_id INTEGER, head_features_json TEXT NOT NULL DEFAULT '{}',
 review_decision TEXT, review_handling TEXT, review_note TEXT, reviewed_by INTEGER, reviewed_at TEXT
);
CREATE TABLE IF NOT EXISTS review_patterns (
 id INTEGER PRIMARY KEY AUTOINCREMENT, server_id INTEGER NOT NULL REFERENCES monitored_servers(id),
 incident_id INTEGER REFERENCES incidents(id), user_id INTEGER, threat_type TEXT NOT NULL, key_kind TEXT NOT NULL,
 decision TEXT NOT NULL CHECK(decision IN ('genuine','attack')),
 handling TEXT NOT NULL CHECK(handling IN ('one_time','allow_similar','prioritize_similar','block_source')),
 source_ip TEXT, account TEXT, path TEXT, volume INTEGER NOT NULL DEFAULT 0, note TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS review_samples (
 id INTEGER PRIMARY KEY AUTOINCREMENT, server_id INTEGER NOT NULL, incident_id INTEGER,
 features_json TEXT NOT NULL, label TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incident_server_time ON incidents(server_id, last_at DESC);
CREATE INDEX IF NOT EXISTS idx_review_pattern_server ON review_patterns(server_id, threat_type);
CREATE INDEX IF NOT EXISTS idx_assessment_asset_time ON risk_assessments(asset_id, assessed_at DESC);
CREATE INDEX IF NOT EXISTS idx_snapshot_cve_time ON threat_intelligence_snapshots(cve_id, snapshot_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_event_time ON audit_events(event_at DESC);
CREATE INDEX IF NOT EXISTS idx_login_attempt_ip_time ON login_attempts(ip_address, attempted_at DESC);
CREATE INDEX IF NOT EXISTS idx_session_expiry ON user_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_server_event_time ON server_events(server_id, event_at DESC);
CREATE INDEX IF NOT EXISTS idx_server_event_threat ON server_events(server_id, threat_type, event_at DESC);
CREATE INDEX IF NOT EXISTS idx_alert_feedback_threat ON alert_feedback(user_id, threat_type, created_at DESC);
"""

@contextmanager
def connection():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()

MIGRATIONS = [   # (table, column, definition): applied to databases created by earlier versions
    ("server_events", "incident_id", "INTEGER"),
    ("monitored_servers", "asset_id", "TEXT"),
    ("users", "must_change_password", "INTEGER NOT NULL DEFAULT 0"),
]

def initialize():
    with connection() as con:
        con.executescript(SCHEMA)
        for table, column, definition in MIGRATIONS:
            if column not in {row["name"] for row in con.execute(f"PRAGMA table_info({table})")}:
                con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        con.execute("CREATE INDEX IF NOT EXISTS idx_server_event_incident ON server_events(incident_id)")
