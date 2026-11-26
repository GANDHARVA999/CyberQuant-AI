"""Where things live: project folder, data folder, database file, model version. Paths can be overridden with environment variables."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
STARTER = DATA / "starter_pack" / "cyber_risk_dataset_starter_pack"
DB_PATH = Path(os.getenv("CYBERQUANT_DB", ROOT / "cyber_risk.db"))
INGEST_DIR = Path(os.getenv("CYBERQUANT_INGEST_DIR", DATA / "raw")).resolve()   # admin import paths must live here
MODEL_VERSION = "benchmark-risk-v1"
