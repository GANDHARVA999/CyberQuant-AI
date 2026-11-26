"""Train a clearly scoped offline network-flow intrusion detector on UNSW-NB15."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
import joblib
import pandas as pd
from pandas.api.types import is_numeric_dtype
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.linear_model import LogisticRegression
from ..settings import ROOT

DATASET_URL = "https://research.unsw.edu.au/projects/unsw-nb15-dataset"
DATASET_CITATION = "Moustafa, N. and Slay, J. (2015), UNSW-NB15."
DATA_DIR = ROOT / "data" / "unsw_nb15"
MODEL_DIR = ROOT / "data" / "models"
MODEL_PATH = MODEL_DIR / "unsw_nb15_intrusion_detector.joblib"
REPORT_PATH = MODEL_DIR / "unsw_nb15_report.json"

def train():
    train_frame = pd.read_csv(DATA_DIR / "UNSW_NB15_training-set.csv")
    test_frame = pd.read_csv(DATA_DIR / "UNSW_NB15_testing-set.csv")
    drop = ["id", "label", "attack_cat"]
    features = [column for column in train_frame.columns if column not in drop]
    categorical = [column for column in features if not is_numeric_dtype(train_frame[column])]
    numeric = [column for column in features if column not in categorical]
    transformer = ColumnTransformer([
        ("numeric", Pipeline([("impute", SimpleImputer(strategy="median")), ("scale", StandardScaler())]), numeric),
        ("categorical", Pipeline([("impute", SimpleImputer(strategy="most_frequent")), ("encode", OneHotEncoder(handle_unknown="ignore"))]), categorical),
    ])
    model = Pipeline([("features", transformer), ("classifier", LogisticRegression(max_iter=500, class_weight="balanced", n_jobs=-1))])
    model.fit(train_frame[features], train_frame["label"])
    predicted = model.predict(test_frame[features])
    probabilities = model.predict_proba(test_frame[features])[:, 1]
    report = classification_report(test_frame["label"], predicted, output_dict=True, zero_division=0)
    sample = test_frame.loc[:, ["id", "proto", "service", "state", "attack_cat"]].copy()
    sample["actual_label"] = test_frame["label"]
    sample["predicted_attack"] = predicted
    sample["attack_probability"] = probabilities.round(4)
    sample = sample.sort_values("attack_probability", ascending=False).head(100)
    MODEL_DIR.mkdir(exist_ok=True)
    joblib.dump({"model": model, "features": features}, MODEL_PATH)
    summary = {
        "model_type": "Logistic regression binary network-flow classifier",
        "dataset": "UNSW-NB15 predefined train/test partition",
        "dataset_url": DATASET_URL,
        "dataset_citation": DATASET_CITATION,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "training_records": len(train_frame), "test_records": len(test_frame),
        "attack_detection": report.get("1", {}), "accuracy": report.get("accuracy"),
        "confusion_matrix": confusion_matrix(test_frame["label"], predicted).tolist(),
        "sample_detections": sample.to_dict(orient="records"),
        "scope_notice": "Offline UNSW-NB15 benchmark results. These are not observations from a connected server."
    }
    REPORT_PATH.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary

if __name__ == "__main__":
    result = train()
    print(json.dumps({key: result[key] for key in ("accuracy", "attack_detection", "training_records", "test_records")}, indent=2))
