"""Random-forest classifier over window features: Normal / Brute force / SQL injection / DDoS.

Training data is the labelled synthetic traffic from simulator.py plus (optionally) events whose label an
analyst reviewed. Metrics are reported on a held-out set of independently seeded sessions, next to a
rules-only baseline, and they are synthetic-benchmark numbers, not a production detection rate.
"""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from . import CLASSES
from .events import prepare
from .features import FEATURE_NAMES, FeatureExtractor, vector
from .rules import evaluate
from .simulator import Simulator

MODEL_PATH = Path(__file__).resolve().parents[2] / "data" / "models" / "web_attack_rf.joblib"
REPORT_PATH = MODEL_PATH.with_name("web_attack_rf_report.json")


def featurize(events: list[dict]) -> tuple[np.ndarray, list[str], list[dict]]:
    """Run a time-ordered event list through a fresh extractor. Returns X, labels, feature dicts."""
    fx, rows, labels, feats = FeatureExtractor(), [], [], []
    for ev in events:
        f = fx.update(prepare(ev)); feats.append(f); rows.append(vector(f)); labels.append(ev.get("label", "Normal"))
    return np.array(rows, dtype=float), labels, feats


def build_dataset(seeds, minutes: float = 30):
    X, y = [], []
    for seed in seeds:
        xs, ys, _ = featurize(Simulator(seed).session(minutes))
        X.append(xs); y += ys
    return np.vstack(X), np.array(y)


def rules_baseline(events: list[dict]) -> list[str]:
    _, _, feats = featurize(events)
    out = []
    for f in feats:
        hits = evaluate(f)
        out.append(max(hits, key=lambda h: h["confidence"])["type"] if hits else "Normal")
    return out


def train(train_seeds=range(40), test_seeds=range(1000, 1012), extra: tuple | None = None, save: bool = True) -> dict:
    X, y = build_dataset(train_seeds)
    weights = np.ones(len(y))
    if extra is not None and len(extra[0]):               # analyst-reviewed examples count more
        X = np.vstack([X, extra[0]]); y = np.concatenate([y, extra[1]]); weights = np.concatenate([weights, np.full(len(extra[1]), 8.0)])
    model = RandomForestClassifier(n_estimators=160, max_depth=14, min_samples_leaf=2, class_weight="balanced_subsample",
                                   n_jobs=-1, random_state=7)
    model.fit(X, y, sample_weight=weights)
    # held-out evaluation on independently seeded sessions, versus rules only
    Xt, yt, rule_pred = [], [], []
    for seed in test_seeds:
        events = Simulator(seed).session(30)
        xs, ys, _ = featurize(events); Xt.append(xs); yt += ys; rule_pred += rules_baseline(events)
    Xt, yt = np.vstack(Xt), np.array(yt)
    pred = model.predict(Xt)
    rep = classification_report(yt, pred, labels=CLASSES, output_dict=True, zero_division=0)
    rule_rep = classification_report(yt, np.array(rule_pred), labels=CLASSES, output_dict=True, zero_division=0)
    normal = rep["Normal"]["recall"]
    summary = {
        "model_type": "RandomForest (160 trees) on 18 window features, 4 classes",
        "trained_at": datetime.now(timezone.utc).isoformat(), "training_rows": int(len(y)), "test_rows": int(len(yt)),
        "reviewed_examples_used": int(len(extra[1])) if extra is not None else 0,
        "data_note": "SYNTHETIC simulated traffic (src/engine/simulator.py). Metrics are a synthetic benchmark, not a production "
                     "detection rate. Replace/augment with real labelled server logs before relying on them.",
        "per_class_ml": {c: {k: round(rep[c][k], 4) for k in ("precision", "recall", "f1-score", "support")} for c in CLASSES},
        "per_class_rules_only": {c: {k: round(rule_rep[c][k], 4) for k in ("precision", "recall", "f1-score", "support")} for c in CLASSES},
        "false_positive_rate_ml": round(1 - normal, 4),
        "false_positive_rate_rules_only": round(1 - rule_rep["Normal"]["recall"], 4),
        "confusion_matrix_ml": {"labels": CLASSES, "matrix": confusion_matrix(yt, pred, labels=CLASSES).tolist()},
        "feature_importance": dict(sorted(zip(FEATURE_NAMES, map(lambda v: round(float(v), 4), model.feature_importances_)), key=lambda kv: -kv[1])),
    }
    if save:
        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": model, "features": FEATURE_NAMES, "classes": list(model.classes_)}, MODEL_PATH)
        REPORT_PATH.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    summary["_model"] = model
    return summary


class Classifier:
    """Loads (or trains) the model and returns class probabilities for one feature dict."""

    @classmethod
    def from_model(cls, model) -> "Classifier":
        self = cls.__new__(cls); self.model, self.classes = model, [str(c) for c in model.classes_]; self.model.n_jobs = 1
        return self

    def __init__(self, path: Path = MODEL_PATH, auto_train: bool = True):
        blob = None
        if path.exists():
            try: blob = joblib.load(path)
            except Exception:                         # e.g. saved by a different scikit-learn version: retrain below
                if not auto_train: raise
        if blob is None:
            if not auto_train: raise FileNotFoundError(path)
            train(); blob = joblib.load(path)
        self.model, self.classes = blob["model"], blob["classes"]
        self.model.n_jobs = 1                    # one-row predictions are far faster without worker start-up

    @staticmethod
    def worth_scoring(f: dict) -> bool:
        """Cheap pre-filter: ordinary low-volume, error-free requests are not sent through the forest."""
        return bool(f["is_failed_auth"] or f["sqli_hits"] or f["special_ratio"] >= 0.15 or f["srv_req_60"] >= 60
                    or f["ip_req_60"] >= 30 or f["is_5xx"])

    def proba(self, features: dict) -> dict:
        p = self.model.predict_proba(np.array([vector(features)], dtype=float))[0]
        return {str(c): float(v) for c, v in zip(self.classes, p)}


if __name__ == "__main__":
    s = train(); s.pop("_model")
    print(json.dumps({k: s[k] for k in ("training_rows", "test_rows", "per_class_ml", "per_class_rules_only",
                                        "false_positive_rate_ml", "false_positive_rate_rules_only")}, indent=2))
