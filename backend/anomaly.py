"""
NetGraph Sentinel — Phase 3: Anomaly Detector (Isolation Forest)

Trains ONLY on benign traffic — it never sees a single labeled attack.
It just learns what "normal" looks like, then flags anything that
deviates. This is what catches attacks the rules and the Random Forest
have never seen before.

Run this once (after train_model.py, or independently):
    python anomaly.py
"""

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

from traffic_generator import generate_benign_traffic
from flow_parser import normalize_flows
from features import extract_features
from datetime import datetime

MODEL_PATH = "../models/isolation_forest.pkl"


def generate_benign_training_data(n: int = 3000) -> pd.DataFrame:
    """Generate a large batch of ONLY benign flows for unsupervised training."""
    rows = generate_benign_traffic(n, datetime(2026, 1, 15, 9, 0, 0))
    raw = pd.DataFrame(rows)
    return normalize_flows(raw)


def train_anomaly_model():
    print("Generating benign-only training data...")
    flows = generate_benign_training_data(3000)
    X = extract_features(flows)

    print("Training Isolation Forest (unsupervised, benign-only)...")
    model = IsolationForest(
        n_estimators=200, contamination=0.05, random_state=42, n_jobs=-1
    )
    model.fit(X)

    joblib.dump(model, MODEL_PATH)
    print(f"Saved anomaly model to {MODEL_PATH}")
    return model


def score_anomalies(flows: pd.DataFrame, model=None) -> pd.DataFrame:
    """
    Return the input flows with two new columns:
    - anomaly_score: lower = more anomalous
    - is_anomaly: True if the model flags this flow as an outlier
    """
    if model is None:
        model = joblib.load(MODEL_PATH)

    X = extract_features(flows)
    scores = model.decision_function(X)
    predictions = model.predict(X)  # -1 = anomaly, 1 = normal

    result = flows.copy()
    result["anomaly_score"] = scores
    result["is_anomaly"] = predictions == -1
    return result


if __name__ == "__main__":
    train_anomaly_model()