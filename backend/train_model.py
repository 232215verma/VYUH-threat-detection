"""
NetGraph Sentinel — Phase 3: Train the Random Forest classifier

Generates a larger batch of synthetic labeled traffic (more variety than
one traffic_generator.py run), extracts features, trains a Random Forest,
and saves it to ../models/random_forest.pkl for detector.py to use.

Run this once (or whenever you want to retrain):
    python train_model.py
"""

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import LabelEncoder

from traffic_generator import build_dataset, ATTACK_GENERATORS
from flow_parser import normalize_flows
from features import extract_features

MODEL_PATH = "../models/random_forest.pkl"
ENCODER_PATH = "../models/label_encoder.pkl"


def generate_training_data(rounds: int = 8) -> pd.DataFrame:
    """
    Build several rounds of synthetic traffic (all attacks + benign each
    round) and concatenate them. Multiple rounds = more variety since
    traffic_generator randomizes IPs/timing/sizes each call.
    """
    all_flows = []
    for _ in range(rounds):
        batch = build_dataset(list(ATTACK_GENERATORS.keys()), benign_count=300)
        all_flows.append(batch)
    raw = pd.concat(all_flows, ignore_index=True)
    return normalize_flows(raw)


def main():
    print("Generating training data...")
    flows = generate_training_data(rounds=8)
    print(f"Generated {len(flows)} labeled flows.")
    print(flows["label"].value_counts())

    X = extract_features(flows)
    y_raw = flows["label"]

    encoder = LabelEncoder()
    y = encoder.fit_transform(y_raw)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("\nTraining Random Forest...")
    model = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print(f"\nTest accuracy: {accuracy_score(y_test, y_pred):.4f}\n")
    print(classification_report(y_test, y_pred, target_names=encoder.classes_))

    joblib.dump(model, MODEL_PATH)
    joblib.dump(encoder, ENCODER_PATH)
    print(f"\nSaved model to {MODEL_PATH}")
    print(f"Saved label encoder to {ENCODER_PATH}")


if __name__ == "__main__":
    main()