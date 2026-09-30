"""
NetGraph Sentinel — Phase 3: Feature Extraction

Turns normalized flow rows into numeric features the ML models can use.
Shared by train_model.py (training) and detector.py (live prediction) so
both sides always compute features the exact same way.
"""

import pandas as pd

FEATURE_COLUMNS = [
    "duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_bytes",
    "dst_port",
    "protocol",
    "total_packets",
    "bytes_per_packet",
    "fwd_bwd_ratio",
]


def extract_features(flows: pd.DataFrame) -> pd.DataFrame:
    """Return a DataFrame of numeric features, one row per input flow."""
    df = flows.copy()

    df["duration"] = pd.to_numeric(df["duration"], errors="coerce").fillna(0)
    df["total_fwd_packets"] = pd.to_numeric(df["total_fwd_packets"], errors="coerce").fillna(0)
    df["total_bwd_packets"] = pd.to_numeric(df["total_bwd_packets"], errors="coerce").fillna(0)
    df["total_bytes"] = pd.to_numeric(df["total_bytes"], errors="coerce").fillna(0)
    df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce").fillna(0)
    df["protocol"] = pd.to_numeric(df["protocol"], errors="coerce").fillna(0)

    df["total_packets"] = df["total_fwd_packets"] + df["total_bwd_packets"]
    df["bytes_per_packet"] = df["total_bytes"] / df["total_packets"].replace(0, 1)
    df["fwd_bwd_ratio"] = df["total_fwd_packets"] / df["total_bwd_packets"].replace(0, 1)

    return df[FEATURE_COLUMNS]