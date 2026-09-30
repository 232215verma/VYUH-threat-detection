"""
NetGraph Sentinel — Phase 1: Flow Parser

Reads a raw CICIDS2017 CSV and converts it into our own standard "flow"
schema — the shape every later phase (graph engine, detector, backend)
will expect.
"""

import pandas as pd
from pathlib import Path

STANDARD_COLUMNS = [
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "timestamp",
    "duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_bytes",
    "label",
]

CICIDS_COLUMN_MAP = {
    "Source IP": "src_ip",
    "Destination IP": "dst_ip",
    "Source Port": "src_port",
    "Destination Port": "dst_port",
    "Protocol": "protocol",
    "Timestamp": "timestamp",
    "Flow Duration": "duration",
    "Total Fwd Packets": "total_fwd_packets",
    "Total Backward Packets": "total_bwd_packets",
    "Total Length of Fwd Packets": "fwd_bytes",
    "Total Length of Bwd Packets": "bwd_bytes",
    "Label": "label",
}


def load_cicids_csv(path: str | Path) -> pd.DataFrame:
    df = pd.read_csv(path, low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    return df


def normalize_flows(df: pd.DataFrame) -> pd.DataFrame:
    renamed = df.rename(columns=CICIDS_COLUMN_MAP)

    if "fwd_bytes" in renamed.columns and "bwd_bytes" in renamed.columns:
        renamed["total_bytes"] = renamed["fwd_bytes"] + renamed["bwd_bytes"]
    else:
        renamed["total_bytes"] = pd.NA

    for col in STANDARD_COLUMNS:
        if col not in renamed.columns:
            renamed[col] = pd.NA

    out = renamed[STANDARD_COLUMNS].copy()
    out["label"] = out["label"].astype(str).str.strip()
    out = out.dropna(subset=["label"])

    return out


def load_and_normalize(path: str | Path) -> pd.DataFrame:
    raw = load_cicids_csv(path)
    return normalize_flows(raw)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python flow_parser.py <path-to-csv>")
        sys.exit(1)

    flows = load_and_normalize(sys.argv[1])
    print(f"Loaded {len(flows)} flows.")
    print(f"Label counts:\n{flows['label'].value_counts()}")
    print(f"\nFirst 5 rows:\n{flows.head()}")