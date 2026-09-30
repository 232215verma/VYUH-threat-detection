"""
NetGraph Sentinel — Phase 6: Test Coverage

Tests each of the 6 threat types INDIVIDUALLY (isolated from the others)
to prove the detector catches each one on its own — not just when they're
all mixed together. Also includes one "never seen before" pattern that
none of our rules/ML were built for, to prove the anomaly layer works.

Run:
    python test_coverage.py
"""

import random
from datetime import datetime, timedelta

import pandas as pd

from traffic_generator import (
    ATTACK_GENERATORS,
    generate_benign_traffic,
    _random_internal_ip,
    _random_external_ip,
    _fmt,
    COLUMNS,
)
from flow_parser import normalize_flows
from detector import detect_flows

# Maps traffic_generator's internal attack key -> the label the detector
# actually produces, so we can check "did we catch what we meant to catch".
EXPECTED_LABELS = {
    "portscan": "PortScan",
    "ddos": "DDoS",
    "c2": "C2Beaconing",
    "dga": "DGA",
    "dnstunnel": "DNSTunneling",
    "exfil": "Exfiltration",
}


def build_isolated_test(attack_key: str, benign_count: int = 150) -> pd.DataFrame:
    """Benign traffic + exactly ONE attack type, nothing else."""
    start = datetime(2026, 2, 1, 9, 0, 0)
    rows = generate_benign_traffic(benign_count, start)
    attack_start = start + timedelta(minutes=5)
    rows.extend(ATTACK_GENERATORS[attack_key](attack_start))

    df = pd.DataFrame(rows, columns=COLUMNS)
    df["_ts"] = pd.to_datetime(df["Timestamp"], format="%d/%m/%Y %H:%M:%S")
    df = df.sort_values("_ts").drop(columns="_ts")
    return df


def run_detector_on(raw_df: pd.DataFrame) -> list[dict]:
    flows = normalize_flows(raw_df)
    flows["timestamp"] = pd.to_datetime(
        flows["timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce"
    )
    return detect_flows(flows)


# ---------------------------------------------------------------------------
# The "never seen before" pattern — a SLOW, LOW-AND-SLOW exfiltration that
# none of our rules or the trained ML model were built to recognize:
#   - No single big flow (rule_high_volume_single_flow won't fire)
#   - Not enough total bytes in a short window to be a z-score outlier
#     on its own... but it keeps happening, hour after hour, forever.
# Only the anomaly layer (which just knows "this doesn't look benign")
# has a chance at flagging it as unusual.
# ---------------------------------------------------------------------------
def generate_slow_and_low_exfil(start_time: datetime, num_flows: int = 40) -> list[dict]:
    source_ip = _random_internal_ip()
    dest_ip = _random_external_ip()
    rows = []
    t = start_time
    for _ in range(num_flows):
        t += timedelta(minutes=random.uniform(8, 15))  # very spaced out — not "fast"
        rows.append({
            "Source IP": source_ip,
            "Destination IP": dest_ip,
            "Source Port": random.randint(40000, 65000),
            "Destination Port": 443,
            "Protocol": 6,
            "Timestamp": _fmt(t),
            "Flow Duration": random.randint(1000, 3000),
            "Total Fwd Packets": random.randint(4, 8),
            "Total Backward Packets": random.randint(1, 3),
            # small each time — well under any "large flow" rule threshold
            "Total Length of Fwd Packets": random.randint(8000, 15000),
            "Total Length of Bwd Packets": random.randint(100, 500),
            "Label": "SlowExfil",  # not a label our system knows about
        })
    return rows


def build_never_seen_before_test(benign_count: int = 150) -> pd.DataFrame:
    start = datetime(2026, 2, 1, 9, 0, 0)
    rows = generate_benign_traffic(benign_count, start)
    rows.extend(generate_slow_and_low_exfil(start + timedelta(minutes=5)))

    df = pd.DataFrame(rows, columns=COLUMNS)
    df["_ts"] = pd.to_datetime(df["Timestamp"], format="%d/%m/%Y %H:%M:%S")
    df = df.sort_values("_ts").drop(columns="_ts")
    return df


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------
def test_known_threats():
    print("=" * 70)
    print("PART 1: Testing each of the 6 known threats in isolation")
    print("=" * 70)

    results = []
    for attack_key, expected_label in EXPECTED_LABELS.items():
        raw = build_isolated_test(attack_key)
        alerts = run_detector_on(raw)

        matching = [a for a in alerts if a["type"] == expected_label]
        passed = len(matching) > 0
        best_confidence = max((a["confidence"] for a in matching), default=0)
        layers = matching[0]["layers_agreeing"] if matching else []

        results.append({
            "attack": expected_label,
            "passed": passed,
            "confidence": best_confidence,
            "layers": layers,
        })

        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"\n{status} — {expected_label}")
        if passed:
            print(f"   Confidence: {best_confidence:.2f} | Layers agreeing: {', '.join(layers)}")
        else:
            print(f"   Not detected! ({len(alerts)} other alerts fired instead)")

    return results


def test_never_seen_before():
    print("\n" + "=" * 70)
    print("PART 2: 'Never seen before' pattern — slow-and-low exfiltration")
    print("=" * 70)
    print("(No rule or ML model was built to recognize this specific pattern.")
    print(" Only the anomaly layer, which just learned what 'normal' looks")
    print(" like, has a chance at flagging it.)\n")

    raw = build_never_seen_before_test()
    alerts = run_detector_on(raw)

    anomaly_alerts = [a for a in alerts if a["type"] == "Anomaly"]
    if anomaly_alerts:
        print(f"✅ PASS — anomaly layer flagged {len(anomaly_alerts)} suspicious source(s):")
        for a in anomaly_alerts:
            print(f"   - {a['source']}: confidence {a['confidence']:.2f}")
            for e in a["evidence"]:
                print(f"     {e}")
    else:
        print("❌ FAIL — the anomaly layer did not flag the slow-and-low pattern.")
        print(f"   ({len(alerts)} other alerts fired instead — none were 'Anomaly' type)")

    return len(anomaly_alerts) > 0


def main():
    known_results = test_known_threats()
    never_seen_passed = test_never_seen_before()

    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    passed_count = sum(1 for r in known_results if r["passed"])
    print(f"Known threats: {passed_count}/{len(known_results)} passed")
    for r in known_results:
        mark = "✅" if r["passed"] else "❌"
        print(f"  {mark} {r['attack']}")
    print(f"Never-seen-before pattern: {'✅ PASS' if never_seen_passed else '❌ FAIL'}")

    total_passed = passed_count + (1 if never_seen_passed else 0)
    total_tests = len(known_results) + 1
    print(f"\nOverall: {total_passed}/{total_tests} test cases passed")


if __name__ == "__main__":
    main()