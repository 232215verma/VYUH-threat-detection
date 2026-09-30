"""
NetGraph Sentinel — Phase 4/7: Live Pipeline + Demo Sequences
"""

import asyncio
from datetime import datetime, timedelta

import pandas as pd

from flow_parser import load_and_normalize, normalize_flows
from detector import detect_flows
from database import save_alert
from traffic_generator import (
    ATTACK_GENERATORS,
    generate_benign_traffic,
    COLUMNS,
)

RUN_DETECTOR_EVERY_N_BATCHES = 3

DEMO_NARRATION = {
    "portscan": "🚪 Port Scan — one host is probing many ports on a target, looking for an open door.",
    "dga": "🎲 DGA Domains — malware is generating random domain names to find its control server.",
    "dnstunnel": "🕳️ DNS Tunneling — data is being smuggled out disguised as oversized DNS lookups.",
    "c2": "📡 C2 Beaconing — an infected host is checking in with its controller on a fixed schedule.",
    "ddos": "🌊 DDoS — a flood of traffic from hundreds of sources is overwhelming one target.",
    "exfil": "📤 Data Exfiltration — a quiet host suddenly moves a large amount of data out.",
}


def _alert_key(alert: dict) -> tuple:
    return (alert["type"], alert.get("source"), alert.get("target"))


async def run_simulation(csv_path: str, ws_manager, batch_size: int = 20, delay_seconds: float = 0.5):
    flows = load_and_normalize(csv_path)
    flows["timestamp"] = pd.to_datetime(
        flows["timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce"
    )
    flows = flows.assign(_ts=flows["timestamp"]).sort_values("_ts", na_position="last").drop(columns="_ts")

    accumulated = pd.DataFrame(columns=flows.columns)
    seen_alert_keys = set()
    total = len(flows)
    batch_num = 0

    await ws_manager.broadcast({"event": "simulation_started", "total_flows": total})

    for start in range(0, total, batch_size):
        batch = flows.iloc[start:start + batch_size]
        accumulated = pd.concat([accumulated, batch], ignore_index=True)
        batch_num += 1

        await ws_manager.broadcast({
            "event": "batch_processed",
            "batch": batch_num,
            "flows_so_far": len(accumulated),
        })

        is_last = start + batch_size >= total
        if batch_num % RUN_DETECTOR_EVERY_N_BATCHES == 0 or is_last:
            alerts = detect_flows(accumulated)
            for alert in alerts:
                key = _alert_key(alert)
                if key in seen_alert_keys:
                    continue
                seen_alert_keys.add(key)
                save_alert(alert)
                await ws_manager.broadcast({"event": "alert", "alert": alert})

        if delay_seconds > 0 and not is_last:
            await asyncio.sleep(delay_seconds)

    await ws_manager.broadcast({"event": "simulation_complete", "total_alerts": len(seen_alert_keys)})


def _build_single_attack_flows(attack_key: str, benign_count: int = 100) -> pd.DataFrame:
    """Build benign + ONE attack, already normalized, ready for the detector."""
    start = datetime(2026, 3, 1, 9, 0, 0)
    rows = generate_benign_traffic(benign_count, start)
    rows.extend(ATTACK_GENERATORS[attack_key](start + timedelta(minutes=2)))

    raw = pd.DataFrame(rows, columns=COLUMNS)
    flows = normalize_flows(raw)
    flows["timestamp"] = pd.to_datetime(
        flows["timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce"
    )
    return flows.sort_values("timestamp", na_position="last")


async def run_single_attack_demo(attack_key: str, ws_manager, delay_seconds: float = 0.3, batch_size: int = 15):
    """Replay ONE attack type on demand — for live, presenter-controlled demos."""
    flows = _build_single_attack_flows(attack_key)
    accumulated = pd.DataFrame(columns=flows.columns)
    seen_alert_keys = set()
    total = len(flows)
    batch_num = 0

    await ws_manager.broadcast({
        "event": "stage_announcement",
        "text": DEMO_NARRATION.get(attack_key, attack_key),
    })
    await ws_manager.broadcast({"event": "simulation_started", "total_flows": total})

    for start in range(0, total, batch_size):
        batch = flows.iloc[start:start + batch_size]
        accumulated = pd.concat([accumulated, batch], ignore_index=True)
        batch_num += 1

        await ws_manager.broadcast({
            "event": "batch_processed",
            "batch": batch_num,
            "flows_so_far": len(accumulated),
        })

        is_last = start + batch_size >= total
        if is_last or batch_num % 2 == 0:
            alerts = detect_flows(accumulated)
            for alert in alerts:
                key = _alert_key(alert)
                if key in seen_alert_keys:
                    continue
                seen_alert_keys.add(key)
                save_alert(alert)
                await ws_manager.broadcast({"event": "alert", "alert": alert})

        if delay_seconds > 0 and not is_last:
            await asyncio.sleep(delay_seconds)

    await ws_manager.broadcast({"event": "simulation_complete", "total_alerts": len(seen_alert_keys)})


async def run_full_demo_sequence(ws_manager):
    """
    Scripted demo: walks through all 6 threats in a suggested order,
    saving a strong finale for last (per the design doc's advice to
    save the most impressive attack for last).
    """
    order = ["portscan", "dga", "dnstunnel", "c2", "exfil", "ddos"]  # DDoS finale — big visual payoff
    for attack_key in order:
        await run_single_attack_demo(attack_key, ws_manager, delay_seconds=0.25, batch_size=15)
        await asyncio.sleep(1.5)  # pause between stages so the presenter can narrate

    await ws_manager.broadcast({
        "event": "stage_announcement",
        "text": "✅ Demo complete — all 6 threat types detected across graph, rules, ML, and anomaly layers.",
    })