"""
NetGraph Sentinel — Phase 3: Rules

Simple, fast threshold checks — no ML, no graph. Catches obvious,
well-known attack patterns instantly by just counting things.
"""

import pandas as pd


def rule_port_scan(flows: pd.DataFrame, port_threshold: int = 15) -> list[dict]:
    """Same src -> same dst touching many distinct ports."""
    alerts = []
    grouped = flows.groupby(["src_ip", "dst_ip"])["dst_port"].nunique()
    for (src, dst), num_ports in grouped.items():
        if num_ports >= port_threshold:
            alerts.append({
                "type": "PortScan",
                "source": src,
                "target": dst,
                "evidence": f"[Rule] {src} tried {num_ports} ports on {dst}",
                "confidence": min(0.95, 0.5 + num_ports / 100),
                "layer": "rule",
            })
    return alerts


def rule_ddos(flows: pd.DataFrame, indegree_threshold: int = 30) -> list[dict]:
    """One dst receiving from many distinct src IPs."""
    alerts = []
    grouped = flows.groupby("dst_ip")["src_ip"].nunique()
    for dst, num_sources in grouped.items():
        if num_sources >= indegree_threshold:
            alerts.append({
                "type": "DDoS",
                "target": dst,
                "evidence": f"[Rule] {dst} hit by {num_sources} distinct sources",
                "confidence": min(0.95, 0.5 + num_sources / 300),
                "layer": "rule",
            })
    return alerts


def rule_dns_tunneling(flows: pd.DataFrame, byte_threshold: int = 500) -> list[dict]:
    """Individual DNS (port 53) flows with abnormally large payloads."""
    alerts = []
    dns_flows = flows[(flows["dst_port"] == 53) & (flows["total_bytes"] >= byte_threshold)]
    for (src, dst), group in dns_flows.groupby(["src_ip", "dst_ip"]):
        avg_bytes = group["total_bytes"].mean()
        alerts.append({
            "type": "DNSTunneling",
            "source": src,
            "target": dst,
            "evidence": f"[Rule] {src} sent oversized DNS traffic to {dst} (avg {avg_bytes:.0f} bytes)",
            "confidence": min(0.9, 0.4 + avg_bytes / 5000),
            "layer": "rule",
        })
    return alerts


def rule_high_volume_single_flow(flows: pd.DataFrame, byte_threshold: int = 300_000) -> list[dict]:
    """A single flow moving a huge amount of data in one go — quick exfil signal."""
    alerts = []
    big_flows = flows[flows["total_bytes"] >= byte_threshold]
    for src, group in big_flows.groupby("src_ip"):
        total = group["total_bytes"].sum()
        alerts.append({
            "type": "Exfiltration",
            "source": src,
            "evidence": f"[Rule] {src} moved {total:,.0f} bytes in {len(group)} large flow(s)",
            "confidence": min(0.9, 0.4 + total / 5_000_000),
            "layer": "rule",
        })
    return alerts


def get_rule_alerts(flows: pd.DataFrame) -> list[dict]:
    """Run every rule and return one combined list."""
    alerts = []
    alerts += rule_port_scan(flows)
    alerts += rule_ddos(flows)
    alerts += rule_dns_tunneling(flows)
    alerts += rule_high_volume_single_flow(flows)
    return alerts