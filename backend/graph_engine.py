"""
NetGraph Sentinel — Phase 2: Graph Engine (the core / USP)

Turns flow data into a live network graph (NetworkX DiGraph) — IPs become
nodes, connections become edges — and looks at how the SHAPE of that graph
changes to spot attacks, on top of (and independent from) any single-flow
check.

Shapes we're looking for (from the design doc):
    Port scan  -> one node has an edge to one target carrying MANY
                  distinct destination ports ("star" on ports, not nodes)
    DDoS       -> one node suddenly has edges arriving from MANY distinct
                  source nodes ("hub" — high in-degree)
    C2/Botnet  -> repeated edge between the same pair, at suspiciously
                  REGULAR time intervals ("beaconing")
    DGA        -> one node has edges to MANY distinct destination nodes,
                  each contacted only once or twice
    Exfil      -> one node's outbound byte volume is a big outlier
                  compared to every other node in the graph
"""

from __future__ import annotations

import statistics
from collections import defaultdict

import networkx as nx
import pandas as pd


# ---------------------------------------------------------------------------
# Building the graph
# ---------------------------------------------------------------------------
def build_graph(flows: pd.DataFrame) -> nx.DiGraph:
    """
    Build a directed graph from normalized flow data (the schema
    flow_parser.py produces). One edge per (src_ip, dst_ip) pair; repeated
    flows between the same pair accumulate onto the same edge instead of
    creating duplicates, so the edge holds the FULL history of that pair.
    """
    G = nx.DiGraph()

    for _, row in flows.iterrows():
        src, dst = row["src_ip"], row["dst_ip"]
        if pd.isna(src) or pd.isna(dst):
            continue

        if not G.has_edge(src, dst):
            G.add_edge(
                src, dst,
                ports=set(),
                flow_count=0,
                total_bytes=0,
                timestamps=[],
            )

        edge = G[src][dst]
        if pd.notna(row.get("dst_port")):
            edge["ports"].add(row["dst_port"])
        edge["flow_count"] += 1
        if pd.notna(row.get("total_bytes")):
            edge["total_bytes"] += row["total_bytes"]
        if pd.notna(row.get("timestamp")):
            edge["timestamps"].append(row["timestamp"])

    return G


# ---------------------------------------------------------------------------
# Snapshot metrics — the numbers behind the shapes
# ---------------------------------------------------------------------------
def node_metrics(G: nx.DiGraph) -> dict[str, dict]:
    """Per-node degree and byte-volume metrics for the current graph snapshot."""
    metrics = {}
    for node in G.nodes:
        out_edges = G.out_edges(node, data=True)
        in_edges = G.in_edges(node, data=True)

        metrics[node] = {
            "out_degree": G.out_degree(node),
            "in_degree": G.in_degree(node),
            "bytes_out": sum(d["total_bytes"] for _, _, d in out_edges),
            "bytes_in": sum(d["total_bytes"] for _, _, d in in_edges),
        }
    return metrics


# ---------------------------------------------------------------------------
# Anomaly detection — graph shape -> alert
# ---------------------------------------------------------------------------
def detect_port_scans(G: nx.DiGraph, port_threshold: int = 15) -> list[dict]:
    """
    Star-on-ports shape: one edge (src -> dst) touching many distinct
    destination ports. This is what a port scan looks like in the graph.
    """
    alerts = []
    for src, dst, data in G.edges(data=True):
        num_ports = len(data["ports"])
        if num_ports >= port_threshold:
            alerts.append({
                "type": "PortScan",
                "source": src,
                "target": dst,
                "evidence": f"{src} touched {num_ports} distinct ports on {dst}",
                "confidence": min(0.99, 0.5 + num_ports / 100),
            })
    return alerts


def detect_ddos(G: nx.DiGraph, indegree_threshold: int = 30) -> list[dict]:
    """
    Hub shape: one node receiving edges from many distinct source nodes.
    This is what a DDoS (or a botnet reporting home) looks like in the graph.
    """
    alerts = []
    for node in G.nodes:
        indeg = G.in_degree(node)
        if indeg >= indegree_threshold:
            alerts.append({
                "type": "DDoS",
                "target": node,
                "evidence": f"{node} received connections from {indeg} distinct sources",
                "confidence": min(0.99, 0.5 + indeg / 300),
            })
    return alerts


def detect_dga(G: nx.DiGraph, outdegree_threshold: int = 12, max_flows_per_edge: int = 2) -> list[dict]:
    """
    Fan-out shape: one node contacting many distinct destinations, each
    only once or twice. Real DGA malware never talks to the same
    (fake, algorithm-generated) domain/IP twice.
    """
    alerts = []
    for node in G.nodes:
        out_edges = list(G.out_edges(node, data=True))
        if len(out_edges) < outdegree_threshold:
            continue
        mostly_one_off = sum(1 for _, _, d in out_edges if d["flow_count"] <= max_flows_per_edge)
        if mostly_one_off >= outdegree_threshold:
            alerts.append({
                "type": "DGA",
                "source": node,
                "evidence": f"{node} contacted {mostly_one_off} distinct destinations, each only 1-2 times",
                "confidence": min(0.95, 0.4 + mostly_one_off / 80),
            })
    return alerts


def detect_c2_beaconing(G: nx.DiGraph, min_beacons: int = 5, regularity_threshold: float = 0.25) -> list[dict]:
    """
    Regular-timing shape: the same edge (src -> dst) repeating at
    suspiciously EVEN time intervals. Regularity is measured as
    coefficient of variation (stdev / mean) of the gaps between
    consecutive timestamps — low = very regular = beacon-like.
    """
    alerts = []
    for src, dst, data in G.edges(data=True):
        ts_list = sorted(t for t in data["timestamps"] if pd.notna(t))
        if len(ts_list) < min_beacons:
            continue

        gaps = [
            (ts_list[i + 1] - ts_list[i]).total_seconds()
            for i in range(len(ts_list) - 1)
            if isinstance(ts_list[i], pd.Timestamp)
        ]
        if len(gaps) < min_beacons - 1 or statistics.mean(gaps) == 0:
            continue

        coeff_of_variation = statistics.pstdev(gaps) / statistics.mean(gaps)
        if coeff_of_variation <= regularity_threshold:
            alerts.append({
                "type": "C2Beaconing",
                "source": src,
                "target": dst,
                "evidence": (
                    f"{src} contacted {dst} {len(ts_list)} times at "
                    f"~{statistics.mean(gaps):.1f}s intervals (very regular)"
                ),
                "confidence": min(0.95, 0.6 + (regularity_threshold - coeff_of_variation)),
            })
    return alerts


def detect_exfiltration(G: nx.DiGraph, zscore_threshold: float = 2.0, min_bytes: int = 100_000) -> list[dict]:
    """
    Outlier-volume shape: one node's outbound byte total is a big
    statistical outlier compared to every other node — a normally-quiet
    node suddenly moving a lot of data. Requires BOTH a high z-score AND
    a meaningful absolute byte volume, so small early-batch noise
    doesn't trigger false alarms.
    """
    metrics = node_metrics(G)
    bytes_out_values = [m["bytes_out"] for m in metrics.values() if m["bytes_out"] > 0]
    if len(bytes_out_values) < 3:
        return []

    mean = statistics.mean(bytes_out_values)
    stdev = statistics.pstdev(bytes_out_values) or 1  # avoid divide-by-zero

    alerts = []
    for node, m in metrics.items():
        if m["bytes_out"] < min_bytes:
            continue
        z = (m["bytes_out"] - mean) / stdev
        if z >= zscore_threshold:
            alerts.append({
                "type": "Exfiltration",
                "source": node,
                "evidence": f"{node} sent {m['bytes_out']:,} bytes out — {z:.1f} std devs above average",
                "confidence": min(0.95, 0.5 + z / 10),
            })
    return alerts


def detect_dns_tunneling(G: nx.DiGraph, min_avg_bytes: int = 500, min_flows: int = 5) -> list[dict]:
    """
    Oversized-DNS shape: repeated traffic on port 53 (DNS) whose average
    payload size per flow is way bigger than a normal DNS lookup
    (normal DNS is usually well under 200 bytes per flow).
    """
    alerts = []
    for src, dst, data in G.edges(data=True):
        if 53 not in data["ports"]:
            continue
        if data["flow_count"] < min_flows:
            continue
        avg_bytes = data["total_bytes"] / data["flow_count"]
        if avg_bytes >= min_avg_bytes:
            alerts.append({
                "type": "DNSTunneling",
                "source": src,
                "target": dst,
                "evidence": (
                    f"{src} sent {data['flow_count']} DNS flows to {dst} averaging "
                    f"{avg_bytes:.0f} bytes each (normal DNS is much smaller)"
                ),
                "confidence": min(0.95, 0.5 + avg_bytes / 4000),
            })
    return alerts


def get_graph_anomalies(G: nx.DiGraph) -> list[dict]:
    """Run every detector and return one combined, sorted alert list."""
    alerts = []
    alerts += detect_port_scans(G)
    alerts += detect_ddos(G)
    alerts += detect_dga(G)
    alerts += detect_c2_beaconing(G)
    alerts += detect_exfiltration(G)
    alerts += detect_dns_tunneling(G)
    alerts.sort(key=lambda a: a["confidence"], reverse=True)
    return alerts


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    from flow_parser import load_and_normalize

    if len(sys.argv) < 2:
        print("Usage: python graph_engine.py <path-to-csv>")
        print("Example: python graph_engine.py ../data/synthetic_traffic.csv")
        sys.exit(1)

    flows = load_and_normalize(sys.argv[1])
    # Parse timestamps to real datetimes so beaconing regularity math works
    flows["timestamp"] = pd.to_datetime(
        flows["timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce"
    )

    print(f"Building graph from {len(flows)} flows...")
    G = build_graph(flows)
    print(f"Graph has {G.number_of_nodes()} nodes and {G.number_of_edges()} edges.\n")

    anomalies = get_graph_anomalies(G)
    if not anomalies:
        print("No anomalies detected.")
    else:
        print(f"Detected {len(anomalies)} anomalies:\n")
        for a in anomalies:
            print(f"[{a['type']}] confidence={a['confidence']:.2f} — {a['evidence']}")