"""
NetGraph Sentinel — Phase 8: Knowledge Base

Static knowledge for the RAG layer: MITRE ATT&CK mappings for each threat
type, plus a few "past incident" style entries (as described in the design
doc) that the retrieval step can surface alongside the technique info.
"""

KNOWLEDGE_BASE = [
    {
        "id": "portscan-mitre",
        "threat_type": "PortScan",
        "mitre_id": "T1046",
        "mitre_name": "Network Service Discovery",
        "text": (
            "Port scanning (MITRE T1046 - Network Service Discovery) is when an "
            "attacker probes a target host across many ports to find open, "
            "reachable services. It is almost always a reconnaissance step that "
            "happens BEFORE a more targeted attack, as the attacker is mapping "
            "out what's available to exploit."
        ),
        "recommended_action": "Monitor the source IP closely for follow-up activity; consider isolating the target host if the scan found open, vulnerable services.",
    },
    {
        "id": "portscan-incident",
        "threat_type": "PortScan",
        "mitre_id": "T1046",
        "mitre_name": "Network Service Discovery",
        "text": (
            "A similar port scan pattern was observed in a past incident log, "
            "where reconnaissance scanning preceded an attempted exploitation of "
            "an exposed service a few days later."
        ),
        "recommended_action": "Cross-reference the target host's exposed services and patch level.",
    },
    {
        "id": "ddos-mitre",
        "threat_type": "DDoS",
        "mitre_id": "T1498",
        "mitre_name": "Network Denial of Service",
        "text": (
            "A distributed denial of service (MITRE T1498) floods a target with "
            "traffic from many sources at once, aiming to exhaust its bandwidth "
            "or connection capacity so legitimate traffic can't get through."
        ),
        "recommended_action": "Engage upstream rate-limiting or blackhole routing for the flood sources; confirm the target service's availability.",
    },
    {
        "id": "c2-mitre",
        "threat_type": "C2Beaconing",
        "mitre_id": "T1071",
        "mitre_name": "Application Layer Protocol (Command and Control)",
        "text": (
            "C2 beaconing (MITRE T1071) is when malware on a compromised host "
            "periodically 'checks in' with an attacker-controlled server, often "
            "at a very regular interval, to receive commands or exfiltrate data "
            "in small increments."
        ),
        "recommended_action": "Isolate the beaconing host from the network and inspect it for malware; block the destination IP at the firewall.",
    },
    {
        "id": "dga-mitre",
        "threat_type": "DGA",
        "mitre_id": "T1568.002",
        "mitre_name": "Dynamic Resolution: Domain Generation Algorithms",
        "text": (
            "A Domain Generation Algorithm (MITRE T1568.002) lets malware compute "
            "large numbers of pseudo-random domain names on the fly, so it can "
            "find its command-and-control server even if earlier domains get "
            "taken down or blocked."
        ),
        "recommended_action": "Flag the host as likely compromised; block DNS resolution to the observed destinations and monitor for the real C2 domain.",
    },
    {
        "id": "dnstunnel-mitre",
        "threat_type": "DNSTunneling",
        "mitre_id": "T1071.004",
        "mitre_name": "Application Layer Protocol: DNS",
        "text": (
            "DNS tunneling (MITRE T1071.004) hides data inside DNS queries and "
            "responses, which are rarely inspected closely by firewalls, "
            "allowing data to be smuggled in or out disguised as ordinary "
            "DNS lookups."
        ),
        "recommended_action": "Inspect the oversized DNS payloads for encoded data; consider blocking the destination DNS server if it's not a legitimate resolver.",
    },
    {
        "id": "exfil-mitre",
        "threat_type": "Exfiltration",
        "mitre_id": "T1041",
        "mitre_name": "Exfiltration Over C2 Channel",
        "text": (
            "Data exfiltration (MITRE T1041 / T1048) is the unauthorized transfer "
            "of data out of the network, often in a short burst from a host that "
            "is not normally a high-traffic sender."
        ),
        "recommended_action": "Identify what data was accessed on the source host prior to the transfer; block the destination and begin incident response.",
    },
    {
        "id": "anomaly-generic",
        "threat_type": "Anomaly",
        "mitre_id": "N/A",
        "mitre_name": "Unclassified Anomalous Behavior",
        "text": (
            "This traffic pattern does not match any known signature or trained "
            "attack type, but statistically deviates from what this network's "
            "baseline (benign) traffic normally looks like."
        ),
        "recommended_action": "Treat as a precaution: monitor the host manually since automated classification could not confirm the threat type.",
    },
]


def get_entries_for_type(threat_type: str) -> list[dict]:
    return [e for e in KNOWLEDGE_BASE if e["threat_type"] == threat_type]