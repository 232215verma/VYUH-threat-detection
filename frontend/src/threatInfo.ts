export interface ThreatInfo {
  label: string;
  color: string;
  mitre: string;
  description: string;
}

export const THREAT_INFO: Record<string, ThreatInfo> = {
  PortScan: {
    label: "Port Scan",
    color: "#f59e0b",
    mitre: "T1046",
    description:
      "A single host probed a large number of ports on one target in rapid succession. This is typically reconnaissance, used to map exposed services before an intrusion attempt.",
  },
  DDoS: {
    label: "DDoS / DoS",
    color: "#f43f5e",
    mitre: "T1498",
    description:
      "A large number of distinct sources sent traffic to a single target within a short window, consistent with a distributed attempt to exhaust the target's bandwidth or connection capacity.",
  },
  Exfiltration: {
    label: "Data Exfiltration",
    color: "#a78bfa",
    mitre: "T1041",
    description:
      "A host transferred an unusually large volume of data out of the network, far above the baseline of its peers. This may indicate unauthorized removal of sensitive data.",
  },
  DNSTunneling: {
    label: "DNS Tunneling",
    color: "#22d3ee",
    mitre: "T1071.004",
    description:
      "DNS queries carried payloads far larger than legitimate lookups. This pattern is commonly used to smuggle data through DNS, which is rarely inspected in depth.",
  },
  DGA: {
    label: "DGA Domains",
    color: "#a3e635",
    mitre: "T1568.002",
    description:
      "A host contacted many distinct destinations only once or twice each, a hallmark of malware using a domain generation algorithm to locate its command server.",
  },
  C2Beaconing: {
    label: "C2 Beaconing",
    color: "#f472b6",
    mitre: "T1071",
    description:
      "A host contacted the same external endpoint at highly regular intervals with near-identical payload sizes, consistent with malware checking in to a command-and-control server.",
  },
  Anomaly: {
    label: "Statistical Anomaly",
    color: "#94a3b8",
    mitre: "N/A",
    description:
      "Traffic from this host deviates significantly from the learned baseline of normal behavior without matching a known attack signature. Manual review is recommended.",
  },
};

export const THREAT_ORDER = [
  "PortScan",
  "DDoS",
  "Exfiltration",
  "DNSTunneling",
  "DGA",
  "C2Beaconing",
  "Anomaly",
];

export const LAYER_LABELS: Record<string, string> = {
  graph: "Graph Analysis",
  rule: "Rule Engine",
  ml: "Random Forest",
  anomaly: "Isolation Forest",
};

export type Severity = "critical" | "high" | "medium" | "low";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

export const SEVERITY_META: Record<Severity, { label: string; color: string }> = {
  critical: { label: "Critical", color: "#f43f5e" },
  high: { label: "High", color: "#fb923c" },
  medium: { label: "Medium", color: "#fbbf24" },
  low: { label: "Low", color: "#60a5fa" },
};

export function severityOf(confidence: number): Severity {
  if (confidence >= 0.9) return "critical";
  if (confidence >= 0.75) return "high";
  if (confidence >= 0.6) return "medium";
  return "low";
}

export function alertKey(a: { type: string; source: string | null; target: string | null }): string {
  return `${a.type}|${a.source ?? ""}|${a.target ?? ""}`;
}