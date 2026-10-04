# VYUH – Threat Detection

**Graph-based, passive AI threat detection for unidirectional (data-diode) IP traffic.**

Smart India Hackathon 2026 | Problem Statement SIH26145 | Organisation: NTRO
Theme: Blockchain & Cybersecurity | Category: Software

---

## Overview

Critical infrastructure operators (defence networks, power grids) often monitor traffic through a hardware data diode or mirror port. The monitoring enclave can see everything but can never send anything back: no ping, no probe, no block command. Traffic is also encrypted, so payloads cannot be read.

VYUH detects cyber threats using only passive flow metadata. It models the whole network as a live graph (IP = node, connection = edge) and combines graph shape analysis with rules, supervised ML, and unsupervised anomaly detection.

## Key Features

- **Read-only ingest:** no return path, no probes, no inline blocking
- **Metadata-only analysis:** no payload decryption
- **Streaming pipeline:** incremental batch processing with bounded alert latency
- **6 threat classes:** DDoS, Port Scanning, C2 Beaconing, DGA, DNS Tunnelling, Data Exfiltration
- **4-layer hybrid detection:** Graph Engine, Rules Engine, Random Forest, Isolation Forest
- **Confidence boosting:** agreement between independent layers raises confidence (0.70 up to 0.99)
- **Zero-day safety net:** Isolation Forest is trained on benign traffic only
- **Explainable alerts:** RAG-based assistant with MITRE ATT&CK mapping
- **Live dashboard:** topology graph, alert feed, KPI cards, activity chart, scenario console

## Architecture

```
Traffic Generator -> CSV (labelled synthetic flows)
        |
Replayer -> streams flows in batches (simulated live traffic)
        |
Feature Extraction + Live Graph Builder
        |
4 Detection Layers (Graph | Rules | Random Forest | Isolation Forest)
        |
Detector -> merges results, boosts confidence, assigns severity
        |
FastAPI Backend -> WebSocket push (real time)
        |
SQLite -> alert storage
        |
React Dashboard -> live graph, alerts, charts
```

In a real deployment the whole pipeline sits inside the monitoring enclave. It only watches and alerts. Any response action is taken by a human analyst through a separate channel.

## Detection Logic

| Threat | Behaviour in flow data | Graph shape |
|---|---|---|
| DDoS | Many sources hitting one target, high packet rate, high source-IP entropy | Hub |
| Port Scanning | One source, many destination ports/hosts, tiny flows | Star |
| C2 Beaconing | Regular inter-arrival times to a small set of destinations | Repeating edge |
| DGA | Many distinct high-entropy domain names, many failed lookups | n/a |
| DNS Tunnelling | Very long, high-entropy queries, unusual record types, high volume to one domain | n/a |
| Data Exfiltration | High outbound-to-inbound byte ratio, sudden volume spike | Node suddenly active |

## Alert Schema

```json
{
  "timestamp": "2026-01-01T10:15:30Z",
  "flow_id": "f-000123",
  "src_ip": "10.0.0.5",
  "dst_ip": "203.0.113.10",
  "threat_class": "Exfiltration",
  "confidence": 0.99,
  "severity": "critical",
  "evidence_features": {
    "bytes_out": 0,
    "bytes_in": 0,
    "out_in_ratio": 0,
    "layers_triggered": ["rules", "random_forest", "isolation_forest"]
  }
}
```

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3 |
| Data Processing | Pandas, NumPy |
| ML | Scikit-learn (Random Forest, Isolation Forest) |
| Graph Analysis | NetworkX |
| Backend | FastAPI, WebSocket |
| Database | SQLite |
| Frontend | React, TypeScript, Vite |
| AI Assistant | RAG (knowledge base + semantic search), MITRE ATT&CK mapping, optional local LLM |

## Project Structure

```
VYUH-threat-detection/
|-- backend/
|   |-- main.py                # FastAPI app + WebSocket
|   |-- pipeline.py            # Orchestrates the streaming pipeline
|   |-- replayer.py            # Replays flows in batches (simulated live traffic)
|   |-- flow_parser.py         # Parses flow records
|   |-- features.py            # Feature extraction
|   |-- graph_engine.py        # Live graph + shape detection
|   |-- rules.py               # Threshold rules
|   |-- anomaly.py             # Isolation Forest anomaly layer
|   |-- detector.py            # Combines layers, confidence boost, severity
|   |-- database.py            # SQLite alert storage
|   |-- rag_engine.py          # RAG assistant for alert explanations
|   |-- knowledge_base.py      # MITRE ATT&CK knowledge base
|   |-- traffic_generator.py   # Synthetic labelled traffic generator
|   |-- train_model.py         # Trains Random Forest + Isolation Forest
|   |-- test_coverage.py       # Detection test cases
|   `-- requirements.txt
|-- frontend/                  # React + TypeScript + Vite dashboard
|   `-- src/components/        # LiveGraph, AlertFeed, AlertDrawer, ActivityChart,
|                              # ThreatTypeMenu, DemoPanel, SummaryReport
|-- data/                      # Synthetic and sample flow CSVs
|-- models/                    # Trained models (.pkl)
`-- README.md
```

## Getting Started

### Prerequisites

- Python 3.10+
- Node.js 18+
- Git

### 1. Clone the repository

```bash
git clone https://github.com/232215verma/VYUH-threat-detection.git
cd VYUH-threat-detection
```

### 2. Backend setup

```bash
cd backend
python -m venv venv

# Windows (PowerShell)
.\venv\Scripts\activate

# Linux / macOS
source venv/bin/activate

pip install -r requirements.txt
```

Generate data and train models:

```bash
python traffic_generator.py
python train_model.py
```

Start the API server:

```bash
uvicorn main:app --reload --port 8000
```

API docs will be available at `http://127.0.0.1:8000/docs`.

### 3. Frontend setup

```bash
cd frontend
npm install
npm run dev
```

Open the dashboard at the URL printed by Vite (usually `http://localhost:5173`).

## Dataset

Training and testing use a custom synthetic traffic generator that produces controlled, labelled scenarios:

- 300 benign flows
- Attack flows for PortScan, DDoS, DGA, C2 Beaconing, DNS Tunnelling, Exfiltration (about 670 labelled flows in total)
- One unseen slow-and-low exfiltration pattern, used only to validate the anomaly layer

Validation on real datasets (CICIDS2017) and lab traffic (iperf3, hping3, dnscat2/iodine, DGArchive samples) is planned future work.

## Testing and Results

- 6 of 6 threat classes detected, confidence up to 0.99
- Unseen slow-and-low exfiltration caught only by the Isolation Forest layer
- Total: 7 of 7 test cases passed
- Tested throughput: [X] flows/sec
- Alert latency: [Y] ms

## Design Constraints Followed

- Read-only ingest with no return path
- No payload decryption (metadata only)
- Streaming, not batch-only reporting
- Standardised alert schema
- Stated and demonstrated throughput target

## Limitations and Future Scope

- Validate on real datasets (CICIDS2017) and live mirrored traffic
- JA3/JA4 TLS fingerprinting for malware in encrypted sessions
- Real NetFlow/IPFIX/sFlow collector ingest
- Graph neural network models (for example E-GraphSAGE)
- Higher throughput via stream processing (Kafka or similar)

## References

- Sharafaldin et al. (2018), CICIDS2017, ICISSP
- Liu, Ting and Zhou (2008), Isolation Forest, IEEE ICDM
- Breiman (2001), Random Forests, Machine Learning
- Mirsky et al. (2018), Kitsune, NDSS
- Lo et al. (2022), E-GraphSAGE, IEEE/IFIP NOMS
- MITRE ATT&CK Framework
- RFC 7011 (IPFIX)