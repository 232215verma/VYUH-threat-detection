"""
NetGraph Sentinel — Phase 4: Database

Simple SQLite storage for alerts. One table: alerts.
"""

import sqlite3
import json
from pathlib import Path
from datetime import datetime, timezone

DB_PATH = Path(__file__).parent / "alerts.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            source TEXT,
            target TEXT,
            confidence REAL NOT NULL,
            layers_agreeing TEXT,
            evidence TEXT,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def save_alert(alert: dict):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        INSERT INTO alerts (type, source, target, confidence, layers_agreeing, evidence, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            alert["type"],
            alert.get("source"),
            alert.get("target"),
            alert["confidence"],
            json.dumps(alert.get("layers_agreeing", [])),
            json.dumps(alert.get("evidence", [])),
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()
    conn.close()


def get_alerts(limit: int = 100) -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()

    result = []
    for row in rows:
        result.append({
            "id": row["id"],
            "type": row["type"],
            "source": row["source"],
            "target": row["target"],
            "confidence": row["confidence"],
            "layers_agreeing": json.loads(row["layers_agreeing"]),
            "evidence": json.loads(row["evidence"]),
            "created_at": row["created_at"],
        })
    return result


def clear_alerts():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()