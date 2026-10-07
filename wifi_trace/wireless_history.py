"""
WiFi-Trace Wireless Historical Analytics.

Persistent wireless telemetry storage using the existing SQLite database.
"""

import sqlite3
from datetime import datetime, timedelta, timezone

from wifi_trace.database import DATABASE_PATH


def initialize_wireless_history():
    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS wireless_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                interface TEXT,
                signal_dbm REAL,
                noise_dbm REAL,
                snr_db REAL,
                tx_rate_mbps REAL
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_wireless_history_timestamp
            ON wireless_history(timestamp)
        """)


def _numeric(value):
    if isinstance(value, bool):
        return None

    if isinstance(value, (int, float)):
        import math
        return float(value) if math.isfinite(value) else None

    return None


def save_wireless_measurement(network, diagnostics):
    initialize_wireless_history()

    timestamp = datetime.now(timezone.utc).isoformat()

    values = (
        timestamp,
        network.get("interface"),
        _numeric(diagnostics.get("signal_dbm")),
        _numeric(diagnostics.get("noise_dbm")),
        _numeric(diagnostics.get("snr_db")),
        _numeric(diagnostics.get("tx_rate_mbps")),
    )

    with sqlite3.connect(DATABASE_PATH) as connection:
        cursor = connection.execute("""
            INSERT INTO wireless_history (
                timestamp,
                interface,
                signal_dbm,
                noise_dbm,
                snr_db,
                tx_rate_mbps
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, values)

        return cursor.lastrowid


def get_wireless_history(hours=1, limit=1000):
    initialize_wireless_history()

    hours = max(1, min(int(hours), 168))
    limit = max(1, min(int(limit), 5000))

    cutoff = (
        datetime.now(timezone.utc) -
        timedelta(hours=hours)
    ).isoformat()

    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute("""
            SELECT *
            FROM wireless_history
            WHERE timestamp >= ?
            ORDER BY timestamp DESC, id DESC
            LIMIT ?
        """, (cutoff, limit)).fetchall()

    return [dict(row) for row in reversed(rows)]
