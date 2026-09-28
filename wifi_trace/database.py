import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
DATABASE_PATH = DATA_DIR / "wifi_trace.db"



def valid_signal(value):
    """Return a valid Wi-Fi RSSI value or None."""
    try:
        value = int(value)
    except (TypeError, ValueError):
        return None

    return value if -100 <= value <= -1 else None


def valid_noise(value):
    """Return a valid Wi-Fi noise-floor value or None."""
    try:
        value = int(value)
    except (TypeError, ValueError):
        return None

    return value if -120 <= value <= -1 else None


def calculate_snr(signal, noise):
    """Calculate SNR only from valid radio telemetry."""
    signal = valid_signal(signal)
    noise = valid_noise(noise)

    if signal is None or noise is None:
        return None

    snr = signal - noise

    # Defensive sanity check.
    if not 0 <= snr <= 100:
        return None

    return snr


TRACKED_FIELDS = {
    "gateway": "Gateway",
    "interface": "Interface",
    "ip_address": "Local IPv4",
    "ssid": "SSID",
    "status": "Wi-Fi Status",
    "phy_mode": "Wi-Fi Standard",
    "channel": "Channel",
    "security": "Security",
    "signal": "Signal",
    "noise": "Noise",
    "tx_rate": "Transmit Rate",
    "country": "Country",
    "dns_servers": "DNS Servers",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_connection() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    return connection


def init_database() -> None:
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                observed_at TEXT NOT NULL,
                gateway TEXT,
                interface TEXT,
                ip_address TEXT,
                ssid TEXT,
                wifi_status TEXT,
                phy_mode TEXT,
                channel TEXT,
                security TEXT,
                signal INTEGER,
                noise INTEGER,
                tx_rate TEXT,
                country TEXT,
                dns_servers TEXT,
                raw_json TEXT NOT NULL
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                observed_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                field_name TEXT NOT NULL,
                field_label TEXT NOT NULL,
                old_value TEXT,
                new_value TEXT,
                severity TEXT NOT NULL DEFAULT 'info'
            )
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_snapshots_observed_at
            ON snapshots(observed_at)
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_events_observed_at
            ON events(observed_at)
            """
        )


def _normalize(value: Any) -> str | None:
    if value is None:
        return None

    if isinstance(value, list):
        return ", ".join(str(item) for item in value)

    return str(value)


def get_latest_snapshot() -> dict | None:
    init_database()

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT *
            FROM snapshots
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()

    if not row:
        return None

    data = json.loads(row["raw_json"])
    data["_observed_at"] = row["observed_at"]
    data["_id"] = row["id"]

    return data


def _event_severity(field: str, old_value: Any, new_value: Any) -> str:
    if field in {"gateway", "security", "dns_servers"}:
        return "warning"

    if field in {"ssid", "status", "ip_address", "channel"}:
        return "notice"

    return "info"


def save_snapshot(network: dict) -> dict:
    init_database()

    # Work on a copy so collectors cannot accidentally persist invalid
    # radio telemetry into forensic history.
    network = dict(network)

    network["signal"] = valid_signal(network.get("signal"))
    network["noise"] = valid_noise(network.get("noise"))

    observed_at = utc_now()
    previous = get_latest_snapshot()

    dns_servers = network.get("dns_servers") or []

    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO snapshots (
                observed_at,
                gateway,
                interface,
                ip_address,
                ssid,
                wifi_status,
                phy_mode,
                channel,
                security,
                signal,
                noise,
                tx_rate,
                country,
                dns_servers,
                raw_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                observed_at,
                network.get("gateway"),
                network.get("interface"),
                network.get("ip_address"),
                network.get("ssid"),
                network.get("status"),
                network.get("phy_mode"),
                network.get("channel"),
                network.get("security"),
                network.get("signal"),
                network.get("noise"),
                network.get("tx_rate"),
                network.get("country"),
                json.dumps(dns_servers),
                json.dumps(network),
            ),
        )

        snapshot_id = cursor.lastrowid

        events_created = 0

        if previous is None:
            connection.execute(
                """
                INSERT INTO events (
                    observed_at,
                    event_type,
                    field_name,
                    field_label,
                    old_value,
                    new_value,
                    severity
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    observed_at,
                    "baseline",
                    "network",
                    "Network Baseline",
                    None,
                    "Initial network observation recorded",
                    "info",
                ),
            )

            events_created += 1

        else:
            for field, label in TRACKED_FIELDS.items():
                old_value = previous.get(field)
                new_value = network.get(field)

                old_normalized = _normalize(old_value)
                new_normalized = _normalize(new_value)

                if old_normalized == new_normalized:
                    continue

                # Ignore transitions where both sides contain no useful data.
                if not old_normalized and not new_normalized:
                    continue

                # Signal and noise naturally fluctuate.
                # Invalid or unavailable readings must never become
                # forensic change events.
                if field in {"signal", "noise"}:
                    try:
                        old_radio = (
                            int(old_value)
                            if old_value is not None
                            else None
                        )

                        new_radio = (
                            int(new_value)
                            if new_value is not None
                            else None
                        )
                    except (TypeError, ValueError):
                        continue

                    # Missing telemetry is not evidence of a radio change.
                    if old_radio is None or new_radio is None:
                        continue

                    if field == "signal":
                        if not (
                            -100 <= old_radio <= -1
                            and -100 <= new_radio <= -1
                        ):
                            continue

                    if field == "noise":
                        if not (
                            -120 <= old_radio <= -1
                            and -120 <= new_radio <= -1
                        ):
                            continue

                    # Small fluctuations are normal Wi-Fi behaviour.
                    if abs(new_radio - old_radio) < 5:
                        continue

                # Transmit rate is highly dynamic and remains available in
                # snapshots. It should not flood the forensic event timeline.
                if field == "tx_rate":
                    continue

                connection.execute(
                    """
                    INSERT INTO events (
                        observed_at,
                        event_type,
                        field_name,
                        field_label,
                        old_value,
                        new_value,
                        severity
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        observed_at,
                        "change",
                        field,
                        label,
                        old_normalized,
                        new_normalized,
                        _event_severity(field, old_value, new_value),
                    ),
                )

                events_created += 1

    return {
        "snapshot_id": snapshot_id,
        "observed_at": observed_at,
        "events_created": events_created,
    }


def get_recent_events(limit: int = 100) -> list[dict]:
    init_database()

    limit = max(1, min(int(limit), 500))

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                observed_at,
                event_type,
                field_name,
                field_label,
                old_value,
                new_value,
                severity
            FROM events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]


def get_recent_snapshots(limit: int = 50) -> list[dict]:
    init_database()

    limit = max(1, min(int(limit), 500))

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                observed_at,
                gateway,
                interface,
                ip_address,
                ssid,
                wifi_status,
                phy_mode,
                channel,
                security,
                signal,
                noise,
                tx_rate,
                country,
                dns_servers
            FROM snapshots
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    results = []

    for row in rows:
        item = dict(row)

        try:
            item["dns_servers"] = json.loads(item["dns_servers"] or "[]")
        except json.JSONDecodeError:
            item["dns_servers"] = []

        results.append(item)

    return results


def get_database_stats() -> dict:
    init_database()

    with get_connection() as connection:
        snapshots = connection.execute(
            "SELECT COUNT(*) FROM snapshots"
        ).fetchone()[0]

        events = connection.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0]

        first = connection.execute(
            """
            SELECT observed_at
            FROM snapshots
            ORDER BY id ASC
            LIMIT 1
            """
        ).fetchone()

        latest = connection.execute(
            """
            SELECT observed_at
            FROM snapshots
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()

    return {
        "snapshots": snapshots,
        "events": events,
        "first_observation": first[0] if first else None,
        "latest_observation": latest[0] if latest else None,
        "database": str(DATABASE_PATH),
    }


def get_snapshot(snapshot_id: int) -> dict | None:
    """Return one historical network snapshot."""
    init_database()

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT
                id,
                observed_at,
                gateway,
                interface,
                ip_address,
                ssid,
                wifi_status,
                phy_mode,
                channel,
                security,
                signal,
                noise,
                tx_rate,
                country,
                dns_servers
            FROM snapshots
            WHERE id = ?
            """,
            (snapshot_id,),
        ).fetchone()

    if not row:
        return None

    item = dict(row)

    try:
        item["dns_servers"] = json.loads(
            item["dns_servers"] or "[]"
        )
    except json.JSONDecodeError:
        item["dns_servers"] = []

    item["signal"] = valid_signal(item.get("signal"))
    item["noise"] = valid_noise(item.get("noise"))
    item["snr"] = calculate_snr(
        item.get("signal"),
        item.get("noise"),
    )

    return item


def get_snapshot_navigation(snapshot_id: int) -> dict:
    """Return previous and next snapshot IDs."""
    init_database()

    with get_connection() as connection:
        previous = connection.execute(
            """
            SELECT id
            FROM snapshots
            WHERE id < ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (snapshot_id,),
        ).fetchone()

        next_snapshot = connection.execute(
            """
            SELECT id
            FROM snapshots
            WHERE id > ?
            ORDER BY id ASC
            LIMIT 1
            """,
            (snapshot_id,),
        ).fetchone()

    return {
        "previous": previous["id"] if previous else None,
        "next": next_snapshot["id"] if next_snapshot else None,
    }


def get_latest_snapshot_id() -> int | None:
    init_database()

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT id
            FROM snapshots
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()

    return row["id"] if row else None


def get_snapshot_index(limit: int = 250) -> list[dict]:
    """Return compact historical snapshot list."""
    init_database()

    limit = max(1, min(int(limit), 1000))

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                observed_at,
                ip_address,
                gateway,
                channel,
                signal,
                noise
            FROM snapshots
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]


def init_device_database():
    """Create device-observation tables used by Device Passport."""
    init_database()

    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS observed_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_key TEXT NOT NULL UNIQUE,
                device_type TEXT NOT NULL,
                display_name TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                observation_count INTEGER NOT NULL DEFAULT 0
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS device_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                observed_at TEXT NOT NULL,
                ip_address TEXT,
                mac_address TEXT,
                hostname TEXT,
                source TEXT NOT NULL,
                evidence_note TEXT,
                FOREIGN KEY(device_id)
                    REFERENCES observed_devices(id)
            )
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_device_observations_device
            ON device_observations(device_id, observed_at)
            """
        )


def observe_device(
    device_key: str,
    device_type: str,
    display_name: str,
    ip_address: str | None,
    source: str,
    mac_address: str | None = None,
    hostname: str | None = None,
    evidence_note: str | None = None,
    observed_at: str | None = None,
) -> int:
    """Store one defensible device observation."""

    init_device_database()

    observed_at = observed_at or utc_now()

    with get_connection() as connection:
        existing = connection.execute(
            """
            SELECT id
            FROM observed_devices
            WHERE device_key = ?
            """,
            (device_key,),
        ).fetchone()

        if existing:
            device_id = existing["id"]

            connection.execute(
                """
                UPDATE observed_devices
                SET
                    last_seen = ?,
                    observation_count = observation_count + 1,
                    display_name = ?
                WHERE id = ?
                """,
                (
                    observed_at,
                    display_name,
                    device_id,
                ),
            )
        else:
            cursor = connection.execute(
                """
                INSERT INTO observed_devices (
                    device_key,
                    device_type,
                    display_name,
                    first_seen,
                    last_seen,
                    observation_count
                )
                VALUES (?, ?, ?, ?, ?, 1)
                """,
                (
                    device_key,
                    device_type,
                    display_name,
                    observed_at,
                    observed_at,
                ),
            )

            device_id = cursor.lastrowid

        connection.execute(
            """
            INSERT INTO device_observations (
                device_id,
                observed_at,
                ip_address,
                mac_address,
                hostname,
                source,
                evidence_note
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                device_id,
                observed_at,
                ip_address,
                mac_address,
                hostname,
                source,
                evidence_note,
            ),
        )

    return device_id


def record_core_devices(network: dict):
    """
    Record devices for which the local collector has direct evidence.

    This intentionally does NOT claim to enumerate every device connected
    to the network.
    """

    import socket

    observed_at = utc_now()

    local_ip = network.get("ip_address")
    interface = network.get("interface")

    if local_ip:
        hostname = socket.gethostname()

        observe_device(
            device_key="local-host",
            device_type="Local Host",
            display_name=hostname or "This Computer",
            ip_address=local_ip,
            hostname=hostname,
            source="Local Interface",
            evidence_note=(
                f"IPv4 address observed on local interface "
                f"{interface or 'unknown'}."
            ),
            observed_at=observed_at,
        )

    gateway = network.get("gateway")

    if gateway:
        observe_device(
            device_key=f"gateway:{gateway}",
            device_type="Gateway",
            display_name="Network Gateway",
            ip_address=gateway,
            source="Default Route",
            evidence_note=(
                "Gateway observed from the operating system "
                "default IPv4 route."
            ),
            observed_at=observed_at,
        )


def get_observed_devices() -> list[dict]:
    init_device_database()

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                d.id,
                d.device_key,
                d.device_type,
                d.display_name,
                d.first_seen,
                d.last_seen,
                d.observation_count,
                (
                    SELECT o.ip_address
                    FROM device_observations o
                    WHERE o.device_id = d.id
                    ORDER BY o.id DESC
                    LIMIT 1
                ) AS latest_ip,
                (
                    SELECT o.mac_address
                    FROM device_observations o
                    WHERE o.device_id = d.id
                      AND o.mac_address IS NOT NULL
                    ORDER BY o.id DESC
                    LIMIT 1
                ) AS latest_mac,
                (
                    SELECT o.source
                    FROM device_observations o
                    WHERE o.device_id = d.id
                    ORDER BY o.id DESC
                    LIMIT 1
                ) AS latest_source
            FROM observed_devices d
            ORDER BY d.last_seen DESC
            """
        ).fetchall()

    return [dict(row) for row in rows]


def get_device_passport(device_id: int) -> dict | None:
    init_device_database()

    with get_connection() as connection:
        device = connection.execute(
            """
            SELECT *
            FROM observed_devices
            WHERE id = ?
            """,
            (device_id,),
        ).fetchone()

        if not device:
            return None

        observations = connection.execute(
            """
            SELECT
                id,
                observed_at,
                ip_address,
                mac_address,
                hostname,
                source,
                evidence_note
            FROM device_observations
            WHERE device_id = ?
            ORDER BY id DESC
            LIMIT 250
            """,
            (device_id,),
        ).fetchall()

        ips = connection.execute(
            """
            SELECT
                ip_address,
                MIN(observed_at) AS first_seen,
                MAX(observed_at) AS last_seen,
                COUNT(*) AS observations
            FROM device_observations
            WHERE device_id = ?
              AND ip_address IS NOT NULL
            GROUP BY ip_address
            ORDER BY last_seen DESC
            """,
            (device_id,),
        ).fetchall()

    result = dict(device)
    result["observations"] = [dict(row) for row in observations]
    result["ip_history"] = [dict(row) for row in ips]

    return result
