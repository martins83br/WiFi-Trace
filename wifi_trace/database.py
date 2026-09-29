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


def init_device_fingerprinting_database() -> None:
    init_device_database()

    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS device_fingerprints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                observed_at TEXT NOT NULL,
                source TEXT NOT NULL,
                hostname TEXT,
                category TEXT,
                confidence TEXT,
                service_type TEXT,
                service_name TEXT,
                service_label TEXT,
                port INTEGER,
                FOREIGN KEY(device_id)
                    REFERENCES observed_devices(id)
            )
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_device_fingerprints_device_time
            ON device_fingerprints(device_id, observed_at)
            """
        )


def add_device_fingerprint(
    *,
    device_id: int,
    source: str,
    hostname: str | None = None,
    category: str | None = None,
    confidence: str | None = None,
    service_type: str | None = None,
    service_name: str | None = None,
    service_label: str | None = None,
    port: int | None = None,
) -> None:
    init_device_fingerprinting_database()

    observed_at = utc_now()

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO device_fingerprints (
                device_id,
                observed_at,
                source,
                hostname,
                category,
                confidence,
                service_type,
                service_name,
                service_label,
                port
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                device_id,
                observed_at,
                source,
                hostname,
                category,
                confidence,
                service_type,
                service_name,
                service_label,
                port,
            ),
        )


def find_observed_device_by_ip(
    ip_address: str,
) -> dict | None:
    init_device_database()

    with get_connection() as connection:
        connection.row_factory = sqlite3.Row

        row = connection.execute(
            """
            SELECT
                d.*
            FROM observed_devices d
            JOIN device_observations o
                ON o.device_id = d.id
            WHERE o.ip_address = ?
            ORDER BY o.observed_at DESC
            LIMIT 1
            """,
            (ip_address,),
        ).fetchone()

    return dict(row) if row else None


def get_device_fingerprints(
    device_id: int,
) -> list[dict]:
    init_device_fingerprinting_database()

    with get_connection() as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            """
            SELECT *
            FROM device_fingerprints
            WHERE device_id = ?
            ORDER BY observed_at DESC
            LIMIT 250
            """,
            (device_id,),
        ).fetchall()

    return [dict(row) for row in rows]


def get_device_identification(
    device_id: int,
) -> dict:
    fingerprints = get_device_fingerprints(device_id)

    if not fingerprints:
        return {
            "category": "Unknown",
            "confidence": None,
            "hostname": None,
            "services": [],
        }

    rank = {
        "High": 3,
        "Medium": 2,
        "Low": 1,
    }

    best = max(
        fingerprints,
        key=lambda item: rank.get(
            item.get("confidence"),
            0,
        ),
    )

    hostname = next(
        (
            item["hostname"]
            for item in fingerprints
            if item.get("hostname")
        ),
        None,
    )

    services = []

    seen = set()

    for item in fingerprints:
        key = (
            item.get("service_type"),
            item.get("service_name"),
        )

        if key in seen:
            continue

        seen.add(key)

        services.append(
            {
                "type": item.get("service_type"),
                "name": item.get("service_name"),
                "label": item.get("service_label"),
                "port": item.get("port"),
                "confidence": item.get("confidence"),
            }
        )

    return {
        "category": best.get("category") or "Unknown",
        "confidence": best.get("confidence"),
        "hostname": hostname,
        "services": services,
    }



# === WIFI-TRACE DEVICE ENRICHMENT V1 ===

def _fingerprint_service_weight(service_type: str | None) -> int:
    weights = {
        "_ipp._tcp": 100,
        "_ipps._tcp": 100,
        "_printer._tcp": 100,
        "_pdl-datastream._tcp": 95,
        "_scanner._tcp": 90,
        "_googlecast._tcp": 80,
        "_workstation._tcp": 75,
        "_smb._tcp": 65,
        "_ssh._tcp": 55,
        "_airplay._tcp": 50,
        "_raop._tcp": 45,
        "_device-info._tcp": 20,
        "_https._tcp": 10,
        "_http._tcp": 5,
    }

    return weights.get(service_type or "", 0)


def get_enriched_device_identification(
    device: dict,
) -> dict:
    fingerprints = get_device_fingerprints(
        device["id"]
    )

    services = []
    seen = set()

    for item in fingerprints:
        key = (
            item.get("service_type"),
            item.get("service_name"),
        )

        if key in seen:
            continue

        seen.add(key)

        services.append(
            {
                "type": item.get("service_type"),
                "name": item.get("service_name"),
                "label": item.get("service_label"),
                "port": item.get("port"),
                "confidence": item.get("confidence"),
                "hostname": item.get("hostname"),
            }
        )

    hostname = next(
        (
            item.get("hostname")
            for item in fingerprints
            if item.get("hostname")
        ),
        None,
    )

    # Direct local evidence outranks advertised services.
    if device.get("device_type") == "Local Host":
        return {
            "display_name":
                device.get("display_name")
                or hostname
                or "Local Computer",
            "category": "Computer",
            "confidence": "High",
            "hostname":
                hostname
                or device.get("display_name"),
            "services": services,
            "fingerprint_count": len(fingerprints),
        }

    # Default route is direct evidence of the gateway role.
    if device.get("device_type") == "Gateway":
        return {
            "display_name":
                device.get("display_name")
                or "Network Gateway",
            "category": "Network Infrastructure",
            "confidence": "High",
            "hostname": hostname,
            "services": services,
            "fingerprint_count": len(fingerprints),
        }

    if not fingerprints:
        return {
            "display_name":
                device.get("display_name")
                or "Observed Device",
            "category": "Unknown",
            "confidence": None,
            "hostname": None,
            "services": [],
            "fingerprint_count": 0,
        }

    service_types = {
        item.get("service_type")
        for item in fingerprints
    }

    printer_types = {
        "_ipp._tcp",
        "_ipps._tcp",
        "_printer._tcp",
        "_pdl-datastream._tcp",
    }

    # Printing + scanning is strong evidence for an MFP.
    if (
        service_types.intersection(printer_types)
        and "_scanner._tcp" in service_types
    ):
        category = "Multifunction Printer"
        confidence = "High"
    else:
        best = max(
            fingerprints,
            key=lambda item:
                _fingerprint_service_weight(
                    item.get("service_type")
                ),
        )

        category = (
            best.get("category")
            or "Unknown"
        )

        confidence = best.get("confidence")

    # Prefer a name attached to the strongest service evidence.
    ranked = sorted(
        fingerprints,
        key=lambda item:
            _fingerprint_service_weight(
                item.get("service_type")
            ),
        reverse=True,
    )

    identified_name = None

    for item in ranked:
        candidate = item.get("service_name")

        if candidate:
            identified_name = candidate
            break

    return {
        "display_name":
            identified_name
            or hostname
            or device.get("display_name")
            or "Observed Device",
        "category": category,
        "confidence": confidence,
        "hostname": hostname,
        "services": services,
        "fingerprint_count": len(fingerprints),
    }


def get_enriched_observed_devices() -> list[dict]:
    devices = get_observed_devices()
    result = []

    for device in devices:
        identification = (
            get_enriched_device_identification(
                device
            )
        )

        result.append(
            {
                **device,
                "identified_name":
                    identification["display_name"],
                "category":
                    identification["category"],
                "confidence":
                    identification["confidence"],
                "identified_hostname":
                    identification["hostname"],
                "services":
                    identification["services"],
                "fingerprint_count":
                    identification["fingerprint_count"],
            }
        )

    return result


def get_enriched_device_passport(
    device_id: int,
) -> dict | None:
    passport = get_device_passport(device_id)

    if passport is None:
        return None

    identification = (
        get_enriched_device_identification(
            passport
        )
    )

    passport["identification"] = identification
    passport["fingerprints"] = (
        get_device_fingerprints(device_id)
    )

    return passport



# === WIFI-TRACE MAC PASSPORT ENRICHMENT V1 ===

def get_device_mac_evidence(device_id: int) -> dict:
    """
    Return the most recent valid MAC evidence associated with a device.

    A MAC address is evidence about an observed network interface.
    It must not be treated as proof of a person's identity or current
    network association.
    """

    from wifi_trace.mac_evidence import analyze_mac

    init_device_database()

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                mac_address,
                observed_at,
                source
            FROM device_observations
            WHERE device_id = ?
              AND mac_address IS NOT NULL
              AND TRIM(mac_address) != ''
            ORDER BY id DESC
            LIMIT 50
            """,
            (device_id,),
        ).fetchall()

    for row in rows:
        evidence = analyze_mac(row["mac_address"])

        if not evidence.valid:
            continue

        result = evidence.to_dict()
        result["observed_at"] = row["observed_at"]
        result["source"] = row["source"]

        return result

    return {
        "raw": None,
        "normalized": None,
        "valid": False,
        "address_type": "Unavailable",
        "administration": "Unavailable",
        "locally_administered": None,
        "globally_administered": None,
        "multicast": None,
        "unicast": None,
        "oui": None,
        "vendor_lookup_eligible": False,
        "forensic_note": (
            "No valid MAC-address evidence has been observed "
            "for this device."
        ),
        "observed_at": None,
        "source": None,
    }


def get_device_mac_history(
    device_id: int,
    limit: int = 100,
) -> list[dict]:
    """
    Return unique valid MAC addresses observed for a device.
    """

    from wifi_trace.mac_evidence import analyze_mac

    init_device_database()

    limit = max(1, min(int(limit), 500))

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                mac_address,
                MIN(observed_at) AS first_seen,
                MAX(observed_at) AS last_seen,
                COUNT(*) AS observations
            FROM device_observations
            WHERE device_id = ?
              AND mac_address IS NOT NULL
              AND TRIM(mac_address) != ''
            GROUP BY mac_address
            ORDER BY last_seen DESC
            LIMIT ?
            """,
            (device_id, limit),
        ).fetchall()

    results = []

    for row in rows:
        evidence = analyze_mac(row["mac_address"])

        if not evidence.valid:
            continue

        item = evidence.to_dict()
        item["first_seen"] = row["first_seen"]
        item["last_seen"] = row["last_seen"]
        item["observations"] = row["observations"]

        results.append(item)

    return results


def get_mac_enriched_device_passport(
    device_id: int,
) -> dict | None:
    """
    Return the enriched Device Passport plus MAC evidence.
    """

    device = get_enriched_device_passport(device_id)

    if device is None:
        return None

    device["mac_evidence"] = get_device_mac_evidence(
        device_id
    )

    device["mac_history"] = get_device_mac_history(
        device_id
    )

    return device



# === WIFI-TRACE NEIGHBOR EVIDENCE V1 ===

def get_latest_observed_ipv4_addresses() -> list[str]:
    """
    Return unique IPv4 addresses already observed by WiFi-Trace.

    This does not generate new targets.
    """

    init_device_database()

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT DISTINCT ip_address
            FROM device_observations
            WHERE ip_address IS NOT NULL
              AND TRIM(ip_address) != ''
            ORDER BY ip_address
            """
        ).fetchall()

    return [
        row["ip_address"]
        for row in rows
        if row["ip_address"]
    ]


def record_neighbor_mac_evidence(
    ip_address: str,
    mac_address: str,
    source: str,
    evidence_note: str,
) -> int | None:
    """
    Attach validated MAC evidence to the device most recently observed
    at an IPv4 address.

    Existing device identity is preserved. The MAC is stored as
    observation evidence and does not automatically replace the
    device_key.
    """

    from wifi_trace.mac_evidence import analyze_mac

    evidence = analyze_mac(mac_address)

    if not evidence.valid:
        return None

    if evidence.multicast:
        return None

    device = find_observed_device_by_ip(ip_address)

    if device is None:
        return None

    return observe_device(
        device_key=device["device_key"],
        device_type=device["device_type"],
        display_name=(
            device.get("display_name")
            or device["device_type"]
        ),
        ip_address=ip_address,
        mac_address=evidence.normalized,
        source=source,
        evidence_note=evidence_note,
    )


# === WIFI-TRACE INVESTIGATIONS V1 ===

def init_investigation_database() -> None:
    init_device_database()

    with get_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                status TEXT NOT NULL DEFAULT 'OPEN',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS investigation_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id INTEGER NOT NULL,
                evidence_type TEXT NOT NULL,
                source TEXT NOT NULL,
                captured_at TEXT NOT NULL,
                added_at TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                note TEXT,
                FOREIGN KEY (
                    investigation_id
                ) REFERENCES investigations(id)
            );

            CREATE INDEX IF NOT EXISTS
                idx_investigation_evidence_case
            ON investigation_evidence(
                investigation_id,
                added_at
            );

            CREATE UNIQUE INDEX IF NOT EXISTS
                idx_investigation_evidence_hash
            ON investigation_evidence(
                investigation_id,
                sha256
            );
            """
        )


def create_investigation(
    title: str,
    description: str | None = None,
) -> int:
    from wifi_trace.evidence import utc_now

    title = title.strip()

    if not title:
        raise ValueError(
            "Investigation title is required."
        )

    description = (
        description.strip()
        if description
        else None
    )

    now = utc_now()

    init_investigation_database()

    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO investigations (
                title,
                description,
                status,
                created_at,
                updated_at
            )
            VALUES (?, ?, 'OPEN', ?, ?)
            """,
            (
                title,
                description,
                now,
                now,
            ),
        )

        return int(cursor.lastrowid)


def get_investigations() -> list[dict]:
    init_investigation_database()

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                i.*,
                COUNT(e.id) AS evidence_count
            FROM investigations AS i
            LEFT JOIN investigation_evidence AS e
                ON e.investigation_id = i.id
            GROUP BY i.id
            ORDER BY i.updated_at DESC, i.id DESC
            """
        ).fetchall()

    return [
        dict(row)
        for row in rows
    ]


def get_investigation(
    investigation_id: int,
) -> dict | None:
    init_investigation_database()

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT *
            FROM investigations
            WHERE id = ?
            """,
            (investigation_id,),
        ).fetchone()

        if row is None:
            return None

        evidence_rows = connection.execute(
            """
            SELECT *
            FROM investigation_evidence
            WHERE investigation_id = ?
            ORDER BY added_at DESC, id DESC
            """,
            (investigation_id,),
        ).fetchall()

    investigation = dict(row)
    investigation["evidence"] = [
        dict(item)
        for item in evidence_rows
    ]

    return investigation


def add_snapshot_to_investigation(
    investigation_id: int,
    snapshot_id: int,
    note: str | None = None,
) -> dict:
    import json

    from wifi_trace.evidence import (
        build_evidence_envelope,
        utc_now,
    )

    investigation = get_investigation(
        investigation_id
    )

    if investigation is None:
        raise ValueError(
            "Investigation not found."
        )

    snapshot = get_snapshot(snapshot_id)

    if snapshot is None:
        raise ValueError(
            "Snapshot not found."
        )

    envelope = build_evidence_envelope(
        evidence_type="network_snapshot",
        source="WiFi-Trace Time Machine",
        captured_at=snapshot.get(
            "observed_at"
        ),
        payload=snapshot,
    )

    note = note.strip() if note else None

    init_investigation_database()

    with get_connection() as connection:
        existing = connection.execute(
            """
            SELECT id
            FROM investigation_evidence
            WHERE investigation_id = ?
              AND sha256 = ?
            """,
            (
                investigation_id,
                envelope["sha256"],
            ),
        ).fetchone()

        if existing is not None:
            raise ValueError(
                "This evidence is already in the investigation."
            )

        cursor = connection.execute(
            """
            INSERT INTO investigation_evidence (
                investigation_id,
                evidence_type,
                source,
                captured_at,
                added_at,
                sha256,
                payload_json,
                note
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                investigation_id,
                envelope["evidence_type"],
                envelope["source"],
                envelope["captured_at"],
                utc_now(),
                envelope["sha256"],
                json.dumps(
                    envelope["payload"],
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ),
                note,
            ),
        )

        connection.execute(
            """
            UPDATE investigations
            SET updated_at = ?
            WHERE id = ?
            """,
            (
                utc_now(),
                investigation_id,
            ),
        )

    return {
        "evidence_id": int(
            cursor.lastrowid
        ),
        "sha256": envelope["sha256"],
    }


# === WIFI-TRACE EVIDENCE INTEGRITY V2 ===

def init_evidence_integrity_database() -> None:
    """
    Create append-only verification history for preserved evidence.

    Verification records do not modify the original evidence payload.
    """
    init_investigation_database()

    with get_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS evidence_verifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id INTEGER NOT NULL,
                verified_at TEXT NOT NULL,
                expected_sha256 TEXT NOT NULL,
                calculated_sha256 TEXT NOT NULL,
                result TEXT NOT NULL,
                verification_method TEXT NOT NULL,
                FOREIGN KEY(evidence_id)
                    REFERENCES investigation_evidence(id)
            );

            CREATE INDEX IF NOT EXISTS
                idx_evidence_verifications_evidence
            ON evidence_verifications(
                evidence_id,
                verified_at
            );
            """
        )


def get_evidence_item(
    evidence_id: int,
) -> dict | None:
    init_evidence_integrity_database()

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT
                e.*,
                i.title AS investigation_title
            FROM investigation_evidence AS e
            JOIN investigations AS i
                ON i.id = e.investigation_id
            WHERE e.id = ?
            """,
            (evidence_id,),
        ).fetchone()

    return dict(row) if row else None


def verify_stored_evidence(
    evidence_id: int,
) -> dict:
    """
    Rebuild the original evidence envelope from the stored record,
    calculate SHA-256 again and compare it with the preserved hash.

    A verification event is appended to the chain-of-custody history.
    """
    import hashlib
    import json

    from wifi_trace.evidence import calculate_sha256

    evidence = get_evidence_item(evidence_id)

    if evidence is None:
        raise ValueError(
            "Evidence item not found."
        )

    try:
        payload = json.loads(
            evidence["payload_json"]
        )
    except (
        json.JSONDecodeError,
        TypeError,
    ):
        payload = None

    if not isinstance(payload, dict):
        calculated_hash = hashlib.sha256(
            str(
                evidence.get(
                    "payload_json",
                    "",
                )
            ).encode("utf-8")
        ).hexdigest()

        result = "FAILED"

    else:
        envelope_without_hash = {
            "schema":
                "wifi-trace-evidence-v1",
            "evidence_type":
                evidence["evidence_type"],
            "source":
                evidence["source"],
            "captured_at":
                evidence["captured_at"],
            "payload":
                payload,
        }

        calculated_hash = calculate_sha256(
            envelope_without_hash
        )

        result = (
            "VERIFIED"
            if calculated_hash
            == evidence["sha256"]
            else "FAILED"
        )

    verified_at = utc_now()

    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO evidence_verifications (
                evidence_id,
                verified_at,
                expected_sha256,
                calculated_sha256,
                result,
                verification_method
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                evidence_id,
                verified_at,
                evidence["sha256"],
                calculated_hash,
                result,
                "SHA-256 deterministic envelope verification",
            ),
        )

    return {
        "verification_id":
            int(cursor.lastrowid),
        "evidence_id":
            evidence_id,
        "verified_at":
            verified_at,
        "expected_sha256":
            evidence["sha256"],
        "calculated_sha256":
            calculated_hash,
        "result":
            result,
        "verification_method":
            (
                "SHA-256 deterministic "
                "envelope verification"
            ),
    }


def get_evidence_verifications(
    evidence_id: int,
) -> list[dict]:
    init_evidence_integrity_database()

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM evidence_verifications
            WHERE evidence_id = ?
            ORDER BY id DESC
            LIMIT 250
            """,
            (evidence_id,),
        ).fetchall()

    return [
        dict(row)
        for row in rows
    ]


def get_investigation_integrity(
    investigation_id: int,
) -> dict:
    """
    Verify every evidence item belonging to an investigation.

    This intentionally creates a verification record for each item,
    producing an auditable verification history.
    """
    investigation = get_investigation(
        investigation_id
    )

    if investigation is None:
        raise ValueError(
            "Investigation not found."
        )

    results = []

    for evidence in investigation["evidence"]:
        results.append(
            verify_stored_evidence(
                evidence["id"]
            )
        )

    verified = sum(
        1
        for item in results
        if item["result"] == "VERIFIED"
    )

    failed = sum(
        1
        for item in results
        if item["result"] == "FAILED"
    )

    return {
        "investigation_id":
            investigation_id,
        "evidence_count":
            len(results),
        "verified":
            verified,
        "failed":
            failed,
        "status":
            (
                "VERIFIED"
                if results and failed == 0
                else
                "EMPTY"
                if not results
                else
                "FAILED"
            ),
        "results":
            results,
    }
