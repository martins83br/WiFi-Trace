"""
WiFi-Trace Forensic Network Diff Engine.

Compares two historical network snapshots without modifying evidence.

Classification:
- SIGNIFICANT: configuration/state change relevant to investigation.
- TELEMETRY: normal operational/radio variation.
- UNCHANGED: no meaningful difference.
- ADDED / REMOVED: evidence became available or unavailable.

No unavailable evidence is inferred.
"""

from __future__ import annotations

from typing import Any


FIELD_DEFINITIONS = (
    ("gateway", "Default Gateway", "STRUCTURAL"),
    ("interface", "Interface", "STRUCTURAL"),
    ("ip_address", "Local IPv4", "STRUCTURAL"),
    ("ssid", "SSID", "STRUCTURAL"),
    ("wifi_status", "Wi-Fi Status", "STRUCTURAL"),
    ("phy_mode", "Wi-Fi Standard", "STRUCTURAL"),
    ("channel", "Channel", "STRUCTURAL"),
    ("security", "Security", "STRUCTURAL"),
    ("signal", "Signal", "RADIO"),
    ("noise", "Noise", "RADIO"),
    ("snr", "SNR", "RADIO"),
    ("tx_rate", "Transmit Rate", "TELEMETRY"),
    ("country", "Country", "STRUCTURAL"),
    ("dns_servers", "DNS Servers", "STRUCTURAL"),
)

RADIO_THRESHOLDS = {
    "signal": 5,
    "noise": 5,
    "snr": 5,
}


def _missing(value: Any) -> bool:
    return (
        value is None
        or value == ""
        or value == []
        or value == ()
    )


def _normalize(value: Any) -> Any:
    if isinstance(value, list):
        return tuple(str(item) for item in value)

    return value


def _numeric(value: Any) -> float | None:
    if value is None:
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _display(value: Any, field: str) -> str:
    if _missing(value):
        return "Unavailable"

    if isinstance(value, (list, tuple)):
        return ", ".join(
            str(item)
            for item in value
        )

    if field in {"signal", "noise"}:
        return f"{value} dBm"

    if field == "snr":
        return f"{value} dB"

    if field == "tx_rate":
        return f"{value} Mbps"

    return str(value)


def _raw_state(
    before: Any,
    after: Any,
) -> str:
    before_missing = _missing(before)
    after_missing = _missing(after)

    if before_missing and after_missing:
        return "UNCHANGED"

    if before_missing:
        return "ADDED"

    if after_missing:
        return "REMOVED"

    if _normalize(before) == _normalize(after):
        return "UNCHANGED"

    return "CHANGED"


def _classify_change(
    field: str,
    field_type: str,
    before: Any,
    after: Any,
    state: str,
) -> tuple[str, str]:
    """
    Return:
        classification
        explanation
    """

    if state == "UNCHANGED":
        return (
            "UNCHANGED",
            "No observed difference.",
        )

    if state == "ADDED":
        if field_type == "TELEMETRY":
            return (
                "TELEMETRY",
                "Telemetry became available.",
            )

        return (
            "SIGNIFICANT",
            "Evidence became available.",
        )

    if state == "REMOVED":
        if field_type == "TELEMETRY":
            return (
                "TELEMETRY",
                "Telemetry became unavailable.",
            )

        return (
            "SIGNIFICANT",
            "Previously observed evidence became unavailable.",
        )

    if field_type == "STRUCTURAL":
        return (
            "SIGNIFICANT",
            "Network configuration or state changed.",
        )

    if field_type == "TELEMETRY":
        return (
            "TELEMETRY",
            "Operational telemetry changed.",
        )

    if field_type == "RADIO":
        before_number = _numeric(before)
        after_number = _numeric(after)

        if (
            before_number is None
            or after_number is None
        ):
            return (
                "TELEMETRY",
                "Radio telemetry changed.",
            )

        delta = abs(
            after_number - before_number
        )

        threshold = RADIO_THRESHOLDS.get(
            field,
            5,
        )

        if delta >= threshold:
            return (
                "SIGNIFICANT",
                (
                    f"Radio telemetry changed by "
                    f"{delta:g}; threshold is "
                    f"{threshold}."
                ),
            )

        return (
            "TELEMETRY",
            (
                f"Radio telemetry changed by "
                f"{delta:g}; below the "
                f"{threshold} threshold."
            ),
        )

    return (
        "TELEMETRY",
        "Observed value changed.",
    )


def _build_summary(
    significant_count: int,
    telemetry_count: int,
    added_count: int,
    removed_count: int,
) -> str:
    if significant_count == 0:
        if telemetry_count == 0:
            return (
                "No meaningful network differences were "
                "observed between these snapshots."
            )

        return (
            "Network configuration remained stable. "
            "Only operational or radio telemetry "
            "variation was observed."
        )

    parts = [
        (
            f"{significant_count} significant "
            f"network change"
            f"{'' if significant_count == 1 else 's'} "
            f"were observed."
        )
    ]

    if added_count:
        parts.append(
            f"{added_count} field"
            f"{'' if added_count == 1 else 's'} "
            f"became available."
        )

    if removed_count:
        parts.append(
            f"{removed_count} field"
            f"{'' if removed_count == 1 else 's'} "
            f"became unavailable."
        )

    if telemetry_count:
        parts.append(
            (
                f"{telemetry_count} additional "
                f"telemetry variation"
                f"{'' if telemetry_count == 1 else 's'} "
                f"were also observed."
            )
        )

    return " ".join(parts)


def compare_snapshots(
    before: dict,
    after: dict,
) -> dict:
    """
    Compare two historical WiFi-Trace snapshots.
    """

    changes = []

    state_counts = {
        "UNCHANGED": 0,
        "CHANGED": 0,
        "ADDED": 0,
        "REMOVED": 0,
    }

    classification_counts = {
        "SIGNIFICANT": 0,
        "TELEMETRY": 0,
        "UNCHANGED": 0,
    }

    for field, label, field_type in FIELD_DEFINITIONS:
        before_value = before.get(field)
        after_value = after.get(field)

        state = _raw_state(
            before_value,
            after_value,
        )

        classification, explanation = (
            _classify_change(
                field=field,
                field_type=field_type,
                before=before_value,
                after=after_value,
                state=state,
            )
        )

        state_counts[state] += 1
        classification_counts[
            classification
        ] += 1

        changes.append(
            {
                "field": field,
                "label": label,
                "field_type": field_type,
                "before": before_value,
                "after": after_value,
                "before_display": _display(
                    before_value,
                    field,
                ),
                "after_display": _display(
                    after_value,
                    field,
                ),
                "state": state,
                "classification": classification,
                "explanation": explanation,
            }
        )

    meaningful_changes = [
        item
        for item in changes
        if item["state"] != "UNCHANGED"
    ]

    significant_changes = [
        item
        for item in changes
        if item["classification"] == "SIGNIFICANT"
    ]

    telemetry_changes = [
        item
        for item in changes
        if item["classification"] == "TELEMETRY"
    ]

    summary = _build_summary(
        significant_count=len(
            significant_changes
        ),
        telemetry_count=len(
            telemetry_changes
        ),
        added_count=state_counts["ADDED"],
        removed_count=state_counts["REMOVED"],
    )

    return {
        "before_snapshot": {
            "id": before.get("id"),
            "observed_at": before.get(
                "observed_at"
            ),
        },
        "after_snapshot": {
            "id": after.get("id"),
            "observed_at": after.get(
                "observed_at"
            ),
        },
        "counts": state_counts,
        "classification_counts":
            classification_counts,
        "changes": changes,
        "meaningful_changes":
            meaningful_changes,
        "significant_changes":
            significant_changes,
        "telemetry_changes":
            telemetry_changes,
        "changed": bool(
            meaningful_changes
        ),
        "significant": bool(
            significant_changes
        ),
        "summary": summary,
    }
