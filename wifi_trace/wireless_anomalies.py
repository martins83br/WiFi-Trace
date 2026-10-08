"""
WiFi-Trace Wireless Anomaly Detection Engine.

Analyzes recorded wireless telemetry.
Does not infer security attacks from radio-quality changes.
"""

from __future__ import annotations

import math


def valid_number(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def detect_wireless_anomalies(
    measurements: list[dict],
    *,
    minimum_samples: int = 3,
) -> dict:
    findings = []

    if len(measurements) < minimum_samples:
        return {
            "status": "insufficient_data",
            "sample_count": len(measurements),
            "findings": [],
            "disclaimer": (
                "Insufficient telemetry for reliable trend analysis."
            ),
        }

    signals = [
        row["signal_dbm"]
        for row in measurements
        if valid_number(row.get("signal_dbm"))
    ]

    snrs = [
        row["snr_db"]
        for row in measurements
        if valid_number(row.get("snr_db"))
    ]

    if len(signals) >= minimum_samples:
        drops = [
            signals[i - 1] - signals[i]
            for i in range(1, len(signals))
        ]

        largest_drop = max(drops, default=0)

        if largest_drop >= 15:
            findings.append({
                "code": "SIGNAL_DROP",
                "severity": "warning",
                "title": "Significant RSSI drop",
                "description": (
                    f"Observed an RSSI decrease of "
                    f"{largest_drop:.1f} dB between "
                    "consecutive valid measurements."
                ),
            })

        variation = max(signals) - min(signals)

        if variation >= 20:
            findings.append({
                "code": "HIGH_SIGNAL_VARIATION",
                "severity": "warning",
                "title": "High signal variation",
                "description": (
                    f"Observed RSSI range: {variation:.1f} dB."
                ),
            })

    if len(snrs) >= minimum_samples:
        low_snr = [value for value in snrs if value < 15]

        if low_snr:
            findings.append({
                "code": "LOW_SNR",
                "severity": "warning",
                "title": "Low signal-to-noise ratio",
                "description": (
                    f"{len(low_snr)} of {len(snrs)} valid "
                    "SNR measurements were below 15 dB."
                ),
            })

    return {
        "status": "warning" if findings else "normal",
        "sample_count": len(measurements),
        "findings": findings,
        "disclaimer": (
            "Wireless anomalies indicate potential connectivity "
            "or environmental issues, not proof of an attack."
        ),
    }
