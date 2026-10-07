"""
WiFi-Trace — Wireless Diagnostics Engine.

Interprets observed radio telemetry without claiming
to measure Internet speed or detect security breaches.
"""

from __future__ import annotations


def _valid(value, minimum, maximum):
    if isinstance(value, bool):
        return None
    if not isinstance(value, (int, float)):
        return None
    if not minimum <= value <= maximum:
        return None
    return value


def analyze_wifi(network: dict) -> dict:
    signal = _valid(network.get("signal"), -100, -1)
    noise = _valid(network.get("noise"), -120, -1)

    snr = None
    if signal is not None and noise is not None:
        calculated = signal - noise
        if 0 <= calculated <= 100:
            snr = calculated

    findings = []

    if signal is None:
        signal_quality = "UNAVAILABLE"
        findings.append(
            "Signal strength could not be measured."
        )
    elif signal >= -55:
        signal_quality = "EXCELLENT"
    elif signal >= -67:
        signal_quality = "GOOD"
    elif signal >= -75:
        signal_quality = "FAIR"
        findings.append(
            "Signal strength may affect connection stability."
        )
    else:
        signal_quality = "POOR"
        findings.append(
            "Weak signal observed. Consider improving "
            "access point placement."
        )

    if snr is None:
        snr_quality = "UNAVAILABLE"
    elif snr >= 40:
        snr_quality = "EXCELLENT"
    elif snr >= 25:
        snr_quality = "GOOD"
    elif snr >= 15:
        snr_quality = "FAIR"
        findings.append(
            "Moderate signal-to-noise ratio observed."
        )
    else:
        snr_quality = "POOR"
        findings.append(
            "Low signal-to-noise ratio may affect reliability."
        )

    raw_rate = network.get("tx_rate")
    tx_rate = None

    if isinstance(raw_rate, (int, float)):
        tx_rate = float(raw_rate)
    elif isinstance(raw_rate, str):
        try:
            tx_rate = float(raw_rate.strip().split()[0])
        except (ValueError, IndexError):
            pass

    if tx_rate is not None and tx_rate <= 0:
        tx_rate = None

    return {
        "signal_dbm": signal,
        "noise_dbm": noise,
        "snr_db": snr,
        "signal_quality": signal_quality,
        "snr_quality": snr_quality,
        "tx_rate_mbps": tx_rate,
        "findings": findings,
        "disclaimer": (
            "Radio diagnostics are based on local observations. "
            "Transmit rate is a negotiated link rate, "
            "not measured Internet throughput."
        ),
    }
