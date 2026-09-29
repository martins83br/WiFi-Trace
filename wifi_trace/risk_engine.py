"""
WiFi-Trace Network Health & Forensic Risk Engine.

The engine evaluates locally observed network evidence using
deterministic, explainable rules.

It does NOT:
- claim that a network is compromised
- perform vulnerability exploitation
- perform active attacks
- infer unavailable evidence
"""

from __future__ import annotations

import ipaddress
from typing import Any


def _missing(value: Any) -> bool:
    return value is None or value == "" or value == []


def _finding(
    *,
    finding_id: str,
    title: str,
    severity: str,
    evidence: str,
    explanation: str,
    recommendation: str,
    score: int,
) -> dict:
    return {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "evidence": evidence,
        "explanation": explanation,
        "recommendation": recommendation,
        "score": score,
    }


def _gateway_is_private(
    gateway: str | None,
) -> bool | None:
    if not gateway:
        return None

    try:
        address = ipaddress.ip_address(gateway)
    except ValueError:
        return None

    return address.is_private


def evaluate_network(
    network: dict,
    recent_events: list[dict] | None = None,
) -> dict:
    """
    Evaluate current network evidence.

    Score represents attention level, not a probability
    of compromise.

    0-19   HEALTHY
    20-49  ATTENTION
    50+    ELEVATED
    """

    recent_events = recent_events or []
    findings: list[dict] = []

    security = (
        str(network.get("security") or "")
        .strip()
        .lower()
    )

    status = (
        str(network.get("status") or "")
        .strip()
        .lower()
    )

    gateway = network.get("gateway")
    dns_servers = network.get("dns_servers") or []

    # -----------------------------------------------------
    # Wi-Fi security
    # -----------------------------------------------------

    if security:
        if (
            "open" in security
            or security == "none"
        ):
            findings.append(
                _finding(
                    finding_id="wifi-open",
                    title="Open Wi-Fi security",
                    severity="HIGH",
                    evidence=(
                        network.get("security")
                        or "Open"
                    ),
                    explanation=(
                        "The observed Wi-Fi security "
                        "configuration does not indicate "
                        "link-layer encryption."
                    ),
                    recommendation=(
                        "Use WPA2 or WPA3 where supported."
                    ),
                    score=45,
                )
            )

        elif "wep" in security:
            findings.append(
                _finding(
                    finding_id="wifi-wep",
                    title="Legacy Wi-Fi security",
                    severity="HIGH",
                    evidence=network["security"],
                    explanation=(
                        "WEP is an obsolete Wi-Fi "
                        "security mechanism."
                    ),
                    recommendation=(
                        "Migrate the wireless network "
                        "to WPA2 or WPA3."
                    ),
                    score=40,
                )
            )

        elif "wpa3" in security:
            findings.append(
                _finding(
                    finding_id="wifi-modern",
                    title="Modern Wi-Fi protection observed",
                    severity="INFO",
                    evidence=network["security"],
                    explanation=(
                        "The current observation reports "
                        "WPA3 protection."
                    ),
                    recommendation=(
                        "No action required from this "
                        "observation."
                    ),
                    score=0,
                )
            )

        elif "wpa2" in security:
            findings.append(
                _finding(
                    finding_id="wifi-protected",
                    title="Wi-Fi encryption observed",
                    severity="INFO",
                    evidence=network["security"],
                    explanation=(
                        "The current observation reports "
                        "WPA2 protection."
                    ),
                    recommendation=(
                        "Keep router firmware and wireless "
                        "credentials maintained."
                    ),
                    score=0,
                )
            )

    else:
        findings.append(
            _finding(
                finding_id="security-unavailable",
                title="Wi-Fi security unavailable",
                severity="NOTICE",
                evidence="Unavailable",
                explanation=(
                    "The operating system did not provide "
                    "usable Wi-Fi security evidence."
                ),
                recommendation=(
                    "Treat this as unavailable evidence, "
                    "not evidence of an insecure network."
                ),
                score=5,
            )
        )

    # -----------------------------------------------------
    # Connection state
    # -----------------------------------------------------

    if status and status != "connected":
        findings.append(
            _finding(
                finding_id="wifi-state",
                title="Wi-Fi not connected",
                severity="NOTICE",
                evidence=(
                    network.get("status")
                    or "Unavailable"
                ),
                explanation=(
                    "The current collector does not report "
                    "an active Wi-Fi connection."
                ),
                recommendation=(
                    "Confirm the expected network "
                    "connection state."
                ),
                score=10,
            )
        )

    # -----------------------------------------------------
    # Gateway
    # -----------------------------------------------------

    gateway_private = _gateway_is_private(
        gateway
    )

    if not gateway:
        findings.append(
            _finding(
                finding_id="gateway-missing",
                title="Default gateway unavailable",
                severity="NOTICE",
                evidence="Unavailable",
                explanation=(
                    "No IPv4 default gateway was available "
                    "in the current observation."
                ),
                recommendation=(
                    "Confirm local routing if Internet or "
                    "LAN connectivity is expected."
                ),
                score=10,
            )
        )

    elif gateway_private is False:
        findings.append(
            _finding(
                finding_id="gateway-public",
                title="Public default gateway observed",
                severity="NOTICE",
                evidence=str(gateway),
                explanation=(
                    "The default gateway is not within a "
                    "private IPv4 address range."
                ),
                recommendation=(
                    "Confirm that this routing configuration "
                    "is expected for this environment."
                ),
                score=10,
            )
        )

    # -----------------------------------------------------
    # DNS evidence
    # -----------------------------------------------------

    if not dns_servers:
        findings.append(
            _finding(
                finding_id="dns-unavailable",
                title="DNS configuration unavailable",
                severity="NOTICE",
                evidence="No DNS servers observed",
                explanation=(
                    "The collector did not obtain DNS "
                    "resolver evidence."
                ),
                recommendation=(
                    "Confirm resolver configuration if "
                    "name resolution is expected."
                ),
                score=5,
            )
        )

    # -----------------------------------------------------
    # Recent forensic changes
    # -----------------------------------------------------

    important_fields = {
        "gateway",
        "security",
        "dns_servers",
        "ssid",
        "ip_address",
    }

    important_events = [
        event
        for event in recent_events
        if event.get("event_type") == "change"
        and event.get("field_name")
        in important_fields
    ]

    if important_events:
        newest = important_events[0]

        findings.append(
            _finding(
                finding_id="recent-network-change",
                title="Recent network change observed",
                severity="NOTICE",
                evidence=(
                    f'{newest.get("field_label", "Network")} '
                    f'changed from '
                    f'{newest.get("old_value") or "Unavailable"} '
                    f'to '
                    f'{newest.get("new_value") or "Unavailable"}'
                ),
                explanation=(
                    "WiFi-Trace has historical evidence of "
                    "a recent network configuration change."
                ),
                recommendation=(
                    "Review the Timeline or Network Diff "
                    "to determine whether the change was "
                    "expected."
                ),
                score=10,
            )
        )

    # -----------------------------------------------------
    # Radio evidence availability
    # -----------------------------------------------------

    signal = network.get("signal")
    noise = network.get("noise")

    if _missing(signal):
        findings.append(
            _finding(
                finding_id="signal-unavailable",
                title="Signal evidence unavailable",
                severity="INFO",
                evidence="Signal: Unavailable",
                explanation=(
                    "The operating system did not provide "
                    "usable RSSI evidence."
                ),
                recommendation=(
                    "No security conclusion should be made "
                    "from missing signal telemetry."
                ),
                score=0,
            )
        )

    if _missing(noise):
        findings.append(
            _finding(
                finding_id="noise-unavailable",
                title="Noise evidence unavailable",
                severity="INFO",
                evidence="Noise: Unavailable",
                explanation=(
                    "The operating system did not provide "
                    "usable noise-floor evidence."
                ),
                recommendation=(
                    "No security conclusion should be made "
                    "from missing radio telemetry."
                ),
                score=0,
            )
        )

    # -----------------------------------------------------
    # Score
    # -----------------------------------------------------

    raw_score = sum(
        finding["score"]
        for finding in findings
    )

    score = min(raw_score, 100)

    if score >= 50:
        posture = "ELEVATED"
    elif score >= 20:
        posture = "ATTENTION"
    else:
        posture = "HEALTHY"

    actionable = [
        finding
        for finding in findings
        if finding["severity"]
        in {"HIGH", "NOTICE"}
    ]

    informational = [
        finding
        for finding in findings
        if finding["severity"] == "INFO"
    ]

    return {
        "posture": posture,
        "attention_score": score,
        "finding_count": len(findings),
        "actionable_count": len(actionable),
        "informational_count": len(informational),
        "findings": findings,
        "actionable": actionable,
        "informational": informational,
        "disclaimer": (
            "The attention score summarizes deterministic "
            "observations. It is not a probability of "
            "compromise and does not prove malicious activity."
        ),
    }
