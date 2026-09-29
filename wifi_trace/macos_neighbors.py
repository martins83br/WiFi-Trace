"""
WiFi-Trace macOS Neighbor Evidence Collector.

Purpose:
- Obtain IP -> MAC evidence for IPv4 hosts already observed by WiFi-Trace.
- Use only local operating-system neighbor information.
- Never perform port scanning.
- Never contact external services.
- Never infer a MAC address when the OS does not provide one.

Collection strategy:
1. Validate that the target is a private IPv4 address.
2. Send one bounded ICMP probe to refresh the local neighbor cache.
3. Query macOS ARP for that exact IP.
4. Validate and normalize the returned MAC.
5. Return explicit evidence metadata.

This module is intentionally macOS-specific.
"""

from __future__ import annotations

import ipaddress
import platform
import re
import subprocess
from dataclasses import asdict, dataclass

from wifi_trace.mac_evidence import analyze_mac, normalize_mac


ARP_PATH = "/usr/sbin/arp"
PING_PATH = "/sbin/ping"

MAC_PATTERN = re.compile(
    r"\b(?:[0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}\b"
)


@dataclass(frozen=True)
class NeighborEvidence:
    ip_address: str
    mac_address: str | None
    available: bool
    source: str
    note: str

    def to_dict(self) -> dict:
        return asdict(self)


def _validate_private_ipv4(value: str) -> str:
    """
    Validate a private IPv4 target.

    WiFi-Trace neighbor collection is intentionally restricted to
    private IPv4 addresses. This prevents this collector from becoming
    a general-purpose remote scanner.
    """

    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("Invalid IPv4 address.") from exc

    if address.version != 4:
        raise ValueError("Only IPv4 addresses are supported.")

    if not address.is_private:
        raise ValueError(
            "Neighbor collection is restricted to private IPv4 addresses."
        )

    if address.is_loopback:
        raise ValueError("Loopback addresses are not valid LAN targets.")

    if address.is_multicast:
        raise ValueError("Multicast addresses are not valid LAN targets.")

    if address.is_unspecified:
        raise ValueError("Unspecified addresses are not valid LAN targets.")

    return str(address)


def _refresh_neighbor_cache(ip_address: str) -> None:
    """
    Send one bounded ICMP probe.

    Failure is acceptable. A device may ignore ICMP while still having
    an existing neighbor-cache entry.
    """

    if platform.system() != "Darwin":
        return

    try:
        subprocess.run(
            [
                PING_PATH,
                "-c",
                "1",
                "-W",
                "300",
                ip_address,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass


def _query_arp(ip_address: str) -> str:
    """
    Query macOS ARP for one exact IPv4 address.
    """

    try:
        result = subprocess.run(
            [
                ARP_PATH,
                "-n",
                ip_address,
            ],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""

    output = result.stdout.strip()

    if not output:
        output = result.stderr.strip()

    return output


def _extract_mac(output: str) -> str | None:
    """
    Extract and normalize a MAC from ARP output.
    """

    if not output:
        return None

    match = MAC_PATTERN.search(output)

    if not match:
        return None

    return normalize_mac(match.group(0))


def collect_neighbor(ip_address: str) -> NeighborEvidence:
    """
    Collect MAC evidence for one private IPv4 host.
    """

    ip_address = _validate_private_ipv4(ip_address)

    if platform.system() != "Darwin":
        return NeighborEvidence(
            ip_address=ip_address,
            mac_address=None,
            available=False,
            source="macOS ARP Neighbor Cache",
            note=(
                "This collector is currently available only on macOS."
            ),
        )

    _refresh_neighbor_cache(ip_address)

    output = _query_arp(ip_address)
    mac_address = _extract_mac(output)

    if mac_address is None:
        return NeighborEvidence(
            ip_address=ip_address,
            mac_address=None,
            available=False,
            source="macOS ARP Neighbor Cache",
            note=(
                "The operating system did not provide valid MAC "
                "evidence for this IPv4 address."
            ),
        )

    mac = analyze_mac(mac_address)

    if not mac.valid:
        return NeighborEvidence(
            ip_address=ip_address,
            mac_address=None,
            available=False,
            source="macOS ARP Neighbor Cache",
            note="The neighbor-cache MAC value was invalid.",
        )

    if mac.multicast:
        return NeighborEvidence(
            ip_address=ip_address,
            mac_address=None,
            available=False,
            source="macOS ARP Neighbor Cache",
            note=(
                "A multicast MAC was returned and was rejected as "
                "device identity evidence."
            ),
        )

    return NeighborEvidence(
        ip_address=ip_address,
        mac_address=mac.normalized,
        available=True,
        source="macOS ARP Neighbor Cache",
        note=(
            "IP-to-MAC mapping observed from the local macOS "
            "neighbor cache after a bounded reachability probe."
        ),
    )


def collect_neighbors(
    ip_addresses: list[str],
) -> list[dict]:
    """
    Collect neighbor evidence only for explicitly supplied IPs.

    The function does not generate address ranges and does not discover
    arbitrary remote targets.
    """

    results = []

    seen = set()

    for value in ip_addresses:
        try:
            ip_address = _validate_private_ipv4(value)
        except ValueError:
            continue

        if ip_address in seen:
            continue

        seen.add(ip_address)

        results.append(
            collect_neighbor(ip_address).to_dict()
        )

    return results
