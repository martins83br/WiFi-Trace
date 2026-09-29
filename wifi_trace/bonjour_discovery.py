from __future__ import annotations

import re
import subprocess
import threading
import time
from dataclasses import dataclass, asdict


SERVICE_TYPES = {
    "_ipp._tcp": ("Printer", "IPP Printing", "High"),
    "_ipps._tcp": ("Printer", "Secure IPP Printing", "High"),
    "_printer._tcp": ("Printer", "Network Printing", "High"),
    "_pdl-datastream._tcp": ("Printer", "Printer Data Stream", "High"),
    "_scanner._tcp": ("Scanner", "Network Scanner", "High"),

    "_airplay._tcp": ("Media Device", "AirPlay", "Medium"),
    "_raop._tcp": ("Media Device", "AirPlay Audio", "Medium"),
    "_googlecast._tcp": ("Media Device", "Google Cast", "High"),

    "_workstation._tcp": ("Computer", "Workstation", "Medium"),
    "_ssh._tcp": ("Computer", "SSH", "Low"),
    "_smb._tcp": ("Computer", "SMB File Sharing", "Low"),

    "_device-info._tcp": ("Device", "Device Information", "Low"),
    "_http._tcp": ("Device", "HTTP Service", "Low"),
    "_https._tcp": ("Device", "HTTPS Service", "Low"),
}


@dataclass
class BonjourObservation:
    service_type: str
    service_name: str
    service_label: str
    category: str
    confidence: str
    hostname: str | None = None
    ip_address: str | None = None
    port: int | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _run_for_window(
    command: list[str],
    seconds: float,
) -> str:
    """
    Run dns-sd briefly and collect output.

    dns-sd is normally long-running, so it is terminated after
    a controlled observation window.
    """

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    lines: list[str] = []

    def reader() -> None:
        if process.stdout is None:
            return

        for line in process.stdout:
            lines.append(line.rstrip())

    thread = threading.Thread(
        target=reader,
        daemon=True,
    )
    thread.start()

    time.sleep(seconds)

    if process.poll() is None:
        process.terminate()

    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)

    thread.join(timeout=1)

    return "\n".join(lines)


def browse_service(
    service_type: str,
    seconds: float = 2.0,
) -> list[str]:
    """
    Return Bonjour instance names observed for a service type.
    """

    output = _run_for_window(
        [
            "/usr/bin/dns-sd",
            "-B",
            service_type,
            "local.",
        ],
        seconds,
    )

    names: list[str] = []

    for line in output.splitlines():
        if " Add " not in line:
            continue

        # Typical dns-sd browse output ends with the instance name.
        match = re.search(
            r"\s+Add\s+\d+\s+\d+\s+\S+\s+\S+\s+(.+)$",
            line,
        )

        if not match:
            continue

        name = match.group(1).strip()

        if name and name not in names:
            names.append(name)

    return names


def resolve_service(
    service_type: str,
    service_name: str,
    seconds: float = 1.5,
) -> tuple[str | None, int | None]:
    """
    Resolve Bonjour service instance to hostname and port.
    """

    output = _run_for_window(
        [
            "/usr/bin/dns-sd",
            "-L",
            service_name,
            service_type,
            "local.",
        ],
        seconds,
    )

    for line in output.splitlines():
        match = re.search(
            r"can be reached at\s+(\S+):(\d+)",
            line,
            re.IGNORECASE,
        )

        if match:
            hostname = match.group(1).rstrip(".")
            port = int(match.group(2))
            return hostname, port

    return None, None


def resolve_hostname_ipv4(
    hostname: str,
    seconds: float = 1.5,
) -> str | None:
    """
    Ask Bonjour specifically for an IPv4 address.
    """

    hostname = hostname.rstrip(".")

    output = _run_for_window(
        [
            "/usr/bin/dns-sd",
            "-G",
            "v4",
            hostname,
        ],
        seconds,
    )

    for line in output.splitlines():
        # Find private IPv4 values in dns-sd output.
        match = re.search(
            r"\b("
            r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
            r")\b",
            line,
        )

        if match:
            return match.group(1)

    return None


def discover_bonjour(
    browse_seconds: float = 2.0,
) -> list[dict]:
    """
    Observe selected Bonjour service classes.

    This is service discovery, not a port scan.
    """

    observations: list[BonjourObservation] = []

    for service_type, (
        category,
        service_label,
        confidence,
    ) in SERVICE_TYPES.items():

        names = browse_service(
            service_type,
            seconds=browse_seconds,
        )

        for service_name in names:
            hostname, port = resolve_service(
                service_type,
                service_name,
            )

            ip_address = None

            if hostname:
                ip_address = resolve_hostname_ipv4(
                    hostname,
                )

            observations.append(
                BonjourObservation(
                    service_type=service_type,
                    service_name=service_name,
                    service_label=service_label,
                    category=category,
                    confidence=confidence,
                    hostname=hostname,
                    ip_address=ip_address,
                    port=port,
                )
            )

    return [
        observation.to_dict()
        for observation in observations
    ]


if __name__ == "__main__":
    results = discover_bonjour()

    print()
    print("WiFi-Trace Bonjour Discovery")
    print("============================")
    print()

    if not results:
        print("No selected Bonjour services observed.")

    for item in results:
        print(
            f'{item["ip_address"] or "IP unavailable":15} | '
            f'{item["category"]:12} | '
            f'{item["service_label"]:20} | '
            f'{item["service_name"]}'
        )
