import re
import socket
import subprocess
from typing import Optional

import psutil


def _run(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        output = result.stdout.strip()

        if not output:
            output = result.stderr.strip()

        return output
    except (OSError, subprocess.TimeoutExpired):
        return ""


def get_default_route() -> dict:
    output = _run(["route", "-n", "get", "default"])

    gateway = None
    interface = None

    gateway_match = re.search(r"gateway:\s+(\S+)", output)
    interface_match = re.search(r"interface:\s+(\S+)", output)

    if gateway_match:
        gateway = gateway_match.group(1)

    if interface_match:
        interface = interface_match.group(1)

    return {
        "gateway": gateway,
        "interface": interface,
    }


def get_ipv4(interface: Optional[str]) -> Optional[str]:
    if not interface:
        return None

    for address in psutil.net_if_addrs().get(interface, []):
        if address.family == socket.AF_INET:
            return address.address

    return None


def get_dns_servers() -> list[str]:
    output = _run(["scutil", "--dns"])

    servers = []
    seen = set()

    for server in re.findall(
        r"nameserver\[\d+\]\s*:\s*(\S+)", output
    ):
        if server not in seen:
            seen.add(server)
            servers.append(server)

    return servers


def get_wifi_info() -> dict:
    output = _run(["system_profiler", "SPAirPortDataType"])

    info = {
        "ssid": None,
        "status": None,
        "phy_mode": None,
        "channel": None,
        "security": None,
        "signal": None,
        "noise": None,
        "tx_rate": None,
        "country": None,
    }

    status = re.search(r"^\s*Status:\s*(.+)$", output, re.MULTILINE)

    if status:
        info["status"] = status.group(1).strip()

    current_match = re.search(
        r"Current Network Information:\s*\n"
        r"\s+(.+?):\s*\n"
        r"(.*?)(?=\n\s+Other Local Wi-Fi Networks:|\Z)",
        output,
        re.DOTALL,
    )

    if not current_match:
        return info

    ssid = current_match.group(1).strip()
    block = current_match.group(2)

    if ssid != "<redacted>":
        info["ssid"] = ssid

    patterns = {
        "phy_mode": r"PHY Mode:\s*(.+)",
        "channel": r"Channel:\s*(.+)",
        "security": r"Security:\s*(.+)",
        "country": r"Country Code:\s*(.+)",
        "tx_rate": r"Transmit Rate:\s*(.+)",
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, block)

        if match:
            info[key] = match.group(1).strip()

    signal_noise = re.search(
        r"Signal / Noise:\s*(-?\d+)\s*dBm\s*/\s*(-?\d+)\s*dBm",
        block,
    )

    if signal_noise:
        info["signal"] = int(signal_noise.group(1))
        info["noise"] = int(signal_noise.group(2))

    return info


def collect_network_info() -> dict:
    route = get_default_route()
    wifi = get_wifi_info()

    interface = route["interface"]

    # Validate Wi-Fi radio telemetry.
    #
    # RSSI/noise readings such as 0 dBm can appear temporarily when macOS
    # cannot provide a valid radio measurement. They must be treated as
    # unavailable rather than as real forensic changes.
    signal = wifi.get("signal")
    noise = wifi.get("noise")

    if not isinstance(signal, int) or not (-100 <= signal <= -1):
        signal = None

    if not isinstance(noise, int) or not (-120 <= noise <= -1):
        noise = None

    return {
        "interface": interface,
        "ip_address": get_ipv4(interface),
        "gateway": route["gateway"],
        "dns_servers": get_dns_servers(),
        **wifi,
        "signal": signal,
        "noise": noise,
    }


def get_saved_wifi_networks() -> list[dict]:
    """Return Wi-Fi networks saved on this Mac without reading passwords."""
    output = _run(
        ["networksetup", "-listpreferredwirelessnetworks", "en0"]
    )

    networks = []

    for line in output.splitlines():
        name = line.strip()

        if not name:
            continue

        if name.startswith("Preferred networks on"):
            continue

        networks.append(
            {
                "ssid": name,
                "password_stored": None,
            }
        )

    return networks
