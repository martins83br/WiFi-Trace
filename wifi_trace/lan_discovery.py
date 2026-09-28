from __future__ import annotations

import ipaddress
import platform
import subprocess
import threading
from datetime import datetime, timezone

from wifi_trace.collectors.macos import collect_network_info
from wifi_trace.database import observe_device


class LANDiscovery:
    """
    Conservative LAN host discovery.

    Evidence produced by this module means only:
    "This IPv4 address responded to an ICMP reachability probe."

    It does NOT mean:
    - every connected device was discovered
    - the host belongs to a particular person
    - the host remained connected after the observation
    """

    def __init__(
        self,
        interval: int = 300,
        max_hosts: int = 254,
    ):
        self.interval = interval
        self.max_hosts = max_hosts

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

        self.running = False
        self.last_scan: str | None = None
        self.last_error: str | None = None
        self.last_hosts_found = 0

    def _ping(self, address: str) -> bool:
        system = platform.system()

        if system == "Darwin":
            command = [
                "/sbin/ping",
                "-c",
                "1",
                "-W",
                "300",
                address,
            ]

        elif system == "Linux":
            command = [
                "ping",
                "-c",
                "1",
                "-W",
                "1",
                address,
            ]

        elif system == "Windows":
            command = [
                "ping",
                "-n",
                "1",
                "-w",
                "400",
                address,
            ]

        else:
            return False

        try:
            result = subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2,
                check=False,
            )

            return result.returncode == 0

        except (
            OSError,
            subprocess.TimeoutExpired,
        ):
            return False

    def _determine_network(
        self,
        local_ip: str,
    ) -> ipaddress.IPv4Network | None:
        """
        v1 intentionally assumes /24 for private IPv4 LANs.

        We do NOT probe outside the local /24 containing this host.
        A future platform collector can obtain the real interface
        netmask and remove this limitation.
        """

        try:
            ip = ipaddress.ip_address(local_ip)

            if not isinstance(ip, ipaddress.IPv4Address):
                return None

            if not ip.is_private:
                return None

            return ipaddress.ip_network(
                f"{local_ip}/24",
                strict=False,
            )

        except ValueError:
            return None

    def scan_once(self) -> dict:
        network_info = collect_network_info()

        local_ip = network_info.get("ip_address")
        gateway = network_info.get("gateway")

        if not local_ip:
            raise RuntimeError(
                "Local IPv4 address unavailable."
            )

        network = self._determine_network(local_ip)

        if network is None:
            raise RuntimeError(
                "No safe private IPv4 /24 network available."
            )

        candidates = [
            str(address)
            for address in network.hosts()
            if str(address) != local_ip
        ]

        candidates = candidates[: self.max_hosts]

        responsive: list[str] = []

        # Keep concurrency modest.
        # This avoids 254 sequential multi-second waits while also
        # avoiding an aggressive burst of probes.
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=16) as executor:
            results = executor.map(
                self._ping,
                candidates,
            )

            for address, responded in zip(
                candidates,
                results,
            ):
                if responded:
                    responsive.append(address)

        observed_at = datetime.now(
            timezone.utc
        ).isoformat()

        for address in responsive:
            if address == gateway:
                # Gateway is already recorded by the default-route
                # evidence source. Do not create a duplicate identity.
                continue

            observe_device(
                device_key=f"lan-ip:{address}",
                device_type="LAN Host",
                display_name=f"Observed Host {address}",
                ip_address=address,
                source="ICMP Reachability",
                evidence_note=(
                    "IPv4 address responded to an ICMP "
                    "reachability probe on the local LAN."
                ),
                observed_at=observed_at,
            )

        with self._lock:
            self.last_scan = observed_at
            self.last_hosts_found = len(responsive)
            self.last_error = None

        return {
            "network": str(network),
            "hosts_tested": len(candidates),
            "responsive_hosts": responsive,
        }

    def _loop(self) -> None:
        self.running = True

        try:
            # Do not immediately scan when the application starts.
            # The normal forensic monitor starts immediately.
            while not self._stop_event.wait(self.interval):
                try:
                    self.scan_once()

                except Exception as exc:
                    with self._lock:
                        self.last_error = (
                            f"{type(exc).__name__}: {exc}"
                        )

        finally:
            self.running = False

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()

        self._thread = threading.Thread(
            target=self._loop,
            name="wifi-trace-lan-discovery",
            daemon=True,
        )

        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

        self.running = False

    def status(self) -> dict:
        with self._lock:
            return {
                "running": self.running,
                "interval": self.interval,
                "last_scan": self.last_scan,
                "last_hosts_found": self.last_hosts_found,
                "last_error": self.last_error,
            }


lan_discovery = LANDiscovery(
    interval=300,
    max_hosts=254,
)
