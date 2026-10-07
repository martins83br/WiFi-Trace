from __future__ import annotations

import threading
from datetime import datetime, timezone

from wifi_trace.collectors.macos import collect_network_info
from wifi_trace.database import record_core_devices, save_snapshot
from wifi_trace.wifi_diagnostics import analyze_wifi
from wifi_trace.wireless_history import save_wireless_measurement


class NetworkMonitor:
    def __init__(self, interval: int = 30):
        self.interval = interval
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

        self.running = False
        self.last_observation: str | None = None
        self.last_error: str | None = None

    def _collect(self) -> None:
        try:
            network = collect_network_info()

            # Preserve the network state in forensic history.
            save_snapshot(network)

            # Record only devices supported by direct local evidence.
            record_core_devices(network)

            # Persist wireless telemetry using the existing monitor.
            diagnostics = analyze_wifi(network)
            save_wireless_measurement(network, diagnostics)

            with self._lock:
                self.last_observation = datetime.now(
                    timezone.utc
                ).isoformat()
                self.last_error = None

        except Exception as exc:
            # A collector failure must not terminate the monitoring thread.
            with self._lock:
                self.last_error = (
                    f"{type(exc).__name__}: {exc}"
                )

    def _loop(self) -> None:
        self.running = True

        try:
            # Collect immediately when the monitor starts.
            self._collect()

            while not self._stop_event.wait(self.interval):
                self._collect()

        finally:
            self.running = False

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()

        self._thread = threading.Thread(
            target=self._loop,
            name="wifi-trace-monitor",
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
                "last_observation": self.last_observation,
                "last_error": self.last_error,
            }


monitor = NetworkMonitor(interval=30)
