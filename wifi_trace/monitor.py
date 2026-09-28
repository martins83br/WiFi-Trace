import threading
from datetime import datetime, timezone

from wifi_trace.collectors.macos import collect_network_info
from wifi_trace.database import save_snapshot


class NetworkMonitor:
    def __init__(self, interval: int = 30):
        self.interval = interval
        self._stop_event = threading.Event()
        self._thread = None
        self.last_observation = None
        self.last_error = None

    @property
    def running(self) -> bool:
        return (
            self._thread is not None
            and self._thread.is_alive()
            and not self._stop_event.is_set()
        )

    def _collect(self):
        try:
            network = collect_network_info()
            result = save_snapshot(network)

            self.last_observation = result["observed_at"]
            self.last_error = None

        except Exception as exc:
            self.last_error = str(exc)

    def _loop(self):
        # Record immediately when the application starts.
        self._collect()

        while not self._stop_event.wait(self.interval):
            self._collect()

    def start(self):
        if self.running:
            return

        self._stop_event.clear()

        self._thread = threading.Thread(
            target=self._loop,
            name="wifi-trace-monitor",
            daemon=True,
        )

        self._thread.start()

    def stop(self):
        self._stop_event.set()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)

    def status(self) -> dict:
        return {
            "running": self.running,
            "interval": self.interval,
            "last_observation": self.last_observation,
            "last_error": self.last_error,
        }


monitor = NetworkMonitor(interval=30)
