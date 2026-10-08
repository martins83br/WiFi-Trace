import csv
import io
import json

from fastapi.testclient import TestClient

from wifi_trace.main import app
from wifi_trace import report_exports


def sample_records():
    return [{
        "id": 1,
        "timestamp": "2026-10-08T00:00:00+00:00",
        "interface": "en0",
        "signal_dbm": -55,
        "noise_dbm": -90,
        "snr_db": 35,
        "tx_rate_mbps": 400,
    }]


def test_export_routes(monkeypatch):
    monkeypatch.setattr(
        report_exports,
        "history_data",
        lambda hours: sample_records(),
    )

    with TestClient(app) as client:
        for route in (
            "/exports/wireless.json",
            "/exports/wireless.csv",
            "/exports/anomalies.json",
            "/exports/summary.html",
        ):
            response = client.get(route)
            assert response.status_code == 200, route
            assert "attachment" in response.headers["content-disposition"]

        payload = client.get("/exports/wireless.json").json()
        assert payload["count"] == 1

        csv_response = client.get("/exports/wireless.csv")
        rows = list(csv.DictReader(io.StringIO(csv_response.text)))
        assert rows[0]["signal_dbm"] == "-55"

        analysis = client.get("/exports/anomalies.json").json()
        assert "analysis" in analysis

        report = client.get("/exports/summary.html")
        assert "WiFi-Trace" in report.text


def test_invalid_period():
    with TestClient(app) as client:
        assert client.get("/exports/wireless.csv?hours=0").status_code == 422
        assert client.get("/exports/wireless.csv?hours=169").status_code == 422
