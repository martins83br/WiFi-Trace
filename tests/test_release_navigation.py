from fastapi.testclient import TestClient
from wifi_trace.main import app

PAGES = [
    "/", "/networks", "/devices", "/timeline",
    "/time-machine", "/network-diff", "/security",
    "/investigations", "/wifi-diagnostics",
    "/wireless-history", "/evidence", "/reports",
]

EXPORTS = [
    "/exports/wireless.csv",
    "/exports/wireless.json",
    "/exports/anomalies.json",
    "/exports/summary.html",
]


def test_all_release_pages():
    with TestClient(app) as client:
        for page in PAGES:
            response = client.get(page)
            assert response.status_code == 200, page


def test_all_release_exports():
    with TestClient(app) as client:
        for route in EXPORTS:
            response = client.get(route)
            assert response.status_code == 200, route
            assert "attachment" in response.headers.get(
                "content-disposition", ""
            )
