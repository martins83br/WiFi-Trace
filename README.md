# WiFi-Trace

**Local-First Wireless Network Forensics & Intelligence Workbench**

WiFi-Trace is a Python-based cybersecurity project focused on local network visibility, wireless diagnostics, historical analysis, anomaly detection, and evidence reporting.

## Features

- Network overview and device inventory
- Device passports
- Network timeline and historical snapshots
- Time Machine and Network Diff
- Security and investigation dashboards
- Wireless diagnostics and history
- Wireless anomaly detection
- Evidence and reporting pages
- CSV, JSON, and HTML exports

## Technology Stack

- Python
- FastAPI
- SQLite
- HTML, CSS, and JavaScript
- pytest
- macOS network collectors

## Installation

Clone the repository:

    git clone https://github.com/martins83br/WiFi-Trace.git
    cd WiFi-Trace

Create a virtual environment:

    python3 -m venv .venv
    source .venv/bin/activate

Install dependencies:

    pip install -r requirements.txt

## Running Locally

    python -m uvicorn wifi_trace.main:app --host 127.0.0.1 --port 8000

Open http://127.0.0.1:8000

## Main Pages

| Feature | Route |
|---|---|
| Overview | / |
| Networks | /networks |
| Devices | /devices |
| Timeline | /timeline |
| Time Machine | /time-machine |
| Network Diff | /network-diff |
| Security | /security |
| Investigations | /investigations |
| Wi-Fi Diagnostics | /wifi-diagnostics |
| Wireless History | /wireless-history |
| Evidence | /evidence |
| Reports | /reports |

## Data Exports

| Format | Endpoint |
|---|---|
| Wireless CSV | /exports/wireless.csv |
| Wireless JSON | /exports/wireless.json |
| Anomaly JSON | /exports/anomalies.json |
| HTML Report | /exports/summary.html |

## Tests

    python -m pytest -q

## Security and Privacy

WiFi-Trace is designed for authorized local network analysis.

- Do not expose the development server to the public Internet.
- Do not publish collected network data or sensitive identifiers.
- Review exports before sharing them.
- Anomalies are indicators, not proof of compromise.
- This project is not a certified forensic evidence system.

## Project Status

Version 1.0 release candidate.

## Author

Diniz Martins

GitHub: https://github.com/martins83br
