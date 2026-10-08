"""Read-only exports of existing WiFi-Trace telemetry."""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from html import escape

from fastapi import APIRouter, Query
from fastapi.responses import HTMLResponse, Response

router = APIRouter(prefix="/exports", tags=["exports"])


def history_data(hours: int) -> list[dict]:
    from wifi_trace.wireless_history import get_wireless_history
    return get_wireless_history(hours=hours, limit=5000)


def anomaly_data(hours: int) -> dict:
    from wifi_trace.wireless_anomalies import detect_wireless_anomalies
    return detect_wireless_anomalies(history_data(hours))


def download(content: str, media_type: str, filename: str) -> Response:
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/wireless.json")
def wireless_json(hours: int = Query(24, ge=1, le=168)):
    records = history_data(hours)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "period_hours": hours,
        "count": len(records),
        "measurements": records,
    }
    return download(
        json.dumps(payload, indent=2, default=str),
        "application/json",
        "wifi_trace_wireless.json",
    )


@router.get("/wireless.csv")
def wireless_csv(hours: int = Query(24, ge=1, le=168)):
    records = history_data(hours)
    fields = [
        "id", "timestamp", "interface", "signal_dbm",
        "noise_dbm", "snr_db", "tx_rate_mbps",
    ]
    output = io.StringIO()
    writer = csv.DictWriter(
        output, fieldnames=fields, extrasaction="ignore"
    )
    writer.writeheader()

    for record in records:
        writer.writerow({
            key: record.get(key)
            for key in fields
        })

    return download(
        output.getvalue(),
        "text/csv",
        "wifi_trace_wireless.csv",
    )


@router.get("/anomalies.json")
def anomalies_json(hours: int = Query(24, ge=1, le=168)):
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "period_hours": hours,
        "analysis": anomaly_data(hours),
    }
    return download(
        json.dumps(payload, indent=2, default=str),
        "application/json",
        "wifi_trace_anomalies.json",
    )


@router.get("/summary.html", response_class=HTMLResponse)
def summary_html(hours: int = Query(24, ge=1, le=168)):
    records = history_data(hours)
    from wifi_trace.wireless_anomalies import detect_wireless_anomalies
    analysis = detect_wireless_anomalies(records)

    generated = datetime.now(timezone.utc).isoformat()

    def cell(value):
        return escape(str(value if value is not None else "Unavailable"))

    rows = "".join(
        "<tr>" +
        "".join(
            f"<td>{cell(record.get(field))}</td>"
            for field in (
                "timestamp", "interface", "signal_dbm",
                "noise_dbm", "snr_db", "tx_rate_mbps"
            )
        ) + "</tr>"
        for record in records[-100:]
    )

    findings = "".join(
        "<li>" + escape(json.dumps(finding, default=str)) + "</li>"
        for finding in analysis.get("findings", [])
    ) or "<li>No findings in the selected period.</li>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>WiFi-Trace Wireless Report</title>
<style>
body {{
  font-family: Arial, sans-serif;
  max-width: 1100px;
  margin: 45px auto;
  padding: 20px;
  color: #17212b;
}}
h1 {{ color: #126c50; }}
table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
th,td {{ border: 1px solid #ccd4dc; padding: 8px; text-align: left; }}
th {{ background: #edf4f1; }}
.info {{ background: #edf4f1; padding: 16px; border-radius: 8px; }}
</style>
</head>
<body>
<h1>WiFi-Trace | Wireless Report</h1>
<div class="info">
<p><b>Generated (UTC):</b> {cell(generated)}</p>
<p><b>Period:</b> Last {hours} hours</p>
<p><b>Measurements:</b> {len(records)}</p>
<p><b>Analysis:</b> {cell(analysis.get("status"))}</p>
</div>
<h2>Wireless Anomaly Findings</h2>
<ul>{findings}</ul>
<h2>Recent Wireless Measurements</h2>
<p>Displaying up to 100 records. CSV and JSON exports provide the selected dataset, subject to the 5,000-record limit.</p>
<table>
<thead>
<tr>
<th>Timestamp</th><th>Interface</th><th>RSSI</th>
<th>Noise</th><th>SNR</th><th>Link Rate</th>
</tr>
</thead>
<tbody>{rows}</tbody>
</table>
<p><small>Measurements and findings are observational.
They do not independently establish a security compromise.</small></p>
</body>
</html>"""

    return download(
        html,
        "text/html",
        "wifi_trace_report.html",
    )
