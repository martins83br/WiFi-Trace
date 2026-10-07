from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import platform
import socket
import psutil
from wifi_trace.collectors.macos import collect_network_info

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_database()
    monitor.start()

    try:
        yield
    finally:
        monitor.stop()


app = FastAPI(
    title="WiFi-Trace",
    description="Wireless Network Forensics & Timeline Analysis",
    version="0.1.0",
    lifespan=lifespan,
)


def get_system_info():
    hostname = socket.gethostname()

    interfaces = []

    for name, addresses in psutil.net_if_addrs().items():
        for address in addresses:
            if address.family == socket.AF_INET:
                interfaces.append(
                    {
                        "name": name,
                        "ip": address.address,
                    }
                )

    return {
        "hostname": hostname,
        "os": "macOS" if platform.system() == "Darwin" else platform.system(),
        "os_version": platform.release(),
        "python": platform.python_version(),
        "interfaces": interfaces,
    }


@app.get("/api/system")
def system_info():
    return get_system_info()


@app.get("/", response_class=HTMLResponse)
def dashboard():
    info = get_system_info()
    network = collect_network_info()

    raw_signal = network.get("signal")
    raw_noise = network.get("noise")

    signal = (
        raw_signal
        if isinstance(raw_signal, (int, float))
        and -100 <= raw_signal <= -1
        else None
    )

    noise = (
        raw_noise
        if isinstance(raw_noise, (int, float))
        and -120 <= raw_noise <= -1
        else None
    )

    snr = (
        signal - noise
        if signal is not None
        and noise is not None
        and 0 <= signal - noise <= 100
        else None
    )

    interface_html = ""

    for interface in info["interfaces"]:
        interface_html += f"""
        <tr>
            <td>{interface["name"]}</td>
            <td>{interface["ip"]}</td>
        </tr>
        """

    return f"""
<!DOCTYPE html>

<html>

<head>

<title>WiFi-Trace</title>

<style>

body {{
    margin: 0;
    background: #0b1118;
    color: #e6edf3;
    font-family: Arial, Helvetica, sans-serif;
}}

.sidebar {{
    position: fixed;
    width: 230px;
    height: 100vh;
    background: #101820;
    border-right: 1px solid #263241;
}}

.logo {{
    padding: 28px;
    font-size: 25px;
    font-weight: bold;
}}

.logo span {{
    color: #39d98a;
}}

.menu {{
    padding: 15px 25px;
}}

.menu a,
.menu .coming-soon {{
    display: block;
    padding: 13px 0;
    color: #9aa7b4;
    text-decoration: none;
    transition:
        color 0.15s ease,
        transform 0.15s ease;
}}

.menu a:hover {{
    color: #39d98a;
    transform: translateX(3px);
}}

.menu a.active {{
    color: #39d98a;
    font-weight: bold;
}}

.menu .coming-soon {{
    color: #596673;
    cursor: default;
}}

.menu .coming-soon span {{
    margin-left: 6px;
    font-size: 9px;
    color: #596673;
}}

.content {{
    margin-left: 230px;
    padding: 40px;
}}

.title {{
    font-size: 30px;
    font-weight: bold;
}}

.subtitle {{
    color: #8b98a5;
    margin-top: 5px;
}}

.cards {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 20px;
    margin-top: 35px;
}}

.card {{
    background: #111b26;
    border: 1px solid #243241;
    border-radius: 10px;
    padding: 22px;
}}

.card-title {{
    color: #8996a3;
    font-size: 13px;
}}

.card-value {{
    margin-top: 10px;
    font-size: 22px;
}}

.online {{
    color: #39d98a;
}}

.panel {{
    margin-top: 30px;
    background: #111b26;
    border: 1px solid #243241;
    border-radius: 10px;
    padding: 25px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
}}

th {{
    text-align: left;
    color: #8996a3;
    padding: 12px;
    border-bottom: 1px solid #263241;
}}

td {{
    padding: 12px;
    border-bottom: 1px solid #1d2935;
}}

.badge {{
    background: #123524;
    color: #39d98a;
    padding: 5px 9px;
    border-radius: 5px;
    font-size: 12px;
}}

</style>

</head>

<body>

<div class="sidebar">

<div class="logo">
WiFi<span>-Trace</span>
</div>

<div class="menu">

<a href="/wifi-diagnostics">◉ Wi-Fi Diagnostics</a>
<a class="active" href="/">
▣ Overview
</a>

<a href="/networks">
◉ Networks
</a>

<a href="/devices">
◈ Devices
</a>

<a href="/timeline">
⌚ Timeline
</a>

<a href="/time-machine">
◫ Time Machine
</a>

<a href="/network-diff">
⇄ Network Diff
</a>

<a href="/investigations">
◇ Investigations
</a>

<div class="coming-soon">
▤ Evidence
<span>COMING SOON</span>
</div>

<div class="coming-soon">
▧ Reports
<span>COMING SOON</span>
</div>

</div>

</div>

<div class="content">

<div class="title">Network Overview</div>

<div class="subtitle">
Wireless Network Forensics & Timeline Analysis
</div>

<div class="cards">

<div class="card">
<div class="card-title">SYSTEM</div>
<div class="card-value">{info["hostname"]}</div>
</div>

<div class="card">
<div class="card-title">OPERATING SYSTEM</div>
<div class="card-value">{info["os"]}</div>
</div>

<div class="card">
<div class="card-title">WIFI-TRACE ENGINE</div>
<div class="card-value online">● ONLINE</div>
</div>

<div class="card">
<div class="card-title">PYTHON</div>
<div class="card-value">{info["python"]}</div>
</div>

</div>


<div class="panel">

<h2>Network Health</h2>

<div id="health-loading">
Analyzing current network evidence...
</div>

<div
    id="health-content"
    style="display:none;"
>

<div
    style="
        display:grid;
        grid-template-columns:
            repeat(3, 1fr);
        gap:16px;
        margin-top:18px;
    "
>

<div
    style="
        background:#0b1118;
        border:1px solid #263241;
        border-radius:8px;
        padding:18px;
    "
>
<div
    style="
        color:#8996a3;
        font-size:12px;
    "
>
SECURITY POSTURE
</div>

<div
    id="health-posture"
    style="
        font-size:24px;
        font-weight:bold;
        margin-top:8px;
    "
>
—
</div>
</div>

<div
    style="
        background:#0b1118;
        border:1px solid #263241;
        border-radius:8px;
        padding:18px;
    "
>
<div
    style="
        color:#8996a3;
        font-size:12px;
    "
>
ATTENTION SCORE
</div>

<div
    id="health-score"
    style="
        font-size:24px;
        font-weight:bold;
        margin-top:8px;
    "
>
—
</div>
</div>

<div
    style="
        background:#0b1118;
        border:1px solid #263241;
        border-radius:8px;
        padding:18px;
    "
>
<div
    style="
        color:#8996a3;
        font-size:12px;
    "
>
ACTIONABLE FINDINGS
</div>

<div
    id="health-findings-count"
    style="
        font-size:24px;
        font-weight:bold;
        margin-top:8px;
    "
>
—
</div>
</div>

</div>

<div
    id="health-summary"
    style="
        margin-top:20px;
    "
></div>

<div
    style="
        margin-top:18px;
        color:#6f7d89;
        font-size:12px;
        line-height:1.6;
    "
>
The attention score is based on deterministic
observations and does not represent a probability
of compromise.
</div>

</div>

</div>


<div class="panel">

<h2>Current Network</h2>

<table>

<tr>
<td>SSID</td>
<td>{network["ssid"] or "Unavailable"}</td>
</tr>

<tr>
<td>Interface</td>
<td>{network["interface"] or "Unavailable"}</td>
</tr>

<tr>
<td>Local IPv4</td>
<td>{network["ip_address"] or "Unavailable"}</td>
</tr>

<tr>
<td>Default Gateway</td>
<td>{network["gateway"] or "Unavailable"}</td>
</tr>

<tr>
<td>Wi-Fi Status</td>
<td>{network["status"] or "Unavailable"}</td>
</tr>

<tr>
<td>Security</td>
<td>{network["security"] or "Unavailable"}</td>
</tr>

<tr>
<td>Wi-Fi Standard</td>
<td>{network["phy_mode"] or "Unavailable"}</td>
</tr>

<tr>
<td>Channel</td>
<td>{network["channel"] or "Unavailable"}</td>
</tr>

<tr>
<td>Signal</td>
<td>{str(signal) + " dBm" if signal is not None else "Unavailable"}</td>
</tr>

<tr>
<td>Noise</td>
<td>{str(noise) + " dBm" if noise is not None else "Unavailable"}</td>
</tr>

<tr>
<td>SNR</td>
<td>{str(snr) + " dB" if snr is not None else "Unavailable"}</td>
</tr>

<tr>
<td>Transmit Rate</td>
<td>{str(network["tx_rate"]) + " Mbps" if network["tx_rate"] else "Unavailable"}</td>
</tr>

<tr>
<td>Country</td>
<td>{network["country"] or "Unavailable"}</td>
</tr>

<tr>
<td>DNS Servers</td>
<td>{"<br>".join(network["dns_servers"]) if network["dns_servers"] else "Unavailable"}</td>
</tr>

</table>

</div>


<div class="panel">

<h2>Network Interfaces</h2>

<table>

<tr>
<th>Interface</th>
<th>IP Address</th>
<th>Status</th>
</tr>

{interface_html}

</table>

</div>


<div class="panel">

<h2>Forensic Engine</h2>

<table>

<tr>
<td>Timeline Engine</td>
<td><span class="badge">READY</span></td>
</tr>

<tr>
<td>Device History</td>
<td><span class="badge">READY</span></td>
</tr>

<tr>
<td>Evidence Database</td>
<td><span class="badge">READY</span></td>
</tr>

<tr>
<td>Router Integration</td>
<td>Not configured</td>
</tr>

</table>

</div>

</div>

<script>
async function loadNetworkHealth() {{
    const loading =
        document.getElementById(
            "health-loading"
        );

    const content =
        document.getElementById(
            "health-content"
        );

    const posture =
        document.getElementById(
            "health-posture"
        );

    const score =
        document.getElementById(
            "health-score"
        );

    const count =
        document.getElementById(
            "health-findings-count"
        );

    const summary =
        document.getElementById(
            "health-summary"
        );

    try {{
        const response = await fetch(
            "/api/network-health",
            {{
                cache: "no-store"
            }}
        );

        const data =
            await response.json();

        if (!response.ok) {{
            throw new Error(
                "Assessment unavailable"
            );
        }}

        const assessment =
            data.assessment;

        posture.textContent =
            assessment.posture;

        score.textContent =
            assessment.attention_score +
            " / 100";

        count.textContent =
            assessment.actionable_count;

        if (
            assessment.posture ===
            "HEALTHY"
        ) {{
            posture.style.color =
                "#39d98a";
        }} else if (
            assessment.posture ===
            "ATTENTION"
        ) {{
            posture.style.color =
                "#f2cc60";
        }} else {{
            posture.style.color =
                "#ff7b72";
        }}

        summary.innerHTML = "";

        if (
            assessment.actionable.length
            === 0
        ) {{
            const clean =
                document.createElement(
                    "div"
                );

            clean.style.padding = "16px";
            clean.style.background =
                "#0b1118";
            clean.style.border =
                "1px solid #263241";
            clean.style.borderRadius =
                "8px";

            clean.innerHTML =
                "<strong>" +
                "No actionable findings" +
                "</strong><br>" +
                "<span style='" +
                "color:#8996a3;" +
                "font-size:13px;" +
                "line-height:1.6;" +
                "'>" +
                "No deterministic rule " +
                "currently requires attention." +
                "</span>";

            summary.appendChild(clean);

        }} else {{
            assessment.actionable
                .forEach((finding) => {{
                    const item =
                        document.createElement(
                            "div"
                        );

                    item.style.padding =
                        "16px";

                    item.style.marginTop =
                        "10px";

                    item.style.background =
                        "#0b1118";

                    item.style.border =
                        "1px solid #263241";

                    item.style.borderRadius =
                        "8px";

                    const severityColor =
                        finding.severity ===
                        "HIGH"
                            ? "#ff7b72"
                            : "#f2cc60";

                    const title =
                        document.createElement(
                            "div"
                        );

                    title.style.fontWeight =
                        "bold";

                    title.style.color =
                        severityColor;

                    title.textContent =
                        finding.severity +
                        " — " +
                        finding.title;

                    const evidence =
                        document.createElement(
                            "div"
                        );

                    evidence.style.marginTop =
                        "8px";

                    evidence.style.fontSize =
                        "13px";

                    evidence.textContent =
                        "Evidence: " +
                        finding.evidence;

                    const explanation =
                        document.createElement(
                            "div"
                        );

                    explanation.style.marginTop =
                        "6px";

                    explanation.style.color =
                        "#8996a3";

                    explanation.style.fontSize =
                        "13px";

                    explanation.style.lineHeight =
                        "1.5";

                    explanation.textContent =
                        finding.explanation;

                    const recommendation =
                        document.createElement(
                            "div"
                        );

                    recommendation.style.marginTop =
                        "8px";

                    recommendation.style.fontSize =
                        "13px";

                    recommendation.textContent =
                        "Next step: " +
                        finding.recommendation;

                    item.appendChild(title);
                    item.appendChild(evidence);
                    item.appendChild(
                        explanation
                    );
                    item.appendChild(
                        recommendation
                    );

                    summary.appendChild(item);
                }});
        }}

        loading.style.display =
            "none";

        content.style.display =
            "block";

    }} catch (error) {{
        loading.textContent =
            "Network health assessment " +
            "is currently unavailable.";
    }}
}}

document.addEventListener(
    "DOMContentLoaded",
    loadNetworkHealth
);
</script>

</body>

</html>
"""


from fastapi import Request, Form
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from wifi_trace.collectors.macos import (
    get_saved_wifi_networks,
    get_saved_wifi_password,
)

templates = Jinja2Templates(directory="wifi_trace/templates")


@app.get("/networks", response_class=HTMLResponse)
def networks_page(request: Request):
    networks = get_saved_wifi_networks()

    return templates.TemplateResponse(
        request=request,
        name="networks.html",
        context={"networks": networks},
    )


@app.post("/api/networks/password")
def network_password(ssid: str = Form(...)):
    password = get_saved_wifi_password(ssid)

    if password is None:
        return JSONResponse(
            status_code=404,
            content={
                "available": False,
                "password": None,
            },
        )

    return JSONResponse(
        content={
            "available": True,
            "password": password,
        },
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache",
        },
    )


from wifi_trace.database import init_database, save_snapshot, get_recent_events, get_database_stats


@app.get("/timeline")
def timeline_page(request: Request):
    events = get_recent_events(limit=100)
    stats = get_database_stats()

    return templates.TemplateResponse(
        request=request,
        name="timeline.html",
        context={
            "events": events,
            "stats": stats,
        },
    )


@app.post("/api/timeline/observe")
def record_timeline_observation():
    network = collect_network_info()
    result = save_snapshot(network)

    response = JSONResponse(
        content={
            "success": True,
            **result,
        }
    )

    response.headers["Cache-Control"] = (
        "no-store, no-cache, must-revalidate"
    )
    response.headers["Pragma"] = "no-cache"

    return response


@app.get("/api/timeline")
def timeline_api():
    response = JSONResponse(
        content={
            "events": get_recent_events(limit=100),
            "stats": get_database_stats(),
        }
    )

    response.headers["Cache-Control"] = "no-store"
    return response

from wifi_trace.monitor import monitor


@app.get("/api/monitor/status")
def monitor_status():
    response = JSONResponse(
        content={
            **monitor.status(),
            "database": get_database_stats(),
        }
    )

    response.headers["Cache-Control"] = "no-store"
    return response

from wifi_trace.database import get_snapshot, get_snapshot_navigation, get_latest_snapshot_id, get_snapshot_index


@app.get("/time-machine")
def time_machine_page(request: Request, snapshot: int | None = None):
    if snapshot is None:
        snapshot = get_latest_snapshot_id()

    selected = get_snapshot(snapshot) if snapshot is not None else None

    navigation = (
        get_snapshot_navigation(snapshot)
        if snapshot is not None
        else {"previous": None, "next": None}
    )

    snapshots = get_snapshot_index(limit=250)

    return templates.TemplateResponse(
        request=request,
        name="time_machine.html",
        context={
            "snapshot": selected,
            "navigation": navigation,
            "snapshots": snapshots,
        },
    )


@app.get("/api/time-machine/{snapshot_id}")
def time_machine_api(snapshot_id: int):
    snapshot = get_snapshot(snapshot_id)

    if snapshot is None:
        return JSONResponse(
            status_code=404,
            content={
                "success": False,
                "detail": "Snapshot not found",
            },
        )

    response = JSONResponse(
        content={
            "success": True,
            "snapshot": snapshot,
            "navigation": get_snapshot_navigation(snapshot_id),
        }
    )

    response.headers["Cache-Control"] = "no-store"
    return response

from wifi_trace.database import (
    get_observed_devices,
    get_device_passport,
    record_core_devices,
    get_enriched_observed_devices,
    get_enriched_device_passport,
    get_mac_enriched_device_passport,
)


@app.get("/devices")
def devices_page(request: Request):
    devices = get_enriched_observed_devices()

    return templates.TemplateResponse(
        request=request,
        name="devices.html",
        context={
            "devices": devices,
        },
    )


@app.get("/devices/{device_id}")
def device_passport_page(request: Request, device_id: int):
    device = get_mac_enriched_device_passport(
        device_id
    )

    if device is None:
        return JSONResponse(
            status_code=404,
            content={"detail": "Observed device not found"},
        )

    return templates.TemplateResponse(
        request=request,
        name="device_passport.html",
        context={
            "device": device,
        },
    )


@app.get("/api/devices")
def devices_api():
    response = JSONResponse(
        content={
            "devices": get_observed_devices(),
        }
    )

    response.headers["Cache-Control"] = "no-store"
    return response


from wifi_trace.lan_discovery import lan_discovery


@app.post("/api/devices/discover")
def discover_devices():
    try:
        result = lan_discovery.scan_once()

        response = JSONResponse(
            content={
                "success": True,
                **result,
            }
        )

        response.headers["Cache-Control"] = "no-store"
        return response

    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "detail": f"{type(exc).__name__}: {exc}",
            },
        )


@app.get("/api/devices/discovery/status")
def discovery_status():
    response = JSONResponse(
        content=lan_discovery.status()
    )

    response.headers["Cache-Control"] = "no-store"
    return response


from wifi_trace.bonjour_discovery import discover_bonjour
from wifi_trace.database import (
    add_device_fingerprint,
    find_observed_device_by_ip,
    get_device_fingerprints,
    get_device_identification,
)


@app.post("/api/devices/bonjour")
def run_bonjour_discovery():
    observations = discover_bonjour()

    matched = []
    unmatched = []

    for observation in observations:
        ip_address = observation.get("ip_address")

        if not ip_address:
            unmatched.append(observation)
            continue

        device = find_observed_device_by_ip(
            ip_address
        )

        if not device:
            unmatched.append(observation)
            continue

        add_device_fingerprint(
            device_id=device["id"],
            source="Bonjour/mDNS",
            hostname=observation.get("hostname"),
            category=observation.get("category"),
            confidence=observation.get("confidence"),
            service_type=observation.get("service_type"),
            service_name=observation.get("service_name"),
            service_label=observation.get("service_label"),
            port=observation.get("port"),
        )

        matched.append(
            {
                "device_id": device["id"],
                **observation,
            }
        )

    response = JSONResponse(
        content={
            "observed_services": len(observations),
            "matched_devices": matched,
            "unmatched_services": unmatched,
        }
    )

    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/api/devices/{device_id}/fingerprint")
def device_fingerprint(device_id: int):
    response = JSONResponse(
        content={
            "identification":
                get_device_identification(device_id),
            "evidence":
                get_device_fingerprints(device_id),
        }
    )

    response.headers["Cache-Control"] = "no-store"
    return response



# === WIFI-TRACE NEIGHBOR COLLECTION API V1 ===

from wifi_trace.macos_neighbors import collect_neighbors
from wifi_trace.database import (
    get_latest_observed_ipv4_addresses,
    record_neighbor_mac_evidence,
)


@app.post("/api/devices/neighbors")
def collect_device_neighbors():
    """
    Collect local IP-to-MAC neighbor evidence only for IPv4 addresses
    already observed by WiFi-Trace.
    """

    targets = get_latest_observed_ipv4_addresses()

    observations = collect_neighbors(targets)

    recorded = []
    unavailable = []

    for observation in observations:
        if not observation.get("available"):
            unavailable.append(observation)
            continue

        device_id = record_neighbor_mac_evidence(
            ip_address=observation["ip_address"],
            mac_address=observation["mac_address"],
            source=observation["source"],
            evidence_note=observation["note"],
        )

        if device_id is None:
            unavailable.append(
                {
                    **observation,
                    "available": False,
                    "note": (
                        "MAC evidence was collected, but no existing "
                        "WiFi-Trace device could be correlated safely."
                    ),
                }
            )
            continue

        recorded.append(
            {
                **observation,
                "device_id": device_id,
            }
        )

    response = JSONResponse(
        content={
            "targets": len(targets),
            "observations": len(observations),
            "recorded": recorded,
            "unavailable": unavailable,
        }
    )

    response.headers["Cache-Control"] = "no-store"

    return response



# === WIFI-TRACE NETWORK DIFF V1 ===

from wifi_trace.network_diff import compare_snapshots


def _resolve_diff_snapshots(
    before_id: int | None,
    after_id: int | None,
):
    """
    Resolve two snapshots for comparison.

    If IDs are omitted, use the two most recent snapshots.
    """

    snapshots = get_snapshot_index(limit=250)

    if not snapshots:
        return None, None

    if after_id is None:
        after_id = snapshots[0]["id"]

    if before_id is None:
        before_id = next(
            (
                item["id"]
                for item in snapshots
                if item["id"] < after_id
            ),
            None,
        )

    before = (
        get_snapshot(before_id)
        if before_id is not None
        else None
    )

    after = (
        get_snapshot(after_id)
        if after_id is not None
        else None
    )

    return before, after


@app.get("/network-diff")
def network_diff_page(
    request: Request,
    before: int | None = None,
    after: int | None = None,
):
    snapshots = get_snapshot_index(limit=250)

    before_snapshot, after_snapshot = (
        _resolve_diff_snapshots(
            before,
            after,
        )
    )

    comparison = None

    if (
        before_snapshot is not None
        and after_snapshot is not None
    ):
        comparison = compare_snapshots(
            before_snapshot,
            after_snapshot,
        )

    return templates.TemplateResponse(
        request=request,
        name="network_diff.html",
        context={
            "snapshots": snapshots,
            "before_snapshot": before_snapshot,
            "after_snapshot": after_snapshot,
            "comparison": comparison,
        },
    )


@app.get("/api/network-diff")
def network_diff_api(
    before: int,
    after: int,
):
    if before == after:
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "detail": (
                    "Two different snapshots are required."
                ),
            },
        )

    before_snapshot = get_snapshot(before)
    after_snapshot = get_snapshot(after)

    if before_snapshot is None:
        return JSONResponse(
            status_code=404,
            content={
                "success": False,
                "detail": "Before snapshot not found.",
            },
        )

    if after_snapshot is None:
        return JSONResponse(
            status_code=404,
            content={
                "success": False,
                "detail": "After snapshot not found.",
            },
        )

    response = JSONResponse(
        content={
            "success": True,
            "comparison": compare_snapshots(
                before_snapshot,
                after_snapshot,
            ),
        }
    )

    response.headers["Cache-Control"] = "no-store"

    return response


# === WIFI-TRACE INVESTIGATIONS API V1 ===

from wifi_trace.database import (
    add_snapshot_to_investigation,
    create_investigation,
    get_investigation,
    get_investigations,
)


@app.get("/investigations")
def investigations_page(
    request: Request,
):
    return templates.TemplateResponse(
        request=request,
        name="investigations.html",
        context={
            "investigations":
                get_investigations(),
            "snapshots":
                get_snapshot_index(limit=250),
        },
    )


@app.get("/investigations/{investigation_id}")
def investigation_page(
    request: Request,
    investigation_id: int,
):
    investigation = get_investigation(
        investigation_id
    )

    if investigation is None:
        return JSONResponse(
            status_code=404,
            content={
                "detail":
                    "Investigation not found."
            },
        )

    return templates.TemplateResponse(
        request=request,
        name="investigation_detail.html",
        context={
            "investigation": investigation,
            "snapshots":
                get_snapshot_index(limit=250),
        },
    )


@app.post("/api/investigations")
def create_investigation_api(
    title: str = Form(...),
    description: str = Form(""),
):
    try:
        investigation_id = (
            create_investigation(
                title=title,
                description=description,
            )
        )
    except ValueError as exc:
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "detail": str(exc),
            },
        )

    response = JSONResponse(
        content={
            "success": True,
            "investigation_id":
                investigation_id,
        }
    )

    response.headers["Cache-Control"] = "no-store"

    return response


@app.post(
    "/api/investigations/{investigation_id}/evidence/snapshot"
)
def add_snapshot_evidence_api(
    investigation_id: int,
    snapshot_id: int = Form(...),
    note: str = Form(""),
):
    try:
        result = add_snapshot_to_investigation(
            investigation_id=
                investigation_id,
            snapshot_id=snapshot_id,
            note=note,
        )
    except ValueError as exc:
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "detail": str(exc),
            },
        )

    response = JSONResponse(
        content={
            "success": True,
            **result,
        }
    )

    response.headers["Cache-Control"] = "no-store"

    return response


# === WIFI-TRACE EVIDENCE INTEGRITY API V2 ===

from wifi_trace.database import (
    get_evidence_item,
    get_evidence_verifications,
    get_investigation_integrity,
    verify_stored_evidence,
)


@app.post(
    "/api/evidence/{evidence_id}/verify"
)
def verify_evidence_api(
    evidence_id: int,
):
    try:
        result = verify_stored_evidence(
            evidence_id
        )

    except ValueError as exc:
        return JSONResponse(
            status_code=404,
            content={
                "success": False,
                "detail": str(exc),
            },
        )

    status_code = (
        200
        if result["result"] == "VERIFIED"
        else 409
    )

    response = JSONResponse(
        status_code=status_code,
        content={
            "success":
                result["result"]
                == "VERIFIED",
            **result,
        },
    )

    response.headers[
        "Cache-Control"
    ] = "no-store"

    return response


@app.get(
    "/api/evidence/{evidence_id}/verifications"
)
def evidence_verifications_api(
    evidence_id: int,
):
    evidence = get_evidence_item(
        evidence_id
    )

    if evidence is None:
        return JSONResponse(
            status_code=404,
            content={
                "success": False,
                "detail":
                    "Evidence item not found.",
            },
        )

    response = JSONResponse(
        content={
            "success": True,
            "evidence_id":
                evidence_id,
            "verifications":
                get_evidence_verifications(
                    evidence_id
                ),
        }
    )

    response.headers[
        "Cache-Control"
    ] = "no-store"

    return response


@app.post(
    "/api/investigations/{investigation_id}/verify"
)
def verify_investigation_api(
    investigation_id: int,
):
    try:
        result = (
            get_investigation_integrity(
                investigation_id
            )
        )

    except ValueError as exc:
        return JSONResponse(
            status_code=404,
            content={
                "success": False,
                "detail": str(exc),
            },
        )

    response = JSONResponse(
        content={
            "success":
                result["failed"] == 0,
            **result,
        }
    )

    response.headers[
        "Cache-Control"
    ] = "no-store"

    return response


# === WIFI-TRACE NETWORK HEALTH API V1 ===

from wifi_trace.risk_engine import (
    evaluate_network,
)



@app.get("/wifi-diagnostics", response_class=HTMLResponse)
def wifi_diagnostics_page():
    from pathlib import Path

    template = (
        Path(__file__).resolve().parent
        / "templates"
        / "wifi_diagnostics.html"
    )
    return HTMLResponse(template.read_text(encoding="utf-8"))


@app.get("/api/wifi-diagnostics")
def wifi_diagnostics_api():
    from wifi_trace.wifi_diagnostics import analyze_wifi

    network = collect_network_info()


    diagnostics = analyze_wifi(network)

    return {
        "network": {
            "ssid": network.get("ssid"),
            "interface": network.get("interface"),
            "phy_mode": network.get("phy_mode"),
            "channel": network.get("channel"),
            "security": network.get("security"),
        },
        "diagnostics": diagnostics,
    }




@app.get("/wireless-history", response_class=HTMLResponse)
def wireless_history_page():
    from pathlib import Path
    path = Path(__file__).resolve().parent / "templates" / "wireless_history.html"
    return HTMLResponse(path.read_text(encoding="utf-8"))


@app.get("/api/wireless-history")
def wireless_history_api(hours: int = 1, limit: int = 1000):
    from wifi_trace.wireless_history import get_wireless_history

    return {
        "hours": max(1, min(hours, 168)),
        "measurements": get_wireless_history(hours, limit),
    }


@app.get("/api/network-health")
def network_health_api():
    network = collect_network_info()

    events = get_recent_events(
        limit=25
    )

    assessment = evaluate_network(
        network,
        events,
    )

    response = JSONResponse(
        content={
            "success": True,
            "assessment": assessment,
        }
    )

    response.headers[
        "Cache-Control"
    ] = "no-store"

    return response
