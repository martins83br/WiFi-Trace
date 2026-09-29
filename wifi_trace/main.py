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
    color: #9aa7b4;
}}

.menu div {{
    padding: 13px 0;
}}

.active {{
    color: #39d98a;
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

<div class="active">▣ Overview</div>
<div>◉ Networks</div>
<div>◈ Devices</div>
<div>⌚ Timeline</div>
<div>⚠ Security</div>
<div>◇ Investigations</div>
<div>▤ Evidence</div>
<div>▧ Reports</div>

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
<div class="card-title">AIRTRACE ENGINE</div>
<div class="card-value online">● ONLINE</div>
</div>

<div class="card">
<div class="card-title">PYTHON</div>
<div class="card-value">{info["python"]}</div>
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
<td>{str(network["signal"]) + " dBm" if network["signal"] is not None else "Unavailable"}</td>
</tr>

<tr>
<td>Noise</td>
<td>{str(network["noise"]) + " dBm" if network["noise"] is not None else "Unavailable"}</td>
</tr>

<tr>
<td>SNR</td>
<td>{str(network["signal"] - network["noise"]) + " dB" if network["signal"] is not None and network["noise"] is not None else "Unavailable"}</td>
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
