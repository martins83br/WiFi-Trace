from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import platform
import socket
import psutil
from wifi_trace.collectors.macos import collect_network_info

app = FastAPI(
    title="WiFi-Trace",
    description="Wireless Network Forensics & Timeline Analysis",
    version="0.1.0",
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
