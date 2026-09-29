from wifi_trace.risk_engine import (
    evaluate_network,
)


def base_network():
    return {
        "gateway": "192.168.1.1",
        "interface": "en0",
        "ip_address": "192.168.1.10",
        "ssid": "Test Network",
        "status": "Connected",
        "phy_mode": "802.11ax",
        "channel": "44",
        "security": "WPA2 Personal",
        "signal": -55,
        "noise": -90,
        "tx_rate": "600",
        "country": "CA",
        "dns_servers": [
            "192.168.1.1"
        ],
    }


def test_normal_network_is_healthy():
    result = evaluate_network(
        base_network()
    )

    assert result["posture"] == "HEALTHY"
    assert result["attention_score"] == 0


def test_open_network_is_elevated():
    network = base_network()
    network["security"] = "Open"

    result = evaluate_network(network)

    assert result["posture"] == "ATTENTION"
    assert result["attention_score"] >= 40


def test_wep_is_attention():
    network = base_network()
    network["security"] = "WEP"

    result = evaluate_network(network)

    assert result["posture"] == "ATTENTION"


def test_missing_signal_not_security_failure():
    network = base_network()
    network["signal"] = None

    result = evaluate_network(network)

    finding = next(
        item
        for item in result["findings"]
        if item["id"] == "signal-unavailable"
    )

    assert finding["severity"] == "INFO"
    assert finding["score"] == 0


def test_missing_security_is_not_called_insecure():
    network = base_network()
    network["security"] = None

    result = evaluate_network(network)

    finding = next(
        item
        for item in result["findings"]
        if item["id"] == "security-unavailable"
    )

    assert finding["severity"] == "NOTICE"
    assert "unavailable" in finding["title"].lower()


def test_recent_gateway_change_is_detected():
    events = [
        {
            "event_type": "change",
            "field_name": "gateway",
            "field_label": "Gateway",
            "old_value": "192.168.1.1",
            "new_value": "192.168.1.254",
        }
    ]

    result = evaluate_network(
        base_network(),
        events,
    )

    ids = {
        item["id"]
        for item in result["findings"]
    }

    assert "recent-network-change" in ids


def test_missing_dns_adds_notice():
    network = base_network()
    network["dns_servers"] = []

    result = evaluate_network(network)

    ids = {
        item["id"]
        for item in result["findings"]
    }

    assert "dns-unavailable" in ids


def test_score_never_exceeds_100():
    network = base_network()

    network.update(
        {
            "security": "Open",
            "gateway": None,
            "status": "Disconnected",
            "dns_servers": [],
        }
    )

    result = evaluate_network(network)

    assert (
        0
        <= result["attention_score"]
        <= 100
    )
