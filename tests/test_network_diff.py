from wifi_trace.network_diff import compare_snapshots


def make_snapshot(**changes):
    snapshot = {
        "id": 1,
        "observed_at":
            "2026-09-28T20:00:00+00:00",
        "gateway": "10.0.0.1",
        "interface": "en0",
        "ip_address": "10.0.0.22",
        "ssid": "Test Network",
        "wifi_status": "Connected",
        "phy_mode": "802.11ax",
        "channel": "36",
        "security": "WPA3",
        "signal": -50,
        "noise": -90,
        "snr": 40,
        "tx_rate": "600",
        "country": "CA",
        "dns_servers": [
            "10.0.0.1",
        ],
    }

    snapshot.update(changes)

    return snapshot


def find_change(result, field):
    return next(
        item
        for item in result["changes"]
        if item["field"] == field
    )


def test_identical_snapshots():
    before = make_snapshot()
    after = make_snapshot(id=2)

    result = compare_snapshots(
        before,
        after,
    )

    assert result["changed"] is False
    assert result["significant"] is False
    assert result["counts"]["UNCHANGED"] == 14
    assert result["meaningful_changes"] == []


def test_ip_change_is_significant():
    before = make_snapshot()

    after = make_snapshot(
        id=2,
        ip_address="10.0.0.50",
    )

    result = compare_snapshots(
        before,
        after,
    )

    change = find_change(
        result,
        "ip_address",
    )

    assert change["state"] == "CHANGED"
    assert (
        change["classification"]
        == "SIGNIFICANT"
    )


def test_security_change_is_significant():
    before = make_snapshot(
        security="WPA2 Personal",
    )

    after = make_snapshot(
        id=2,
        security="WPA3 Personal",
    )

    result = compare_snapshots(
        before,
        after,
    )

    change = find_change(
        result,
        "security",
    )

    assert (
        change["classification"]
        == "SIGNIFICANT"
    )


def test_small_noise_change_is_telemetry():
    before = make_snapshot(
        noise=-84,
    )

    after = make_snapshot(
        id=2,
        noise=-85,
    )

    result = compare_snapshots(
        before,
        after,
    )

    change = find_change(
        result,
        "noise",
    )

    assert change["state"] == "CHANGED"
    assert (
        change["classification"]
        == "TELEMETRY"
    )


def test_large_noise_change_is_significant():
    before = make_snapshot(
        noise=-80,
    )

    after = make_snapshot(
        id=2,
        noise=-90,
    )

    result = compare_snapshots(
        before,
        after,
    )

    change = find_change(
        result,
        "noise",
    )

    assert (
        change["classification"]
        == "SIGNIFICANT"
    )


def test_small_signal_change_is_telemetry():
    before = make_snapshot(
        signal=-50,
    )

    after = make_snapshot(
        id=2,
        signal=-53,
    )

    result = compare_snapshots(
        before,
        after,
    )

    change = find_change(
        result,
        "signal",
    )

    assert (
        change["classification"]
        == "TELEMETRY"
    )


def test_threshold_signal_change_is_significant():
    before = make_snapshot(
        signal=-50,
    )

    after = make_snapshot(
        id=2,
        signal=-55,
    )

    result = compare_snapshots(
        before,
        after,
    )

    change = find_change(
        result,
        "signal",
    )

    assert (
        change["classification"]
        == "SIGNIFICANT"
    )


def test_tx_rate_is_telemetry():
    before = make_snapshot(
        tx_rate="648",
    )

    after = make_snapshot(
        id=2,
        tx_rate="680",
    )

    result = compare_snapshots(
        before,
        after,
    )

    change = find_change(
        result,
        "tx_rate",
    )

    assert (
        change["classification"]
        == "TELEMETRY"
    )


def test_dns_change_is_significant():
    before = make_snapshot(
        dns_servers=["10.0.0.1"],
    )

    after = make_snapshot(
        id=2,
        dns_servers=[
            "1.1.1.1",
            "1.0.0.1",
        ],
    )

    result = compare_snapshots(
        before,
        after,
    )

    change = find_change(
        result,
        "dns_servers",
    )

    assert (
        change["classification"]
        == "SIGNIFICANT"
    )


def test_stable_network_summary():
    before = make_snapshot(
        noise=-84,
        tx_rate="648",
    )

    after = make_snapshot(
        id=2,
        noise=-85,
        tx_rate="680",
    )

    result = compare_snapshots(
        before,
        after,
    )

    assert result["significant"] is False

    assert (
        result["summary"]
        ==
        "Network configuration remained stable. "
        "Only operational or radio telemetry "
        "variation was observed."
    )


def test_radio_display_units():
    before = make_snapshot(
        signal=-55,
    )

    after = make_snapshot(
        id=2,
        signal=-60,
    )

    result = compare_snapshots(
        before,
        after,
    )

    signal = find_change(
        result,
        "signal",
    )

    assert (
        signal["before_display"]
        == "-55 dBm"
    )

    assert (
        signal["after_display"]
        == "-60 dBm"
    )
