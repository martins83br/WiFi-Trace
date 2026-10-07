from wifi_trace.wifi_diagnostics import analyze_wifi


def test_good_connection():
    result = analyze_wifi({
        "signal": -58,
        "noise": -88,
        "tx_rate": "720",
    })

    assert result["signal_quality"] == "GOOD"
    assert result["snr_quality"] == "GOOD"
    assert result["snr_db"] == 30
    assert result["tx_rate_mbps"] == 720.0


def test_excellent_connection():
    result = analyze_wifi({
        "signal": -45,
        "noise": -90,
        "tx_rate": 1200,
    })

    assert result["signal_quality"] == "EXCELLENT"
    assert result["snr_quality"] == "EXCELLENT"


def test_weak_connection():
    result = analyze_wifi({
        "signal": -82,
        "noise": -90,
        "tx_rate": 54,
    })

    assert result["signal_quality"] == "POOR"
    assert result["snr_quality"] == "POOR"
    assert result["findings"]


def test_unavailable_measurements():
    result = analyze_wifi({
        "signal": 0,
        "noise": None,
        "tx_rate": "Unavailable",
    })

    assert result["signal_dbm"] is None
    assert result["snr_db"] is None
    assert result["tx_rate_mbps"] is None


def test_boolean_not_accepted_as_signal():
    result = analyze_wifi({
        "signal": True,
        "noise": -90,
    })

    assert result["signal_dbm"] is None
