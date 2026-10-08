from wifi_trace.wireless_anomalies import (
    detect_wireless_anomalies,
)


def rows(signals, snrs=None):
    snrs = snrs or [35] * len(signals)

    return [
        {"signal_dbm": signal, "snr_db": snr}
        for signal, snr in zip(signals, snrs)
    ]


def test_insufficient_data():
    result = detect_wireless_anomalies(rows([-55, -56]))
    assert result["status"] == "insufficient_data"


def test_stable_signal():
    result = detect_wireless_anomalies(
        rows([-55, -56, -54, -55])
    )
    assert result["status"] == "normal"


def test_significant_signal_drop():
    result = detect_wireless_anomalies(
        rows([-50, -52, -75, -74])
    )
    assert any(
        finding["code"] == "SIGNAL_DROP"
        for finding in result["findings"]
    )


def test_high_signal_variation():
    result = detect_wireless_anomalies(
        rows([-50, -60, -75])
    )
    assert any(
        finding["code"] == "HIGH_SIGNAL_VARIATION"
        for finding in result["findings"]
    )


def test_low_snr():
    result = detect_wireless_anomalies(
        rows([-55, -56, -57], [30, 12, 10])
    )
    assert any(
        finding["code"] == "LOW_SNR"
        for finding in result["findings"]
    )


def test_invalid_measurements():
    result = detect_wireless_anomalies([
        {"signal_dbm": None, "snr_db": None},
        {"signal_dbm": True, "snr_db": float("nan")},
        {"signal_dbm": -55, "snr_db": 35},
    ])
    assert result["status"] == "normal"
    assert result["findings"] == []
