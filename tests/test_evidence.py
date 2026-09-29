from wifi_trace.evidence import (
    build_evidence_envelope,
    calculate_sha256,
    sanitize_evidence,
    verify_evidence,
)


def test_hash_is_deterministic():
    first = {
        "b": 2,
        "a": 1,
    }

    second = {
        "a": 1,
        "b": 2,
    }

    assert (
        calculate_sha256(first)
        == calculate_sha256(second)
    )


def test_sensitive_fields_are_removed():
    payload = {
        "ssid": "Example",
        "password": "never-store-this",
        "nested": {
            "token": "secret-token",
            "channel": 44,
        },
    }

    cleaned = sanitize_evidence(payload)

    assert "password" not in cleaned
    assert "token" not in cleaned["nested"]
    assert cleaned["nested"]["channel"] == 44


def test_build_and_verify_evidence():
    envelope = build_evidence_envelope(
        evidence_type="network_snapshot",
        source="WiFi-Trace Time Machine",
        captured_at="2026-09-29T03:00:00+00:00",
        payload={
            "gateway": "10.0.0.1",
            "channel": "44",
        },
    )

    assert len(envelope["sha256"]) == 64
    assert verify_evidence(envelope) is True


def test_tampered_evidence_fails():
    envelope = build_evidence_envelope(
        evidence_type="network_snapshot",
        source="WiFi-Trace Time Machine",
        captured_at="2026-09-29T03:00:00+00:00",
        payload={
            "channel": "44",
        },
    )

    envelope["payload"]["channel"] = "149"

    assert verify_evidence(envelope) is False


def test_password_never_enters_envelope():
    envelope = build_evidence_envelope(
        evidence_type="network_snapshot",
        source="test",
        payload={
            "ssid": "Example",
            "wifi_password": "do-not-store",
        },
    )

    assert "wifi_password" not in envelope["payload"]
    assert verify_evidence(envelope) is True
