from wifi_trace.mac_evidence import (
    analyze_mac,
    get_oui,
    is_locally_administered_mac,
    is_multicast_mac,
    normalize_mac,
)


def test_normalize_colon_mac():
    assert (
        normalize_mac("00:1a:2b:3c:4d:5e")
        == "00:1A:2B:3C:4D:5E"
    )


def test_normalize_dash_mac():
    assert (
        normalize_mac("00-1a-2b-3c-4d-5e")
        == "00:1A:2B:3C:4D:5E"
    )


def test_normalize_cisco_style_mac():
    assert (
        normalize_mac("001a.2b3c.4d5e")
        == "00:1A:2B:3C:4D:5E"
    )


def test_normalize_compact_mac():
    assert (
        normalize_mac("001a2b3c4d5e")
        == "00:1A:2B:3C:4D:5E"
    )


def test_invalid_mac_returns_none():
    assert normalize_mac("not-a-mac") is None


def test_empty_mac_returns_none():
    assert normalize_mac("") is None


def test_none_mac_returns_none():
    assert normalize_mac(None) is None


def test_globally_administered_unicast():
    evidence = analyze_mac("00:1A:2B:3C:4D:5E")

    assert evidence.valid is True
    assert evidence.unicast is True
    assert evidence.multicast is False
    assert evidence.locally_administered is False
    assert evidence.globally_administered is True
    assert evidence.vendor_lookup_eligible is True
    assert evidence.oui == "00:1A:2B"


def test_locally_administered_unicast():
    evidence = analyze_mac("02:11:22:33:44:55")

    assert evidence.valid is True
    assert evidence.unicast is True
    assert evidence.multicast is False
    assert evidence.locally_administered is True
    assert evidence.globally_administered is False
    assert evidence.vendor_lookup_eligible is False
    assert evidence.oui is None


def test_multicast_mac():
    evidence = analyze_mac("01:00:5E:00:00:01")

    assert evidence.valid is True
    assert evidence.multicast is True
    assert evidence.unicast is False
    assert evidence.vendor_lookup_eligible is False
    assert evidence.oui is None


def test_locally_administered_detection():
    assert (
        is_locally_administered_mac(
            "02:11:22:33:44:55"
        )
        is True
    )


def test_multicast_detection():
    assert (
        is_multicast_mac(
            "01:00:5E:00:00:01"
        )
        is True
    )


def test_oui_from_global_unicast():
    assert (
        get_oui("00:1A:2B:3C:4D:5E")
        == "00:1A:2B"
    )


def test_no_oui_from_local_mac():
    assert get_oui("02:11:22:33:44:55") is None


def test_no_oui_from_multicast_mac():
    assert get_oui("01:00:5E:00:00:01") is None


def test_invalid_analysis_is_safe():
    evidence = analyze_mac("invalid")

    assert evidence.valid is False
    assert evidence.normalized is None
    assert evidence.oui is None
    assert evidence.vendor_lookup_eligible is False
