from wifi_trace.mac_evidence import analyze_mac


def test_global_mac_is_vendor_lookup_eligible():
    evidence = analyze_mac(
        "00:1A:2B:3C:4D:5E"
    )

    assert evidence.valid is True
    assert evidence.vendor_lookup_eligible is True
    assert evidence.oui == "00:1A:2B"


def test_private_mac_blocks_vendor_lookup():
    evidence = analyze_mac(
        "02:11:22:33:44:55"
    )

    assert evidence.valid is True
    assert evidence.locally_administered is True
    assert evidence.vendor_lookup_eligible is False
    assert evidence.oui is None


def test_multicast_blocks_vendor_lookup():
    evidence = analyze_mac(
        "01:00:5E:00:00:01"
    )

    assert evidence.valid is True
    assert evidence.multicast is True
    assert evidence.vendor_lookup_eligible is False
    assert evidence.oui is None
