import pytest

from wifi_trace.macos_neighbors import (
    _extract_mac,
    _validate_private_ipv4,
    collect_neighbors,
)


def test_validate_private_ipv4():
    assert _validate_private_ipv4("192.168.1.25") == "192.168.1.25"


def test_reject_public_ipv4():
    with pytest.raises(ValueError):
        _validate_private_ipv4("8.8.8.8")


def test_reject_invalid_ip():
    with pytest.raises(ValueError):
        _validate_private_ipv4("not-an-ip")


def test_reject_loopback():
    with pytest.raises(ValueError):
        _validate_private_ipv4("127.0.0.1")


def test_extract_standard_arp_mac():
    output = (
        "? (192.168.1.25) at "
        "0:1a:2b:3c:4d:5e on en0 ifscope"
    )

    assert (
        _extract_mac(output)
        == "00:1A:2B:3C:4D:5E"
    )


def test_extract_missing_mac():
    output = (
        "? (192.168.1.25) at "
        "(incomplete) on en0 ifscope"
    )

    assert _extract_mac(output) is None


def test_collect_neighbors_deduplicates_invalid_targets():
    results = collect_neighbors(
        [
            "not-an-ip",
            "8.8.8.8",
        ]
    )

    assert results == []
