"""
WiFi-Trace MAC Evidence Engine.

Defensive utilities for validating and interpreting MAC-address evidence.

Design rules:
- Never invent a MAC address.
- Never infer a vendor from a locally administered MAC.
- Never send MAC addresses to external services.
- Treat MAC-derived information as evidence, not device identity.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass


_MAC_HEX_RE = re.compile(r"^[0-9A-F]{12}$")


@dataclass(frozen=True)
class MacEvidence:
    raw: str | None
    normalized: str | None
    valid: bool
    address_type: str
    administration: str
    locally_administered: bool | None
    globally_administered: bool | None
    multicast: bool | None
    unicast: bool | None
    oui: str | None
    vendor_lookup_eligible: bool
    forensic_note: str

    def to_dict(self) -> dict:
        return asdict(self)


def normalize_mac(
    value: str | None,
) -> str | None:
    """
    Normalize common MAC-address representations.

    Accepted examples:
    AA:BB:CC:DD:EE:FF
    aa-bb-cc-dd-ee-ff
    aabb.ccdd.eeff
    AABBCCDDEEFF
    0:1a:2b:3c:4d:5e
    """

    if value is None:
        return None

    candidate = str(value).strip()

    if not candidate:
        return None

    # Cisco dotted notation.
    if "." in candidate:
        compact = candidate.replace(".", "")

        if not re.fullmatch(
            r"[0-9A-Fa-f]{12}",
            compact,
        ):
            return None

        octets = [
            compact[index:index + 2]
            for index in range(
                0,
                12,
                2,
            )
        ]

    # Colon/hyphen notation. Each octet may contain
    # one or two hexadecimal characters.
    elif ":" in candidate or "-" in candidate:
        parts = re.split(
            r"[:-]",
            candidate,
        )

        if len(parts) != 6:
            return None

        if not all(
            re.fullmatch(
                r"[0-9A-Fa-f]{1,2}",
                part,
            )
            for part in parts
        ):
            return None

        octets = [
            part.zfill(2)
            for part in parts
        ]

    else:
        if not re.fullmatch(
            r"[0-9A-Fa-f]{12}",
            candidate,
        ):
            return None

        octets = [
            candidate[index:index + 2]
            for index in range(
                0,
                12,
                2,
            )
        ]

    return ":".join(
        part.upper()
        for part in octets
    )


def _first_octet(normalized: str) -> int:
    return int(normalized[0:2], 16)


def is_multicast_mac(value: str | None) -> bool | None:
    normalized = normalize_mac(value)

    if normalized is None:
        return None

    return bool(_first_octet(normalized) & 0x01)


def is_locally_administered_mac(
    value: str | None,
) -> bool | None:
    normalized = normalize_mac(value)

    if normalized is None:
        return None

    return bool(_first_octet(normalized) & 0x02)


def get_oui(value: str | None) -> str | None:
    """
    Return an OUI only when vendor attribution is defensible.

    Multicast and locally administered addresses are intentionally
    excluded because their first 24 bits should not be treated as a
    reliable manufacturer identifier.
    """

    normalized = normalize_mac(value)

    if normalized is None:
        return None

    if is_multicast_mac(normalized):
        return None

    if is_locally_administered_mac(normalized):
        return None

    return ":".join(normalized.split(":")[:3])


def analyze_mac(value: str | None) -> MacEvidence:
    normalized = normalize_mac(value)

    if normalized is None:
        return MacEvidence(
            raw=value,
            normalized=None,
            valid=False,
            address_type="Unavailable",
            administration="Unavailable",
            locally_administered=None,
            globally_administered=None,
            multicast=None,
            unicast=None,
            oui=None,
            vendor_lookup_eligible=False,
            forensic_note=(
                "No valid MAC-address evidence is available."
            ),
        )

    multicast = bool(_first_octet(normalized) & 0x01)
    locally_administered = bool(
        _first_octet(normalized) & 0x02
    )

    unicast = not multicast
    globally_administered = not locally_administered

    if multicast:
        address_type = "Multicast"
    else:
        address_type = "Unicast"

    if locally_administered:
        administration = "Locally Administered"
    else:
        administration = "Globally Administered"

    vendor_lookup_eligible = (
        unicast and globally_administered
    )

    oui = (
        ":".join(normalized.split(":")[:3])
        if vendor_lookup_eligible
        else None
    )

    if multicast:
        forensic_note = (
            "This is a multicast MAC address. It must not be "
            "treated as a unique physical-device identifier or "
            "used for manufacturer attribution."
        )
    elif locally_administered:
        forensic_note = (
            "This is a locally administered MAC address. It may "
            "be randomized, private, virtual, or manually assigned. "
            "Manufacturer attribution from its prefix is not "
            "considered reliable."
        )
    else:
        forensic_note = (
            "This is a globally administered unicast MAC address. "
            "Its OUI is eligible for local manufacturer lookup, "
            "but a MAC address alone does not identify a person "
            "or prove current network association."
        )

    return MacEvidence(
        raw=value,
        normalized=normalized,
        valid=True,
        address_type=address_type,
        administration=administration,
        locally_administered=locally_administered,
        globally_administered=globally_administered,
        multicast=multicast,
        unicast=unicast,
        oui=oui,
        vendor_lookup_eligible=vendor_lookup_eligible,
        forensic_note=forensic_note,
    )


def mac_evidence_dict(value: str | None) -> dict:
    return analyze_mac(value).to_dict()
