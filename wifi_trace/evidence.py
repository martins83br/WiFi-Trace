"""
WiFi-Trace Evidence Locker.

Creates deterministic evidence records from WiFi-Trace observations.

Principles:
- Evidence is append-only.
- SHA-256 protects integrity verification.
- Original evidence payload is preserved.
- Passwords and credentials must never enter evidence records.
- Evidence timestamps use UTC.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any


SENSITIVE_KEYS = {
    "password",
    "wifi_password",
    "credential",
    "credentials",
    "secret",
    "token",
    "api_key",
    "private_key",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sanitize_evidence(value: Any) -> Any:
    """
    Recursively remove sensitive fields before evidence is serialized.
    """

    if isinstance(value, dict):
        cleaned = {}

        for key, item in value.items():
            if str(key).lower() in SENSITIVE_KEYS:
                continue

            cleaned[key] = sanitize_evidence(item)

        return cleaned

    if isinstance(value, list):
        return [
            sanitize_evidence(item)
            for item in value
        ]

    if isinstance(value, tuple):
        return [
            sanitize_evidence(item)
            for item in value
        ]

    return value


def canonical_json(payload: dict) -> str:
    """
    Deterministic JSON representation used for hashing.
    """

    cleaned = sanitize_evidence(payload)

    return json.dumps(
        cleaned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def calculate_sha256(payload: dict) -> str:
    serialized = canonical_json(payload)

    return hashlib.sha256(
        serialized.encode("utf-8")
    ).hexdigest()


def build_evidence_envelope(
    *,
    evidence_type: str,
    source: str,
    payload: dict,
    captured_at: str | None = None,
) -> dict:
    """
    Create an integrity-protected evidence envelope.

    The SHA-256 covers the evidence content, type, source and capture
    timestamp, but not the hash field itself.
    """

    envelope = {
        "schema": "wifi-trace-evidence-v1",
        "evidence_type": evidence_type,
        "source": source,
        "captured_at": captured_at or utc_now(),
        "payload": sanitize_evidence(payload),
    }

    envelope["sha256"] = calculate_sha256(
        envelope
    )

    return envelope


def verify_evidence(envelope: dict) -> bool:
    supplied_hash = envelope.get("sha256")

    if not isinstance(supplied_hash, str):
        return False

    candidate = {
        key: value
        for key, value in envelope.items()
        if key != "sha256"
    }

    calculated = calculate_sha256(candidate)

    return hashlib.compare_digest(
        supplied_hash,
        calculated,
    )
