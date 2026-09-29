import json

import pytest

from wifi_trace.database import (
    add_snapshot_to_investigation,
    create_investigation,
    get_connection,
    get_evidence_item,
    get_evidence_verifications,
    init_evidence_integrity_database,
    verify_stored_evidence,
)


def _latest_snapshot_id():
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT id
            FROM snapshots
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()

    return row["id"] if row else None


def test_integrity_database_initializes():
    init_evidence_integrity_database()

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name =
                'evidence_verifications'
            """
        ).fetchone()

    assert row is not None


def test_missing_evidence_fails_safely():
    with pytest.raises(
        ValueError,
        match="Evidence item not found",
    ):
        verify_stored_evidence(
            999999999
        )


def test_preserved_snapshot_verifies():
    snapshot_id = _latest_snapshot_id()

    if snapshot_id is None:
        pytest.skip(
            "No snapshot available."
        )

    investigation_id = (
        create_investigation(
            "Integrity Test Case"
        )
    )

    preserved = (
        add_snapshot_to_investigation(
            investigation_id,
            snapshot_id,
            note=(
                "Automated integrity test."
            ),
        )
    )

    result = verify_stored_evidence(
        preserved["evidence_id"]
    )

    assert (
        result["result"]
        == "VERIFIED"
    )

    assert (
        result["expected_sha256"]
        == result[
            "calculated_sha256"
        ]
    )

    history = (
        get_evidence_verifications(
            preserved["evidence_id"]
        )
    )

    assert len(history) >= 1

    assert (
        history[0]["result"]
        == "VERIFIED"
    )


def test_tampering_is_detected():
    snapshot_id = _latest_snapshot_id()

    if snapshot_id is None:
        pytest.skip(
            "No snapshot available."
        )

    investigation_id = (
        create_investigation(
            "Tamper Detection Test"
        )
    )

    preserved = (
        add_snapshot_to_investigation(
            investigation_id,
            snapshot_id,
        )
    )

    evidence_id = (
        preserved["evidence_id"]
    )

    evidence = get_evidence_item(
        evidence_id
    )

    original_payload = (
        evidence["payload_json"]
    )

    payload = json.loads(
        original_payload
    )

    payload[
        "_integrity_test"
    ] = "tampered"

    with get_connection() as connection:
        connection.execute(
            """
            UPDATE investigation_evidence
            SET payload_json = ?
            WHERE id = ?
            """,
            (
                json.dumps(
                    payload,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                evidence_id,
            ),
        )

    try:
        result = verify_stored_evidence(
            evidence_id
        )

        assert (
            result["result"]
            == "FAILED"
        )

        assert (
            result[
                "expected_sha256"
            ]
            != result[
                "calculated_sha256"
            ]
        )

    finally:
        # Restore the test record so the development
        # database is not intentionally left corrupted.
        with get_connection() as connection:
            connection.execute(
                """
                UPDATE investigation_evidence
                SET payload_json = ?
                WHERE id = ?
                """,
                (
                    original_payload,
                    evidence_id,
                ),
            )
