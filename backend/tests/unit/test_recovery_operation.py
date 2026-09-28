from datetime import datetime

from backend.app.recovery.recovery_operation import RecoveryOperation


def test_recovery_operation_starts_with_expected_state():
    operation = RecoveryOperation(
        "/backup/point-1",
        "/restore",
    )

    assert operation.operation_id
    assert operation.backup_path == "/backup/point-1"
    assert operation.restore_path == "/restore"
    assert operation.status == "STARTED"
    assert operation.completed_at is None
    assert operation.error is None


def test_recovery_operation_completes():
    operation = RecoveryOperation(
        "/backup/point-1",
        "/restore",
    )

    operation.complete()

    assert operation.status == "RECOVERY_COMPLETED"
    assert operation.completed_at is not None


def test_recovery_operation_fails():
    operation = RecoveryOperation(
        "/backup/point-1",
        "/restore",
    )

    operation.fail(
        "RESTORE_FAILED",
        "Restore destination is unavailable",
    )

    assert operation.status == "RESTORE_FAILED"
    assert operation.error == (
        "Restore destination is unavailable"
    )
    assert operation.completed_at is not None


def test_recovery_operation_to_dict():
    operation = RecoveryOperation(
        "/backup/point-1",
        "/restore",
    )

    operation.verification = {
        "trusted": True,
    }

    data = operation.to_dict()

    assert data["operation_id"] == operation.operation_id
    assert data["backup_path"] == "/backup/point-1"
    assert data["restore_path"] == "/restore"
    assert data["status"] == "STARTED"
    assert data["verification"]["trusted"] is True