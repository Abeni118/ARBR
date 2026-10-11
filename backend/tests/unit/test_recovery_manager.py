import hashlib

from backend.app.recovery.backup_verifier import BackupVerifier
from backend.app.recovery.recovery_manager import RecoveryManager
from backend.app.recovery.restore_validator import RestoreValidator


def test_recovery_blocked_when_backup_missing(tmp_path):
    manager = RecoveryManager(
        BackupVerifier(),
        RestoreValidator(),
    )

    result = manager.recover(
        str(tmp_path / "missing"),
        str(tmp_path / "restore"),
        {"data.txt": "abc123"},
    )

    assert result["success"] is False
    assert result["status"] == "RECOVERY_BLOCKED"
    assert result["reason"] == "BACKUP_NOT_TRUSTED"


def test_recovery_blocked_when_backup_integrity_fails(tmp_path):
    backup = tmp_path / "backup"
    backup.mkdir()

    file_path = backup / "data.txt"
    file_path.write_text("modified data")

    wrong_hash = hashlib.sha256(
        b"original data"
    ).hexdigest()

    manager = RecoveryManager(
        BackupVerifier(),
        RestoreValidator(),
    )

    result = manager.recover(
        str(backup),
        str(tmp_path / "restore"),
        {"data.txt": wrong_hash},
    )

    assert result["success"] is False
    assert result["status"] == "RECOVERY_BLOCKED"
    assert result["reason"] == "BACKUP_NOT_TRUSTED"


def test_successful_recovery(tmp_path):
    backup = tmp_path / "backup"
    backup.mkdir()

    file_path = backup / "data.txt"
    file_path.write_text("trusted data")

    file_hash = hashlib.sha256(
        file_path.read_bytes()
    ).hexdigest()

    restore = tmp_path / "restore"

    manager = RecoveryManager(
        BackupVerifier(),
        RestoreValidator(),
    )

    result = manager.recover(
        str(backup),
        str(restore),
        {"data.txt": file_hash},
        ["data.txt"],
    )

    assert result["success"] is True
    assert result["status"] == "RECOVERY_COMPLETED"
    assert (
        restore / "data.txt"
    ).read_text() == "trusted data"


def test_recovery_copies_nested_directories(tmp_path):
    backup = tmp_path / "backup"
    backup.mkdir()

    nested = backup / "documents"
    nested.mkdir()

    file_path = nested / "report.txt"
    file_path.write_text("important report")

    file_hash = hashlib.sha256(
        file_path.read_bytes()
    ).hexdigest()

    restore = tmp_path / "restore"

    manager = RecoveryManager(
        BackupVerifier(),
        RestoreValidator(),
    )

    result = manager.recover(
        str(backup),
        str(restore),
        {"documents/report.txt": file_hash},
        ["documents/report.txt"],
    )

    assert result["success"] is True
    assert result["status"] == "RECOVERY_COMPLETED"
    assert (
        restore / "documents" / "report.txt"
    ).read_text() == "important report"


def test_successful_recovery_records_operation_details(tmp_path):
    backup = tmp_path / "backup"
    backup.mkdir()

    file_path = backup / "data.txt"
    file_path.write_text("trusted data")

    file_hash = hashlib.sha256(
        file_path.read_bytes()
    ).hexdigest()

    restore = tmp_path / "restore"

    manager = RecoveryManager(
        BackupVerifier(),
        RestoreValidator(),
    )

    result = manager.recover(
        str(backup),
        str(restore),
        {"data.txt": file_hash},
        ["data.txt"],
    )

    assert result["operation_id"]
    assert result["started_at"]
    assert result["completed_at"]
    assert result["status"] == "RECOVERY_COMPLETED"
    assert result["success"] is True
    assert result["verification"]["trusted"] is True
    assert result["validation"]["success"] is True


def test_blocked_recovery_records_failure_details(tmp_path):
    manager = RecoveryManager(
        BackupVerifier(),
        RestoreValidator(),
    )

    result = manager.recover(
        str(tmp_path / "missing"),
        str(tmp_path / "restore"),
        {"data.txt": "abc123"},
    )

    assert result["operation_id"]
    assert result["started_at"]
    assert result["completed_at"]
    assert result["status"] == "RECOVERY_BLOCKED"
    assert result["success"] is False
    assert result["error"] == "Backup is not trusted."
    assert result["verification"]["trusted"] is False
