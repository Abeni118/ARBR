import hashlib

from backend.app.recovery.backup_verifier import BackupVerifier


def test_missing_backup_is_not_trusted(tmp_path):
    verifier = BackupVerifier()

    result = verifier.verify_backup(
        str(tmp_path / "missing"),
        {"data.txt": "abc123"},
    )

    assert result["success"] is False
    assert result["trusted"] is False
    assert result["status"] == "BACKUP_NOT_FOUND"


def test_empty_integrity_data_is_not_trusted(tmp_path):
    backup = tmp_path / "backup"
    backup.mkdir()

    verifier = BackupVerifier()

    result = verifier.verify_backup(
        str(backup),
        {},
    )

    assert result["success"] is False
    assert result["trusted"] is False
    assert result["status"] == "NO_INTEGRITY_DATA"


def test_valid_backup_is_trusted(tmp_path):
    backup = tmp_path / "backup"
    backup.mkdir()

    file_path = backup / "data.txt"
    file_path.write_text("trusted backup")

    file_hash = hashlib.sha256(
        file_path.read_bytes()
    ).hexdigest()

    verifier = BackupVerifier()

    result = verifier.verify_backup(
        str(backup),
        {"data.txt": file_hash},
    )

    assert result["success"] is True
    assert result["trusted"] is True
    assert result["status"] == "BACKUP_VERIFIED"


def test_modified_backup_is_not_trusted(tmp_path):
    backup = tmp_path / "backup"
    backup.mkdir()

    file_path = backup / "data.txt"
    file_path.write_text("original data")

    original_hash = hashlib.sha256(
        file_path.read_bytes()
    ).hexdigest()

    file_path.write_text("modified data")

    verifier = BackupVerifier()

    result = verifier.verify_backup(
        str(backup),
        {"data.txt": original_hash},
    )

    assert result["success"] is False
    assert result["trusted"] is False
    assert result["status"] == "INTEGRITY_FAILED"