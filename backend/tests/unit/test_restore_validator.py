from hashlib import sha256

from backend.app.recovery.restore_validator import RestoreValidator


def test_missing_restore_path(tmp_path):
    validator = RestoreValidator()

    result = validator.validate_path(
        str(tmp_path / "missing")
    )

    assert result["success"] is False
    assert result["status"] == "RESTORE_PATH_NOT_FOUND"


def test_valid_restore_path(tmp_path):
    restore = tmp_path / "restore"
    restore.mkdir()

    validator = RestoreValidator()

    result = validator.validate_path(
        str(restore)
    )

    assert result["success"] is True
    assert result["status"] == "RESTORE_PATH_VALID"


def test_missing_restored_file(tmp_path):
    restore = tmp_path / "restore"
    restore.mkdir()

    validator = RestoreValidator()

    result = validator.validate_files(
        str(restore),
        ["data.txt"],
    )

    assert result["success"] is False
    assert result["status"] == "FILES_MISSING"


def test_restored_files_are_valid(tmp_path):
    restore = tmp_path / "restore"
    restore.mkdir()

    (restore / "data.txt").write_text("restored data")

    validator = RestoreValidator()

    result = validator.validate_files(
        str(restore),
        ["data.txt"],
    )

    assert result["success"] is True
    assert result["status"] == "FILES_VALID"


def test_valid_file_hash(tmp_path):
    file_path = tmp_path / "data.txt"
    file_path.write_text("restored data")

    expected_hash = sha256(
        file_path.read_bytes()
    ).hexdigest()

    validator = RestoreValidator()

    result = validator.validate_hash(
        str(file_path),
        expected_hash,
    )

    assert result["success"] is True
    assert result["status"] == "INTEGRITY_VALID"


def test_modified_file_fails_hash_validation(tmp_path):
    file_path = tmp_path / "data.txt"
    file_path.write_text("original data")

    expected_hash = sha256(
        file_path.read_bytes()
    ).hexdigest()

    file_path.write_text("modified data")

    validator = RestoreValidator()

    result = validator.validate_hash(
        str(file_path),
        expected_hash,
    )

    assert result["success"] is False
    assert result["status"] == "INTEGRITY_FAILED"