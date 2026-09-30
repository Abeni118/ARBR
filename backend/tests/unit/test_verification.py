"""
Unit tests for backend.app.backup.verification.
"""

from backend.app.backup.recovery_point import RecoveryPoint
from backend.app.backup.verification import (
    STATUS_MISSING,
    STATUS_TAMPERED,
    STATUS_UNVERIFIED,
    STATUS_VERIFIED,
    apply_result_to_recovery_point,
    read_trusted_hash,
    verify_recovery_point,
    write_trusted_hash,
)


def _make_recovery_point(destination):
    return RecoveryPoint.create(
        backup_id="backup-001",
        source_path="/src",
        destination_path=str(destination),
        status="COMPLETED",
        file_count=1,
        size_bytes=10,
    )


# -----------------------------------------------------------------------------
# write / read trusted hash
# -----------------------------------------------------------------------------

def test_write_and_read_trusted_hash(tmp_path):
    backup_dir = tmp_path / "backup-001"
    backup_dir.mkdir()
    (backup_dir / "file.txt").write_text("data")

    storage_dir = tmp_path / "storage"

    sidecar = write_trusted_hash(str(backup_dir), "backup-001", storage_dir)

    assert sidecar.exists()
    assert read_trusted_hash("backup-001", storage_dir) is not None


def test_read_trusted_hash_returns_none_when_absent(tmp_path):
    assert read_trusted_hash("never-seen", tmp_path) is None


# -----------------------------------------------------------------------------
# verify_recovery_point
# -----------------------------------------------------------------------------

def test_verify_intact_backup_returns_verified(tmp_path):
    backup_dir = tmp_path / "backup-001"
    backup_dir.mkdir()
    (backup_dir / "file.txt").write_text("data")

    storage_dir = tmp_path / "storage"
    write_trusted_hash(str(backup_dir), "backup-001", storage_dir)

    result = verify_recovery_point(
        _make_recovery_point(backup_dir), storage_dir
    )

    assert result.status == STATUS_VERIFIED
    assert result.is_intact is True
    assert result.actual_hash == result.expected_hash


def test_verify_tampered_backup_returns_tampered(tmp_path):
    backup_dir = tmp_path / "backup-001"
    backup_dir.mkdir()
    (backup_dir / "file.txt").write_text("data")

    storage_dir = tmp_path / "storage"
    write_trusted_hash(str(backup_dir), "backup-001", storage_dir)

    # Tamper after recording the trusted hash.
    (backup_dir / "file.txt").write_text("data tampered")

    result = verify_recovery_point(
        _make_recovery_point(backup_dir), storage_dir
    )

    assert result.status == STATUS_TAMPERED
    assert result.is_intact is False
    assert result.actual_hash != result.expected_hash


def test_verify_missing_backup_dir_returns_missing(tmp_path):
    storage_dir = tmp_path / "storage"
    storage_dir.mkdir()
    # Note: no backup_dir exists, but write a sidecar manually.
    (storage_dir / "backup-001.sha256").write_text("dummy-hash")

    missing_dir = tmp_path / "gone"
    result = verify_recovery_point(
        _make_recovery_point(missing_dir), storage_dir
    )

    assert result.status == STATUS_MISSING


def test_verify_without_trusted_hash_returns_unverified(tmp_path):
    backup_dir = tmp_path / "backup-001"
    backup_dir.mkdir()

    storage_dir = tmp_path / "storage"
    storage_dir.mkdir()

    result = verify_recovery_point(
        _make_recovery_point(backup_dir), storage_dir
    )

    assert result.status == STATUS_UNVERIFIED


# -----------------------------------------------------------------------------
# apply_result_to_recovery_point
# -----------------------------------------------------------------------------

def test_apply_result_updates_integrity_status(tmp_path):
    backup_dir = tmp_path / "backup-001"
    backup_dir.mkdir()
    (backup_dir / "file.txt").write_text("data")

    storage_dir = tmp_path / "storage"
    write_trusted_hash(str(backup_dir), "backup-001", storage_dir)

    original = _make_recovery_point(backup_dir)
    assert original.integrity_status == "UNVERIFIED"
    result = verify_recovery_point(original, storage_dir)
    updated = apply_result_to_recovery_point(result, original)

    assert updated.integrity_status == STATUS_VERIFIED
    # Original must not be mutated.
    assert original.integrity_status == "UNVERIFIED"