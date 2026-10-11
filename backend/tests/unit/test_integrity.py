"""
Unit tests for backend.app.backup.integrity.
"""

import hashlib

import pytest

from backend.app.backup.integrity import (
    calculate_sha256,
    calculate_directory_sha256,
    verify_backup_integrity,
)


# -----------------------------------------------------------------------------
# calculate_sha256
# -----------------------------------------------------------------------------

def test_calculate_sha256_matches_reference_hash(tmp_path):
    backup = tmp_path / "backup.bin"
    backup.write_bytes(b"backup data")

    result = calculate_sha256(str(backup))

    assert result == hashlib.sha256(b"backup data").hexdigest()


def test_calculate_sha256_handles_files_larger_than_one_chunk(tmp_path):
    backup = tmp_path / "large.bin"
    data = b"A" * (200 * 1024)
    backup.write_bytes(data)

    result = calculate_sha256(str(backup))

    assert result == hashlib.sha256(data).hexdigest()


def test_calculate_sha256_raises_for_missing_file(tmp_path):
    missing = tmp_path / "does-not-exist.bin"

    with pytest.raises(FileNotFoundError):
        calculate_sha256(str(missing))


# -----------------------------------------------------------------------------
# verify_backup_integrity
# -----------------------------------------------------------------------------

def test_verify_backup_integrity_passes_for_untampered_file(tmp_path):
    backup = tmp_path / "backup.bin"
    backup.write_bytes(b"backup data")
    stored_hash = hashlib.sha256(b"backup data").hexdigest()

    assert verify_backup_integrity(str(backup), stored_hash) is True


def test_verify_backup_integrity_fails_when_file_is_tampered(tmp_path):
    backup = tmp_path / "backup.bin"
    backup.write_bytes(b"backup data")
    stored_hash = hashlib.sha256(b"backup data").hexdigest()

    backup.write_bytes(b"backup data!")

    assert verify_backup_integrity(str(backup), stored_hash) is False


def test_verify_backup_integrity_returns_false_for_missing_file(tmp_path):
    missing = tmp_path / "does-not-exist.bin"
    stored_hash = hashlib.sha256(b"anything").hexdigest()

    assert verify_backup_integrity(str(missing), stored_hash) is False


# -----------------------------------------------------------------------------
# calculate_directory_sha256
# -----------------------------------------------------------------------------

def test_calculate_directory_sha256_is_deterministic(tmp_path):
    backup = tmp_path / "backup"
    (backup / "sub").mkdir(parents=True)
    (backup / "a.txt").write_text("alpha")
    (backup / "sub" / "b.txt").write_text("beta")

    first = calculate_directory_sha256(str(backup))
    second = calculate_directory_sha256(str(backup))

    assert first == second


def test_calculate_directory_sha256_changes_when_file_changes(tmp_path):
    backup = tmp_path / "backup"
    backup.mkdir()
    (backup / "a.txt").write_text("alpha")

    before = calculate_directory_sha256(str(backup))

    (backup / "a.txt").write_text("alpha tampered")

    after = calculate_directory_sha256(str(backup))

    assert before != after


def test_calculate_directory_sha256_raises_for_missing_directory(tmp_path):
    with pytest.raises(FileNotFoundError):
        calculate_directory_sha256(str(tmp_path / "does-not-exist"))
