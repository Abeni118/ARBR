"""
Unit tests for backend.app.backup.protection.

The chattr / lsattr commands are mocked via subprocess, so these tests
run on any OS including Windows.
"""

import subprocess
from pathlib import Path

import pytest

from backend.app.backup import protection
from backend.app.backup.protection import (
    is_locked,
    lock_backup,
    unlock_backup,
)


def _make_backup(tmp_path: Path) -> Path:
    backup = tmp_path / "backup-001"
    backup.mkdir()
    (backup / "file1.txt").write_text("data1")
    (backup / "file2.txt").write_text("data2")
    (backup / "sub").mkdir()
    (backup / "sub" / "file3.txt").write_text("data3")
    return backup


# -----------------------------------------------------------------------------
# lock_backup
# -----------------------------------------------------------------------------

def test_lock_backup_returns_failure_for_missing_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(protection, "_is_linux", lambda: True)

    result = lock_backup(tmp_path / "does-not-exist")

    assert result.success is False
    assert "does not exist" in result.error


def test_lock_backup_returns_failure_for_file_path(tmp_path, monkeypatch):
    monkeypatch.setattr(protection, "_is_linux", lambda: True)

    file_path = tmp_path / "somefile.txt"
    file_path.write_text("x")

    result = lock_backup(file_path)

    assert result.success is False
    assert "not a directory" in result.error


def test_lock_backup_fails_on_non_linux(tmp_path, monkeypatch):
    backup = _make_backup(tmp_path)
    monkeypatch.setattr(protection, "_is_linux", lambda: False)

    result = lock_backup(backup)

    assert result.success is False
    assert "requires Linux" in result.error


def test_lock_backup_success_calls_chattr_for_each_item(tmp_path, monkeypatch):
    backup = _make_backup(tmp_path)
    monkeypatch.setattr(protection, "_is_linux", lambda: True)

    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(protection.subprocess, "run", fake_run)

    result = lock_backup(backup)

    assert result.success is True
    # 3 files + 1 subfolder + 1 root folder = 5 items
    assert result.file_count == 5
    # Every call should be chattr +i <path>
    for command in calls:
        assert command[0] == "chattr"
        assert command[1] == "+i"


def test_lock_backup_handles_chattr_failure(tmp_path, monkeypatch):
    backup = _make_backup(tmp_path)
    monkeypatch.setattr(protection, "_is_linux", lambda: True)

    def failing_run(command, **kwargs):
        raise subprocess.CalledProcessError(
            returncode=1,
            cmd=command,
            stderr="Operation not permitted",
        )

    monkeypatch.setattr(protection.subprocess, "run", failing_run)

    result = lock_backup(backup)

    assert result.success is False
    assert "chattr failed" in result.error


# -----------------------------------------------------------------------------
# unlock_backup
# -----------------------------------------------------------------------------

def test_unlock_backup_success_calls_chattr_with_minus_i(tmp_path, monkeypatch):
    backup = _make_backup(tmp_path)
    monkeypatch.setattr(protection, "_is_linux", lambda: True)

    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(protection.subprocess, "run", fake_run)

    result = unlock_backup(backup)

    assert result.success is True
    for command in calls:
        assert command[0] == "chattr"
        assert command[1] == "-i"


def test_unlock_backup_returns_failure_for_missing_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(protection, "_is_linux", lambda: True)

    result = unlock_backup(tmp_path / "missing")

    assert result.success is False
    # -----------------------------------------------------------------------------
# is_locked
# -----------------------------------------------------------------------------

def test_is_locked_returns_true_when_flag_present(tmp_path, monkeypatch):
    backup = _make_backup(tmp_path)
    monkeypatch.setattr(protection, "_is_linux", lambda: True)

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command, 0, f"----i--------- {backup}\n", ""
        )

    monkeypatch.setattr(protection.subprocess, "run", fake_run)

    assert is_locked(backup) is True


def test_is_locked_returns_false_when_flag_absent(tmp_path, monkeypatch):
    backup = _make_backup(tmp_path)
    monkeypatch.setattr(protection, "_is_linux", lambda: True)

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command, 0, f"-------------- {backup}\n", ""
        )

    monkeypatch.setattr(protection.subprocess, "run", fake_run)

    assert is_locked(backup) is False


def test_is_locked_returns_false_on_non_linux(tmp_path, monkeypatch):
    backup = _make_backup(tmp_path)
    monkeypatch.setattr(protection, "_is_linux", lambda: False)

    assert is_locked(backup) is False


def test_is_locked_returns_false_when_path_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(protection, "_is_linux", lambda: True)

    assert is_locked(tmp_path / "missing") is False