import hashlib

from backend.app.recovery.backup_verifier import BackupVerifier
from backend.app.recovery.recovery_manager import RecoveryManager
from backend.app.recovery.restore_validator import RestoreValidator


def test_real_recovery_flow(tmp_path):
    backup = tmp_path / "backup"
    restore = tmp_path / "restore"

    backup.mkdir()

    (backup / "important.txt").write_text(
        "Attack-Resistant Backup System"
    )

    documents = backup / "documents"
    documents.mkdir()

    (documents / "report.txt").write_text(
        "Trusted recovery data"
    )

    expected_hashes = {
        "important.txt": hashlib.sha256(
            (backup / "important.txt").read_bytes()
        ).hexdigest(),
        "documents/report.txt": hashlib.sha256(
            (documents / "report.txt").read_bytes()
        ).hexdigest(),
    }

    manager = RecoveryManager(
        BackupVerifier(),
        RestoreValidator(),
    )

    result = manager.recover(
        str(backup),
        str(restore),
        expected_hashes,
        [
            "important.txt",
            "documents/report.txt",
        ],
    )

    assert result["success"] is True
    assert result["status"] == "RECOVERY_COMPLETED"

    assert (
        restore / "important.txt"
    ).read_text() == "Attack-Resistant Backup System"

    assert (
        restore / "documents" / "report.txt"
    ).read_text() == "Trusted recovery data"