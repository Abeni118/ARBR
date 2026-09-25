from pathlib import Path
import shutil

from backend.app.recovery.backup_verifier import BackupVerifier
from backend.app.recovery.restore_validator import RestoreValidator


class RecoveryManager:
    def __init__(
        self,
        backup_verifier: BackupVerifier,
        restore_validator: RestoreValidator,
    ):
        self.backup_verifier = backup_verifier
        self.restore_validator = restore_validator

    def recover(
        self,
        backup_path: str,
        restore_path: str,
        expected_hashes: dict[str, str],
        expected_files: list[str] | None = None,
    ) -> dict:
        verification = self.backup_verifier.verify_backup(
            backup_path,
            expected_hashes,
        )

        if not verification["trusted"]:
            return {
                "success": False,
                "status": "RECOVERY_BLOCKED",
                "reason": "BACKUP_NOT_TRUSTED",
                "verification": verification,
            }

        backup = Path(backup_path)
        restore = Path(restore_path)

        try:
            restore.mkdir(parents=True, exist_ok=True)

            for item in backup.iterdir():
                destination = restore / item.name

                if item.is_dir():
                    shutil.copytree(
                        item,
                        destination,
                        dirs_exist_ok=True,
                    )
                else:
                    shutil.copy2(item, destination)

        except (OSError, shutil.Error) as error:
            return {
                "success": False,
                "status": "RESTORE_FAILED",
                "error": str(error),
            }

        if expected_files is not None:
            validation = self.restore_validator.validate_files(
                str(restore),
                expected_files,
            )

            if not validation["success"]:
                return {
                    "success": False,
                    "status": "RESTORE_VALIDATION_FAILED",
                    "validation": validation,
                }

        return {
            "success": True,
            "status": "RECOVERY_COMPLETED",
            "backup_path": str(backup),
            "restore_path": str(restore),
            "verification": verification,
        }