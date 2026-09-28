from pathlib import Path
import shutil

from backend.app.recovery.backup_verifier import BackupVerifier
from backend.app.recovery.recovery_operation import RecoveryOperation
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
        operation = RecoveryOperation(
            backup_path,
            restore_path,
        )

        verification = self.backup_verifier.verify_backup(
            backup_path,
            expected_hashes,
        )

        operation.verification = verification

        if not verification["trusted"]:
            operation.fail(
                "RECOVERY_BLOCKED",
                "Backup is not trusted.",
            )

            result = operation.to_dict()
            result["success"] = False
            result["reason"] = "BACKUP_NOT_TRUSTED"
            return result

        backup = Path(backup_path)
        restore = Path(restore_path)

        try:
            restore.mkdir(
                parents=True,
                exist_ok=True,
            )

            for item in backup.iterdir():
                destination = restore / item.name

                if item.is_dir():
                    shutil.copytree(
                        item,
                        destination,
                        dirs_exist_ok=True,
                    )
                else:
                    shutil.copy2(
                        item,
                        destination,
                    )

        except (OSError, shutil.Error) as error:
            operation.fail(
                "RESTORE_FAILED",
                str(error),
            )

            result = operation.to_dict()
            result["success"] = False
            return result

        if expected_files is not None:
            validation = self.restore_validator.validate_files(
                str(restore),
                expected_files,
            )

            operation.validation = validation

            if not validation["success"]:
                operation.fail(
                    "RESTORE_VALIDATION_FAILED",
                    "Restored files failed validation.",
                )

                result = operation.to_dict()
                result["success"] = False
                return result

        operation.complete()

        result = operation.to_dict()
        result["success"] = True
        return result