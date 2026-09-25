import hashlib
from pathlib import Path


class BackupVerifier:
    def verify_backup(
        self,
        backup_path: str,
        expected_hashes: dict[str, str],
    ) -> dict:
        backup = Path(backup_path)

        if not backup.exists():
            return {
                "success": False,
                "status": "BACKUP_NOT_FOUND",
                "backup_path": str(backup),
                "trusted": False,
            }

        if not backup.is_dir():
            return {
                "success": False,
                "status": "BACKUP_PATH_INVALID",
                "backup_path": str(backup),
                "trusted": False,
            }

        if not expected_hashes:
            return {
                "success": False,
                "status": "NO_INTEGRITY_DATA",
                "backup_path": str(backup),
                "trusted": False,
            }

        mismatches = []

        for relative_path, expected_hash in expected_hashes.items():
            file_path = backup / relative_path

            if not file_path.is_file():
                mismatches.append(
                    {
                        "file": relative_path,
                        "reason": "FILE_NOT_FOUND",
                    }
                )
                continue

            actual_hash = self._calculate_hash(file_path)

            if actual_hash != expected_hash.lower():
                mismatches.append(
                    {
                        "file": relative_path,
                        "reason": "HASH_MISMATCH",
                        "expected_hash": expected_hash.lower(),
                        "actual_hash": actual_hash,
                    }
                )

        if mismatches:
            return {
                "success": False,
                "status": "INTEGRITY_FAILED",
                "backup_path": str(backup),
                "trusted": False,
                "mismatches": mismatches,
            }

        return {
            "success": True,
            "status": "BACKUP_VERIFIED",
            "backup_path": str(backup),
            "trusted": True,
            "files_verified": len(expected_hashes),
        }

    def _calculate_hash(self, file_path: Path) -> str:
        digest = hashlib.sha256()

        with file_path.open("rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                digest.update(chunk)

        return digest.hexdigest()