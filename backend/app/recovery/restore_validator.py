from hashlib import sha256
from pathlib import Path


class RestoreValidator:
    def validate_path(self, restore_path: str) -> dict:
        path = Path(restore_path)

        if not path.exists():
            return {
                "success": False,
                "status": "RESTORE_PATH_NOT_FOUND",
                "path": str(path),
            }

        if not path.is_dir():
            return {
                "success": False,
                "status": "RESTORE_PATH_INVALID",
                "path": str(path),
            }

        return {
            "success": True,
            "status": "RESTORE_PATH_VALID",
            "path": str(path),
        }

    def validate_files(
        self,
        restore_path: str,
        expected_files: list[str],
    ) -> dict:
        path_result = self.validate_path(restore_path)

        if not path_result["success"]:
            return path_result

        root = Path(restore_path)
        missing_files = [
            file for file in expected_files
            if not (root / file).is_file()
        ]

        if missing_files:
            return {
                "success": False,
                "status": "FILES_MISSING",
                "path": str(root),
                "missing_files": missing_files,
            }

        return {
            "success": True,
            "status": "FILES_VALID",
            "path": str(root),
            "files_checked": len(expected_files),
        }

    def calculate_hash(self, file_path: str) -> str:
        path = Path(file_path)
        digest = sha256()

        with path.open("rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                digest.update(chunk)

        return digest.hexdigest()

    def validate_hash(
        self,
        file_path: str,
        expected_hash: str,
    ) -> dict:
        path = Path(file_path)

        if not path.is_file():
            return {
                "success": False,
                "status": "FILE_NOT_FOUND",
                "path": str(path),
            }

        actual_hash = self.calculate_hash(str(path))

        if actual_hash != expected_hash.lower():
            return {
                "success": False,
                "status": "INTEGRITY_FAILED",
                "path": str(path),
                "expected_hash": expected_hash.lower(),
                "actual_hash": actual_hash,
            }

        return {
            "success": True,
            "status": "INTEGRITY_VALID",
            "path": str(path),
            "hash": actual_hash,
        }