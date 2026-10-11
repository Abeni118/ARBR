from pathlib import Path


class BackupStorageManager:
    def __init__(self, storage_path: str):
        self.storage_path = Path(storage_path)

    def create_recovery_point(
        self,
        backup_id: str,
    ) -> Path:
        recovery_point = self.storage_path / backup_id

        if recovery_point.exists():
            raise FileExistsError(
                f"Recovery point already exists: {backup_id}"
            )

        recovery_point.mkdir(
            parents=True,
            exist_ok=False,
        )

        return recovery_point

    def get_recovery_point(
        self,
        backup_id: str,
    ) -> Path:
        return self.storage_path / backup_id

    def recovery_point_exists(
        self,
        backup_id: str,
    ) -> bool:
        return self.get_recovery_point(backup_id).is_dir()

    def list_recovery_points(self) -> list[Path]:
        if not self.storage_path.exists():
            return []

        return sorted(
            path
            for path in self.storage_path.iterdir()
            if path.is_dir()
        )