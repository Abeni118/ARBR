from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import logging
import subprocess


logging.basicConfig(
    filename="backup.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


@dataclass
class BackupResult:
    backup_id: str
    source_path: str
    destination_path: str
    started_at: str
    completed_at: str | None
    status: str
    file_count: int
    size_bytes: int
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "backup_id": self.backup_id,
            "source_path": self.source_path,
            "destination_path": self.destination_path,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "status": self.status,
            "file_count": self.file_count,
            "size_bytes": self.size_bytes,
            "error": self.error,
        }


class BackupManager:
    def __init__(self, rsync_path: str = "rsync"):
        self.rsync_path = rsync_path

    def create_backup(
        self,
        backup_id: str,
        source_path: str,
        destination_path: str,
    ) -> BackupResult:
        started_at = datetime.now(timezone.utc).isoformat()

        source = Path(source_path)
        destination = Path(destination_path)

        if not source.exists():
            return BackupResult(
                backup_id=backup_id,
                source_path=source_path,
                destination_path=destination_path,
                started_at=started_at,
                completed_at=None,
                status="FAILED",
                file_count=0,
                size_bytes=0,
                error="Source path does not exist.",
            )

        if not source.is_dir():
            return BackupResult(
                backup_id=backup_id,
                source_path=source_path,
                destination_path=destination_path,
                started_at=started_at,
                completed_at=None,
                status="FAILED",
                file_count=0,
                size_bytes=0,
                error="Source path is not a directory.",
            )

        try:
            destination.mkdir(
                parents=True,
                exist_ok=True,
            )

            command = [
                self.rsync_path,
                "-a",
                "--delete",
                f"{source}/",
                f"{destination}/",
            ]

            logging.info(
                "Starting backup %s from %s to %s.",
                backup_id,
                source_path,
                destination_path,
            )

            subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
            )

            file_count, size_bytes = self._get_statistics(
                destination
            )

            completed_at = datetime.now(
                timezone.utc
            ).isoformat()

            logging.info(
                "Backup %s completed successfully.",
                backup_id,
            )

            return BackupResult(
                backup_id=backup_id,
                source_path=source_path,
                destination_path=destination_path,
                started_at=started_at,
                completed_at=completed_at,
                status="COMPLETED",
                file_count=file_count,
                size_bytes=size_bytes,
            )

        except (OSError, subprocess.CalledProcessError) as error:
            logging.error(
                "Backup %s failed: %s",
                backup_id,
                error,
            )

            return BackupResult(
                backup_id=backup_id,
                source_path=source_path,
                destination_path=destination_path,
                started_at=started_at,
                completed_at=datetime.now(
                    timezone.utc
                ).isoformat(),
                status="FAILED",
                file_count=0,
                size_bytes=0,
                error=str(error),
            )

    def _get_statistics(
        self,
        path: Path,
    ) -> tuple[int, int]:
        file_count = 0
        size_bytes = 0

        for item in path.rglob("*"):
            if item.is_file():
                file_count += 1
                size_bytes += item.stat().st_size

        return file_count, size_bytes