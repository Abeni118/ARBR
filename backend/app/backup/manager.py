import os
import shutil
from datetime import datetime

from .integrity import calculate_directory_sha256


def create_backup(source_dir: str, dest_dir: str) -> dict:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"backup_{timestamp}"
    backup_path = os.path.join(dest_dir, backup_filename)

    os.makedirs(dest_dir, exist_ok=True)

    try:
        if not os.path.isdir(source_dir):
            raise NotADirectoryError(f"Source directory not found: {source_dir}")

        if os.path.exists(backup_path):
            shutil.rmtree(backup_path)

        shutil.copytree(source_dir, backup_path)

        file_hash = calculate_directory_sha256(backup_path)

        size = sum(
            os.path.getsize(os.path.join(root, name))
            for root, _, files in os.walk(backup_path)
            for name in files
        )

        return {
            "filename": backup_filename,
            "file_path": backup_path,
            "size_bytes": size,
            "sha256_hash": file_hash,
            "status": "TRUSTED",
            "is_verified": True,
            "created_at": datetime.now(),
        }

    except (OSError, shutil.Error):
        if os.path.exists(backup_path):
            shutil.rmtree(backup_path, ignore_errors=True)
        return None


def lock_backup(file_path: str) -> bool:
    if not os.path.exists(file_path):
        return False

    try:
        if os.path.isdir(file_path):
            for root, _, files in os.walk(file_path):
                for name in files:
                    os.chmod(os.path.join(root, name), 0o444)
            os.chmod(file_path, 0o555)
        else:
            os.chmod(file_path, 0o444)

        return True
    except OSError:
        return False