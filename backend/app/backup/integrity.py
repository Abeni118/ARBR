
import hashlib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def calculate_sha256(file_path: str | Path) -> str:
    sha256_hash = hashlib.sha256()
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Backup file not found: {path}")

    if not path.is_file():
        raise IsADirectoryError(f"Path is not a file: {path}")

    with path.open("rb") as file:
        for byte_block in iter(lambda: file.read(65536), b""):
            sha256_hash.update(byte_block)

    return sha256_hash.hexdigest()


def verify_backup_integrity(file_path: str | Path, stored_hash: str) -> bool:
    try:
        current_hash = calculate_sha256(file_path)

        if current_hash != stored_hash:
            logger.warning(
                f"Integrity mismatch for {file_path}: "
                f"expected {stored_hash}, got {current_hash}"
            )
            return False

        logger.info(f"Integrity verified for {file_path}")
        return True

    except (FileNotFoundError, IsADirectoryError) as error:
        logger.error(f"Could not read backup file {file_path}: {error}")
        return False

    except Exception as error:
        logger.error(f"Error verifying backup: {error}")
        return False


def calculate_directory_sha256(directory_path: str | Path) -> str:
    root = Path(directory_path)

    if not root.exists():
        raise FileNotFoundError(f"Backup directory not found: {root}")

    if not root.is_dir():
        raise NotADirectoryError(f"Path is not a directory: {root}")

    entries = []

    for item in sorted(root.rglob("*")):
        if item.is_file():
            relative_path = item.relative_to(root).as_posix()
            file_hash = calculate_sha256(item)
            entries.append((relative_path, file_hash))

    master = hashlib.sha256()

    for relative_path, file_hash in entries:
        master.update(relative_path.encode("utf-8"))
        master.update(b"\0")
        master.update(file_hash.encode("utf-8"))
        master.update(b"\0")

    return master.hexdigest()
