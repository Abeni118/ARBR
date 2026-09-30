"""
Backup integrity verification.

Provides SHA-256 hashing and tamper detection for backup files. Used by
the recovery, audit, and reporting layers to confirm a backup has not
been altered since it was created.
"""

from pathlib import Path
import hashlib
import logging


logger = logging.getLogger(__name__)

# Files are read in fixed-size chunks so memory usage stays low even when
# verifying very large backups. 64 KB is a common sweet spot.
CHUNK_SIZE_BYTES = 64 * 1024


def calculate_sha256(file_path: str | Path) -> str:
    """
    Calculate the SHA-256 hash of a file.

    The file is streamed in fixed-size chunks, so this is safe to call on
    backups that are much larger than available memory.

    Args:
        file_path: Path to the file to hash.

    Returns:
        The SHA-256 digest as a lowercase hexadecimal string (64 characters).

    Raises:
        FileNotFoundError: If the file does not exist.
        IsADirectoryError: If the path points to a directory instead of a file.
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Backup file not found: {path}")

    if not path.is_file():
        raise IsADirectoryError(f"Path is not a file: {path}")

    sha256 = hashlib.sha256()

    with path.open("rb") as backup_file:
        for chunk in iter(lambda: backup_file.read(CHUNK_SIZE_BYTES), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def verify_backup_integrity(file_path: str | Path, stored_hash: str) -> bool:
    """
    Check whether a backup file still matches its trusted stored hash.

    This is the main entry point used by the backup and recovery layers.
    It never raises: any failure (missing file, unreadable path, hash
    mismatch) is reported as ``False`` so callers can treat the backup as
    unsafe without wrapping the call in try/except.

    Args:
        file_path: Path to the backup file to verify.
        stored_hash: The trusted SHA-256 hash (hex string) recorded when
            the backup was created.

    Returns:
        True if the file exists and its current hash matches ``stored_hash``.
        False otherwise.
    """
    try:
        current_hash = calculate_sha256(file_path)
    except FileNotFoundError:
        logger.warning(
            "Backup file missing during integrity check: %s", file_path
        )
        return False
    except OSError as error:
        logger.error("Could not read backup file %s: %s", file_path, error)
        return False

    if current_hash != stored_hash:
        logger.warning(
            "Integrity mismatch for %s: expected %s, got %s",
            file_path,
            stored_hash,
            current_hash,
        )
        return False

    logger.info("Integrity verified for %s", file_path)
    return True