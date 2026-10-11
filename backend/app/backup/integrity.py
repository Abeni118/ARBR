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
def calculate_directory_sha256(directory_path: str | Path) -> str:
    """
    Calculate a deterministic SHA-256 hash of a directory tree.

    Hashes the sorted list of (relative_path, file_hash) pairs, so the
    result depends only on directory contents — not on the order the OS
    happens to enumerate files. This is what makes it a "backup identity":
    the same backup always hashes to the same value.

    Args:
        directory_path: Root directory to hash.

    Returns:
        Hex digest (64 characters).

    Raises:
        FileNotFoundError: If the directory does not exist.
        NotADirectoryError: If the path points to a file.
    """
    root = Path(directory_path)

    if not root.exists():
        raise FileNotFoundError(f"Backup directory not found: {root}")

    if not root.is_dir():
        raise NotADirectoryError(f"Path is not a directory: {root}")

    entries: list[tuple[str, str]] = []
    for item in sorted(root.rglob("*")):
        if item.is_file():
            relative = item.relative_to(root).as_posix()
            entries.append((relative, calculate_sha256(item)))

    master = hashlib.sha256()
    for relative, file_hash in entries:
        master.update(relative.encode("utf-8"))
        master.update(b"\0")
        master.update(file_hash.encode("utf-8"))
        master.update(b"\0")

    return master.hexdigest()
import os

def calculate_directory_sha256(dir_path: str) -> str:
    """Calculates the SHA-256 hash of an entire directory."""
    sha256_hash = hashlib.sha256()
    if not os.path.exists(dir_path):
        raise FileNotFoundError(f"Directory not found: {dir_path}")
        
    # Walk through all files in the directory and hash their contents
    for root, dirs, files in os.walk(dir_path):
        dirs.sort()
        for file in sorted(files):
            file_path = os.path.join(root, file)
            sha256_hash.update(file.encode()) # Include filename
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(65536), b""):
                    sha256_hash.update(byte_block)
                    
    return sha256_hash.hexdigest()