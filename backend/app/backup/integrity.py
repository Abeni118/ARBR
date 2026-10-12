import hashlib
import os
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

def calculate_sha256(file_path: str | Path) -> str:
    """Calculates the SHA-256 fingerprint of a file."""
    sha256_hash = hashlib.sha256()
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Backup file not found: {path}")
    if not path.is_file():
        raise IsADirectoryError(f"Path is not a file: {path}")

    with open(path, "rb") as f:
        for byte_block in iter(lambda: f.read(65536), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def verify_backup_integrity(file_path: str | Path, stored_hash: str) -> bool:
    """Checks if a backup file is safe to restore."""
    try:
        current_hash = calculate_sha256(file_path)
        if current_hash != stored_hash:
            logger.warning(f"Integrity mismatch for {file_path}: expected {stored_hash}, got {current_hash}")
            return False
        logger.info(f"Integrity verified for {file_path}")
        return True
    except (FileNotFoundError, IsADirectoryError) as e:
        logger.error(f"Could not read backup file {file_path}: {e}")
        return False
    except Exception as e:
        logger.error(f"Error verifying backup: {e}")
        return False

def calculate_directory_sha256(directory_path: str | Path) -> str:
    """Calculates the SHA-256 hash of an entire directory."""
    sha256_hash = hashlib.sha256()
    path = Path(directory_path)
    
    if not path.exists():
        raise FileNotFoundError(f"Directory not found: {path}")
        
    # Walk through all files in the directory and hash their contents
    for root, dirs, files in os.walk(path):
        dirs.sort()  # Ensure deterministic order
        for file in sorted(files):
            file_path = os.path.join(root, file)
            sha256_hash.update(file.encode()) # Include the filename in the hash
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(65536), b""):
                    sha256_hash.update(byte_block)
                    
    return sha256_hash.hexdigest()