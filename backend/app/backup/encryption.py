"""
Backup encryption at rest using Fernet (symmetric authenticated encryption).

Implements FR-B05: store backups encrypted at rest. Each backup file is
encrypted individually with a per-backup key. The encrypted file gets a
.enc suffix; the key is stored separately.

For the MVP, keys are stored as plain files next to the encrypted backups.
In production this should be replaced with a proper key management system
(KMS, HashiCorp Vault, or an OS keyring).

Uses the cryptography library (pip install cryptography).
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import logging

from cryptography.fernet import Fernet, InvalidToken


logger = logging.getLogger(__name__)

ENCRYPTED_SUFFIX = ".enc"
KEY_SUFFIX = ".key"


@dataclass
class EncryptionResult:
    source_path: str
    destination_path: str
    file_count: int
    success: bool
    attempted_at: str
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "source_path": self.source_path,
            "destination_path": self.destination_path,
            "file_count": self.file_count,
            "success": self.success,
            "attempted_at": self.attempted_at,
            "errors": self.errors,
        }


def generate_key() -> bytes:
    """Generate a fresh Fernet key. Store securely."""
    return Fernet.generate_key()


def save_key(key: bytes, key_path: str | Path) -> Path:
    """Write a Fernet key to disk. Creates parent directories."""
    path = Path(key_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key)
    return path


def load_key(key_path: str | Path) -> bytes:
    """Read a Fernet key from disk."""
    return Path(key_path).read_bytes()


def encrypt_file(source: str | Path, destination: str | Path, key: bytes) -> Path:
    """
    Encrypt a single file to destination.

    The destination is written with the encrypted bytes. The original file
    is not modified.
    """
    src = Path(source)
    dst = Path(destination)

    if not src.exists():
        raise FileNotFoundError(f"Source file not found: {src}")

    dst.parent.mkdir(parents=True, exist_ok=True)

    fernet = Fernet(key)
    plaintext = src.read_bytes()
    ciphertext = fernet.encrypt(plaintext)
    dst.write_bytes(ciphertext)

    return dst


def decrypt_file(source: str | Path, destination: str | Path, key: bytes) -> Path:
    """
    Decrypt an encrypted file.

    Raises InvalidToken if the ciphertext was tampered with or the key is
    wrong — this is the authentication guarantee Fernet provides.
    """
    src = Path(source)
    dst = Path(destination)

    if not src.exists():
        raise FileNotFoundError(f"Encrypted file not found: {src}")

    dst.parent.mkdir(parents=True, exist_ok=True)

    fernet = Fernet(key)
    ciphertext = src.read_bytes()
    plaintext = fernet.decrypt(ciphertext)
    dst.write_bytes(plaintext)

    return dst


def is_encrypted(path: str | Path) -> bool:
    """Check whether a path has the encrypted suffix."""
    return Path(path).name.endswith(ENCRYPTED_SUFFIX)


def encrypt_backup_dir(
    source_dir: str | Path,
    destination_dir: str | Path,
    key: bytes,
) -> EncryptionResult:
    """
    Recursively encrypt every file under source_dir into destination_dir.

    Directory structure is preserved. Files get a .enc suffix.
    """
    src = Path(source_dir)
    dst = Path(destination_dir)
    attempted_at = datetime.now(timezone.utc).isoformat()
    errors: list[str] = []
    encrypted_count = 0

    if not src.exists() or not src.is_dir():
        return EncryptionResult(
            source_path=str(src),
            destination_path=str(dst),
            file_count=0,
            success=False,
            attempted_at=attempted_at,
            errors=["Source directory does not exist or is not a directory."],
        )

    dst.mkdir(parents=True, exist_ok=True)

    for item in src.rglob("*"):
        if not item.is_file():
            continue
        relative = item.relative_to(src)
        target = dst / (str(relative) + ENCRYPTED_SUFFIX)

        try:
            encrypt_file(item, target, key)
            encrypted_count += 1
        except Exception as error:
            logger.error("Failed to encrypt %s: %s", item, error)
            errors.append(f"{item}: {error}")

    return EncryptionResult(
        source_path=str(src),
        destination_path=str(dst),
        file_count=encrypted_count,
        success=len(errors) == 0,
        attempted_at=attempted_at,
        errors=errors,
    )


def decrypt_backup_dir(
    source_dir: str | Path,
    destination_dir: str | Path,
    key: bytes,
) -> EncryptionResult:
    """
    Recursively decrypt every .enc file under source_dir into destination_dir.

    The .enc suffix is stripped from decrypted files.
    """
    src = Path(source_dir)
    dst = Path(destination_dir)
    attempted_at = datetime.now(timezone.utc).isoformat()
    errors: list[str] = []
    decrypted_count = 0

    if not src.exists() or not src.is_dir():
        return EncryptionResult(
            source_path=str(src),
            destination_path=str(dst),
            file_count=0,
            success=False,
            attempted_at=attempted_at,
            errors=["Source directory does not exist or is not a directory."],
        )

    dst.mkdir(parents=True, exist_ok=True)

    for item in src.rglob("*"):
        if not item.is_file() or not is_encrypted(item):
            continue

        relative = item.relative_to(src)
        stripped = Path(str(relative)[: -len(ENCRYPTED_SUFFIX)])
        target = dst / stripped

        try:
            decrypt_file(item, target, key)
            decrypted_count += 1
        except InvalidToken:
            errors.append(f"{item}: authentication failed (wrong key or tampered).")
        except Exception as error:
            logger.error("Failed to decrypt %s: %s", item, error)
            errors.append(f"{item}: {error}")

    return EncryptionResult(
        source_path=str(src),
        destination_path=str(dst),
        file_count=decrypted_count,
        success=len(errors) == 0,
        attempted_at=attempted_at,
        errors=errors,
    )