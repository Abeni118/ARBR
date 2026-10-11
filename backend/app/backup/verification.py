"""
Backup verification workflow.

Higher-level layer on top of integrity.py:

  - Records a trusted hash for a recovery point ("trust on first hash").
  - Verifies a recovery point against its recorded trusted hash.
  - Updates a RecoveryPoint's integrity_status based on the result.

Trusted hashes are stored as sidecar files: ``<storage_dir>/<backup_id>.sha256``.
"""

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
import logging

from .integrity import calculate_directory_sha256
from .recovery_point import RecoveryPoint


logger = logging.getLogger(__name__)

SIDECAR_SUFFIX = ".sha256"

# Status constants (kept as strings so they map directly into API responses).
STATUS_VERIFIED = "VERIFIED"
STATUS_TAMPERED = "TAMPERED"
STATUS_MISSING = "MISSING"
STATUS_UNVERIFIED = "UNVERIFIED"
STATUS_ERROR = "ERROR"


@dataclass
class VerificationResult:
    backup_id: str
    destination_path: str
    expected_hash: str | None
    actual_hash: str | None
    is_intact: bool
    status: str
    checked_at: str
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "backup_id": self.backup_id,
            "destination_path": self.destination_path,
            "expected_hash": self.expected_hash,
            "actual_hash": self.actual_hash,
            "is_intact": self.is_intact,
            "status": self.status,
            "checked_at": self.checked_at,
            "error": self.error,
        }


def _sidecar_path(storage_dir: str | Path, backup_id: str) -> Path:
    return Path(storage_dir) / f"{backup_id}{SIDECAR_SUFFIX}"


def write_trusted_hash(
    destination_path: str | Path,
    backup_id: str,
    storage_dir: str | Path,
) -> Path:
    """
    Hash a recovery point's directory and record its trusted hash.

    Returns the path to the sidecar file that was written.
    """
    digest = calculate_directory_sha256(destination_path)

    sidecar = _sidecar_path(storage_dir, backup_id)
    sidecar.parent.mkdir(parents=True, exist_ok=True)
    sidecar.write_text(digest, encoding="utf-8")

    logger.info("Recorded trusted hash for %s at %s", backup_id, sidecar)
    return sidecar


def read_trusted_hash(
    backup_id: str,
    storage_dir: str | Path,
) -> str | None:
    """
    Read a recorded trusted hash for a backup.

    Returns None if no sidecar exists (backup was never trusted).
    """
    sidecar = _sidecar_path(storage_dir, backup_id)

    if not sidecar.exists():
        return None

    content = sidecar.read_text(encoding="utf-8").strip()
    return content or None


def verify_recovery_point(
    recovery_point: RecoveryPoint,
    storage_dir: str | Path,
) -> VerificationResult:
    """
    Verify a recovery point against its recorded trusted hash.

    Never raises: any failure is returned as a VerificationResult with a
    non-VERIFIED status so callers can report it uniformly.
    """
    backup_id = recovery_point.backup_id
    destination = recovery_point.destination_path
    checked_at = datetime.now(timezone.utc).isoformat()

    expected = read_trusted_hash(backup_id, storage_dir)

    if expected is None:
        logger.warning("No trusted hash recorded for backup %s", backup_id)
        return VerificationResult(
            backup_id=backup_id,
            destination_path=destination,
            expected_hash=None,
            actual_hash=None,
            is_intact=False,
            status=STATUS_UNVERIFIED,
            checked_at=checked_at,
            error="No trusted hash recorded for this backup.",
        )

    try:
        actual = calculate_directory_sha256(destination)
    except FileNotFoundError:
        logger.warning("Backup directory missing for %s", backup_id)
        return VerificationResult(
            backup_id=backup_id,
            destination_path=destination,
            expected_hash=expected,
            actual_hash=None,
            is_intact=False,
            status=STATUS_MISSING,
            checked_at=checked_at,
            error="Backup directory not found.",
        )
    except OSError as error:
        logger.error("Could not hash backup %s: %s", backup_id, error)
        return VerificationResult(
            backup_id=backup_id,
            destination_path=destination,
            expected_hash=expected,
            actual_hash=None,
            is_intact=False,
            status=STATUS_ERROR,
            checked_at=checked_at,
            error=str(error),
        )

    is_intact = actual == expected

    if is_intact:
        logger.info("Backup %s VERIFIED", backup_id)
        status = STATUS_VERIFIED
        error_message = None
    else:
        logger.warning(
            "Backup %s TAMPERED: expected %s, got %s",
            backup_id,
            expected,
            actual,
        )
        status = STATUS_TAMPERED
        error_message = "Content hash does not match the trusted hash."

    return VerificationResult(
        backup_id=backup_id,
        destination_path=destination,
        expected_hash=expected,
        actual_hash=actual,
        is_intact=is_intact,
        status=status,
        checked_at=checked_at,
        error=error_message,
    )


def apply_result_to_recovery_point(
    result: VerificationResult,
    recovery_point: RecoveryPoint,
) -> RecoveryPoint:
    """
    Return a copy of the recovery point with its integrity_status updated.

    Does NOT mutate the original object (functional style).
    """
    return replace(recovery_point, integrity_status=result.status)