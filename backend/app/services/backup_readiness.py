from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Backup, IntegrityVerification


@dataclass(frozen=True)
class RecoveryEligibility:
    eligible: bool
    backup_id: str
    reasons: list[str]
    verified: bool


def latest_completed_verification(db: Session, backup_id: str) -> IntegrityVerification | None:
    """Return the newest terminal result for this exact backup, not a sibling backup."""
    terminal_statuses = ("passed", "failed", "inconclusive", "cancelled", "error")
    return db.scalar(
        select(IntegrityVerification)
        .where(
            IntegrityVerification.backup_id == backup_id,
            IntegrityVerification.result_status.in_(terminal_statuses),
        )
        .order_by(IntegrityVerification.completed_at.desc(), IntegrityVerification.created_at.desc())
        .limit(1)
    )


def is_backup_verified(db: Session, backup_id: str) -> bool:
    """Whether the latest completed verification for this exact backup passed."""
    verification = latest_completed_verification(db, backup_id)
    return verification is not None and verification.result_status == "passed"


def assess_recovery_eligibility(db: Session, backup: Backup) -> RecoveryEligibility:
    reasons: list[str] = []
    if backup.lifecycle_status != "available":
        reasons.append(f"backup_{backup.lifecycle_status}")
    verification = latest_completed_verification(db, backup.id)
    verified = verification is not None and verification.result_status == "passed"
    if verification is None:
        reasons.append("verification_missing")
    elif verification.result_status != "passed":
        reasons.append(f"verification_{verification.result_status}")
    return RecoveryEligibility(
        eligible=not reasons,
        backup_id=backup.id,
        reasons=reasons,
        verified=verified,
    )