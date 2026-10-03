from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.common import get_or_404, paginate
from app.database.session import get_db
from app.enums import VerificationStatus
from app.models import IntegrityVerification
from app.schemas import IntegrityVerificationRead, Page

router = APIRouter(prefix="/api/integrity-verifications", tags=["integrity-verifications"])


@router.get("", response_model=Page[IntegrityVerificationRead])
def list_integrity_verifications(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    backup_id: UUID | None = None,
    status: VerificationStatus | None = None,
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(IntegrityVerification)
    if backup_id:
        query = query.filter(IntegrityVerification.backup_id == str(backup_id))
    if status:
        query = query.filter(IntegrityVerification.result_status == status.value)
    if from_:
        query = query.filter(IntegrityVerification.started_at >= from_)
    if to:
        query = query.filter(IntegrityVerification.started_at <= to)
    return paginate(query.order_by(IntegrityVerification.started_at.desc()), page, page_size)


@router.get("/{verification_id}", response_model=IntegrityVerificationRead)
def get_integrity_verification(verification_id: UUID, db: Session = Depends(get_db)):
    return get_or_404(db, IntegrityVerification, str(verification_id), "Integrity verification")