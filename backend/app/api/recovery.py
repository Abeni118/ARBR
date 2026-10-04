from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.common import as_utc, get_or_404, paginate
from app.database.session import get_db
from app.enums import RecoveryJobStatus
from app.models import RecoveryJob
from app.schemas import Page, RecoveryJobRead

router = APIRouter(prefix="/api/recovery-jobs", tags=["recovery"])


@router.get("", response_model=Page[RecoveryJobRead])
def list_recovery_jobs(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    asset_id: UUID | None = None,
    incident_id: UUID | None = None,
    status: RecoveryJobStatus | None = None,
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(RecoveryJob)
    if asset_id:
        query = query.filter(RecoveryJob.asset_id == str(asset_id))
    if incident_id:
        query = query.filter(RecoveryJob.incident_id == str(incident_id))
    if status:
        query = query.filter(RecoveryJob.job_status == status.value)
    if from_:
        query = query.filter(RecoveryJob.started_at >= as_utc(from_))
    if to:
        query = query.filter(RecoveryJob.started_at <= as_utc(to))
    return paginate(query.order_by(RecoveryJob.started_at.desc()), page, page_size)


@router.get("/{recovery_job_id}", response_model=RecoveryJobRead)
def get_recovery_job(recovery_job_id: UUID, db: Session = Depends(get_db)):
    return get_or_404(db, RecoveryJob, str(recovery_job_id), "Recovery job")