from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.common import as_utc, get_or_404, paginate
from app.database.session import get_db
from app.models import AuditEvent
from app.schemas import AuditEventRead, Page

router = APIRouter(prefix="/api/audit-logs", tags=["audit-logs"])


@router.get("", response_model=Page[AuditEventRead])
def list_audit_events(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    actor_type: str | None = None,
    action: str | None = None,
    result_status: str | None = None,
    asset_id: UUID | None = None,
    incident_id: UUID | None = None,
    correlation_id: UUID | None = None,
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(AuditEvent)
    if actor_type:
        query = query.filter(AuditEvent.actor_type == actor_type)
    if action:
        query = query.filter(AuditEvent.action.ilike(f"%{action}%"))
    if result_status:
        query = query.filter(AuditEvent.result_status == result_status)
    if asset_id:
        query = query.filter(AuditEvent.asset_id == str(asset_id))
    if incident_id:
        query = query.filter(AuditEvent.incident_id == str(incident_id))
    if correlation_id:
        query = query.filter(AuditEvent.correlation_id == str(correlation_id))
    if from_:
        query = query.filter(AuditEvent.occurred_at >= as_utc(from_))
    if to:
        query = query.filter(AuditEvent.occurred_at <= as_utc(to))
    return paginate(query.order_by(AuditEvent.occurred_at.desc()), page, page_size)


@router.get("/{audit_event_id}", response_model=AuditEventRead)
def get_audit_event(audit_event_id: UUID, db: Session = Depends(get_db)):
    return get_or_404(db, AuditEvent, str(audit_event_id), "Audit event")