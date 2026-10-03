from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.common import get_or_404, paginate
from app.database.session import get_db
from app.enums import EventProcessingStatus, EventSeverity
from app.models import SecurityEvent
from app.schemas import Page, SecurityEventRead

router = APIRouter(prefix="/api/security-events", tags=["security-events"])


@router.get("", response_model=Page[SecurityEventRead])
def list_security_events(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    asset_id: UUID | None = None,
    incident_id: UUID | None = None,
    status: EventProcessingStatus | None = None,
    severity: EventSeverity | None = None,
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(SecurityEvent)
    if asset_id:
        query = query.filter(SecurityEvent.asset_id == str(asset_id))
    if incident_id:
        query = query.filter(SecurityEvent.incident_id == str(incident_id))
    if status:
        query = query.filter(SecurityEvent.processing_status == status.value)
    if severity:
        query = query.filter(SecurityEvent.event_severity == severity.value)
    if from_:
        query = query.filter(SecurityEvent.occurred_at >= from_)
    if to:
        query = query.filter(SecurityEvent.occurred_at <= to)
    return paginate(query.order_by(SecurityEvent.occurred_at.desc()), page, page_size)


@router.get("/{event_id}", response_model=SecurityEventRead)
def get_security_event(event_id: UUID, db: Session = Depends(get_db)):
    return get_or_404(db, SecurityEvent, str(event_id), "Security event")