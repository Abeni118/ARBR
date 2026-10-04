from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.common import as_utc, get_or_404, paginate
from app.database.session import get_db
from app.enums import IncidentLifecycleStatus
from app.models import ThreatIncident
from app.schemas import Page, ThreatIncidentRead

router = APIRouter(prefix="/api/threats", tags=["threats"])


@router.get("", response_model=Page[ThreatIncidentRead])
def list_threats(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    asset_id: UUID | None = None,
    status: IncidentLifecycleStatus | None = None,
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(ThreatIncident)
    if asset_id:
        query = query.filter(ThreatIncident.asset_id == str(asset_id))
    if status:
        query = query.filter(ThreatIncident.lifecycle_status == status.value)
    if from_:
        query = query.filter(ThreatIncident.detected_at >= as_utc(from_))
    if to:
        query = query.filter(ThreatIncident.detected_at <= as_utc(to))
    return paginate(query.order_by(ThreatIncident.detected_at.desc()), page, page_size)


@router.get("/{incident_id}", response_model=ThreatIncidentRead)
def get_threat(incident_id: UUID, db: Session = Depends(get_db)):
    return get_or_404(db, ThreatIncident, str(incident_id), "Threat incident")