from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.common import as_utc, get_or_404, paginate
from app.database.session import get_db
from app.enums import DecisionStatus
from app.models import Decision
from app.schemas import DecisionRead, Page

router = APIRouter(prefix="/api/decisions", tags=["decisions"])


@router.get("", response_model=Page[DecisionRead])
def list_decisions(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    asset_id: UUID | None = None,
    incident_id: UUID | None = None,
    assessment_id: UUID | None = None,
    status: DecisionStatus | None = None,
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(Decision)
    if asset_id:
        query = query.filter(Decision.asset_id == str(asset_id))
    if incident_id:
        query = query.filter(Decision.incident_id == str(incident_id))
    if assessment_id:
        query = query.filter(Decision.assessment_id == str(assessment_id))
    if status:
        query = query.filter(Decision.decision_status == status.value)
    if from_:
        query = query.filter(Decision.created_at >= as_utc(from_))
    if to:
        query = query.filter(Decision.created_at <= as_utc(to))
    return paginate(query.order_by(Decision.created_at.desc()), page, page_size)


@router.get("/{decision_id}", response_model=DecisionRead)
def get_decision(decision_id: UUID, db: Session = Depends(get_db)):
    return get_or_404(db, Decision, str(decision_id), "Decision")