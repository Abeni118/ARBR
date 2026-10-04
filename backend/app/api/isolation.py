from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.common import as_utc, get_or_404, paginate
from app.database.session import get_db
from app.enums import IsolationExecutionStatus
from app.models import IsolationAction
from app.schemas import IsolationActionRead, Page

router = APIRouter(prefix="/api/isolation", tags=["isolation"])


@router.get("", response_model=Page[IsolationActionRead])
def list_isolation_actions(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    asset_id: UUID | None = None,
    incident_id: UUID | None = None,
    status: IsolationExecutionStatus | None = None,
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(IsolationAction)
    if asset_id:
        query = query.filter(IsolationAction.asset_id == str(asset_id))
    if incident_id:
        query = query.filter(IsolationAction.incident_id == str(incident_id))
    if status:
        query = query.filter(IsolationAction.execution_status == status.value)
    if from_:
        query = query.filter(IsolationAction.requested_at >= as_utc(from_))
    if to:
        query = query.filter(IsolationAction.requested_at <= as_utc(to))
    return paginate(query.order_by(IsolationAction.requested_at.desc()), page, page_size)


@router.get("/{isolation_action_id}", response_model=IsolationActionRead)
def get_isolation_action(isolation_action_id: UUID, db: Session = Depends(get_db)):
    return get_or_404(db, IsolationAction, str(isolation_action_id), "Isolation action")