from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.common import as_utc, get_or_404, paginate
from app.database.session import get_db
from app.enums import ActionExecutionStatus, ActionType, ApprovalStatus
from app.models import ActionRequest
from app.schemas import ActionRequestRead, Page

router = APIRouter(prefix="/api/action-requests", tags=["action-requests"])


@router.get("", response_model=Page[ActionRequestRead])
def list_action_requests(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    asset_id: UUID | None = None,
    incident_id: UUID | None = None,
    action_type: ActionType | None = None,
    approval_status: ApprovalStatus | None = None,
    execution_status: ActionExecutionStatus | None = None,
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(ActionRequest)
    if asset_id:
        query = query.filter(ActionRequest.asset_id == str(asset_id))
    if incident_id:
        query = query.filter(ActionRequest.incident_id == str(incident_id))
    if action_type:
        query = query.filter(ActionRequest.action_type == action_type.value)
    if approval_status:
        query = query.filter(ActionRequest.approval_status == approval_status.value)
    if execution_status:
        query = query.filter(ActionRequest.execution_status == execution_status.value)
    if from_:
        query = query.filter(ActionRequest.created_at >= as_utc(from_))
    if to:
        query = query.filter(ActionRequest.created_at <= as_utc(to))
    return paginate(query.order_by(ActionRequest.created_at.desc()), page, page_size)


@router.get("/{action_request_id}", response_model=ActionRequestRead)
def get_action_request(action_request_id: UUID, db: Session = Depends(get_db)):
    return get_or_404(db, ActionRequest, str(action_request_id), "Action request")