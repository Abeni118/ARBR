from datetime import datetime
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.common import as_utc, get_or_404, paginate
from app.database.session import get_db
from app.enums import DecisionStatus
from app.models import Asset, Decision, RiskAssessment, ThreatIncident
from app.schemas import DecisionCreate, DecisionRead, Page
from app.services.audit import record_phase2_audit

router = APIRouter(prefix="/api/decisions", tags=["decisions"])
internal_router = APIRouter(prefix="/api/internal/decisions", tags=["internal-decisions"])


def _reject_decision(db: Session, payload: DecisionCreate, detail: str, code: int):
    record_phase2_audit(
        db,
        action="decision.create",
        result_status="rejected",
        resource_type="decision",
        correlation_id=payload.correlation_id or uuid4(),
        reason=detail,
    )
    db.commit()
    raise HTTPException(status_code=code, detail=detail)


@internal_router.post("", response_model=DecisionRead, status_code=status.HTTP_201_CREATED)
def create_decision(payload: DecisionCreate, db: Session = Depends(get_db)):
    incident = db.get(ThreatIncident, str(payload.incident_id))
    if incident is None:
        _reject_decision(db, payload, "Threat incident not found", status.HTTP_404_NOT_FOUND)
    assessment = db.get(RiskAssessment, str(payload.assessment_id))
    if assessment is None:
        _reject_decision(db, payload, "Risk assessment not found", status.HTTP_404_NOT_FOUND)
    asset = db.get(Asset, str(payload.asset_id))
    if asset is None:
        _reject_decision(db, payload, "Asset not found", status.HTTP_404_NOT_FOUND)
    if assessment.incident_id != incident.id:
        _reject_decision(db, payload, "Risk assessment does not belong to the referenced incident", status.HTTP_409_CONFLICT)
    related_asset_ids = {incident.asset_id, *(item.id for item in incident.affected_assets)}
    if assessment.asset_id != asset.id or asset.id not in related_asset_ids:
        _reject_decision(
            db,
            payload,
            "Decision asset must match the assessment and be affected by the incident",
            status.HTTP_409_CONFLICT,
        )

    correlation_id = payload.correlation_id or UUID(assessment.correlation_id)
    decision = Decision(
        incident_id=incident.id,
        assessment_id=assessment.id,
        asset_id=asset.id,
        recommended_actions=list(payload.recommended_actions),
        rationale=payload.rationale,
        approval_required=payload.approval_required,
        decision_status="proposed",
        policy_version=payload.policy_version,
        engine_version=payload.decision_engine_version,
        correlation_id=str(correlation_id),
    )
    db.add(decision)
    db.flush()
    record_phase2_audit(
        db,
        action="decision.create",
        result_status="success",
        resource_type="decision",
        resource_id=decision.id,
        incident_id=incident.id,
        assessment_id=assessment.id,
        decision_id=decision.id,
        asset_id=asset.id,
        correlation_id=correlation_id,
        actor_id=payload.decision_engine_version,
        source_component="decision_engine",
        safe_metadata={"recommended_action_count": len(decision.recommended_actions)},
    )
    db.commit()
    db.refresh(decision)
    return decision


@router.get("", response_model=Page[DecisionRead])
def list_decisions(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    asset_id: UUID | None = None,
    incident_id: UUID | None = None,
    assessment_id: UUID | None = None,
    decision_status: DecisionStatus | None = None,
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
    selected_status = decision_status or status
    if selected_status:
        query = query.filter(Decision.decision_status == selected_status.value)
    if from_:
        query = query.filter(Decision.created_at >= as_utc(from_))
    if to:
        query = query.filter(Decision.created_at <= as_utc(to))
    return paginate(query.order_by(Decision.created_at.desc()), page, page_size)


@router.get("/{decision_id}", response_model=DecisionRead)
def get_decision(decision_id: UUID, db: Session = Depends(get_db)):
    return get_or_404(db, Decision, str(decision_id), "Decision")
