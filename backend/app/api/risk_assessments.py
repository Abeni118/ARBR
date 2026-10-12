from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.common import as_utc, get_or_404, paginate
from app.database.session import get_db
from app.enums import RiskAssessmentStatus, RiskLevel
from app.models import Asset, RiskAssessment, ThreatIncident
from app.risk import risk_level_for_score
from app.schemas import Page, RiskAssessmentCreate, RiskAssessmentRead
from app.services.audit import record_phase2_audit
from app.services.internal_auth import ComponentPrincipal, ComponentScope, require_component_scope
from app.services.user_auth import get_current_user

router = APIRouter(prefix="/api/risk-assessments", tags=["risk-assessments"], dependencies=[Depends(get_current_user)])
risk_assessment_component = require_component_scope(ComponentScope.RISK_ASSESSMENTS_WRITE)
internal_router = APIRouter(
    prefix="/api/internal/risk-assessments",
    tags=["internal-risk-assessments"],
    dependencies=[Depends(risk_assessment_component)],
)


def _reject_assessment(db: Session, payload: RiskAssessmentCreate, detail: str, code: int):
    record_phase2_audit(
        db,
        action="risk_assessment.create",
        result_status="rejected",
        resource_type="risk_assessment",
        correlation_id=payload.correlation_id or uuid4(),
        reason=detail,
    )
    db.commit()
    raise HTTPException(status_code=code, detail=detail)


@internal_router.post("", response_model=RiskAssessmentRead, status_code=status.HTTP_201_CREATED)
def create_risk_assessment(
    payload: RiskAssessmentCreate,
    db: Session = Depends(get_db),
    component: ComponentPrincipal = Depends(risk_assessment_component),
):
    incident = db.get(ThreatIncident, str(payload.incident_id))
    if incident is None:
        _reject_assessment(db, payload, "Threat incident not found", status.HTTP_404_NOT_FOUND)
    asset = db.get(Asset, str(payload.asset_id))
    if asset is None:
        _reject_assessment(db, payload, "Asset not found", status.HTTP_404_NOT_FOUND)
    related_asset_ids = {incident.asset_id, *(item.id for item in incident.affected_assets)}
    if asset.id not in related_asset_ids:
        _reject_assessment(db, payload, "Asset is not affected by the referenced incident", status.HTTP_409_CONFLICT)

    correlation_id = payload.correlation_id or UUID(incident.correlation_id)
    assessment = RiskAssessment(
        incident_id=incident.id,
        asset_id=asset.id,
        score=payload.score,
        risk_level=risk_level_for_score(payload.score).value,
        factors=payload.factors,
        confidence=payload.confidence,
        model_version=payload.model_version,
        policy_version=payload.policy_version,
        assessed_at=as_utc(payload.assessed_at) if payload.assessed_at else datetime.now(timezone.utc),
        correlation_id=str(correlation_id),
    )
    db.add(assessment)
    db.flush()
    incident.current_risk_assessment_id = assessment.id
    record_phase2_audit(
        db,
        action="risk_assessment.create",
        result_status="success",
        resource_type="risk_assessment",
        resource_id=assessment.id,
        incident_id=incident.id,
        asset_id=asset.id,
        assessment_id=assessment.id,
        correlation_id=correlation_id,
        actor_id=component.component_id,
        source_component=component.component_id,
        safe_metadata={"score": assessment.score, "risk_level": assessment.risk_level},
    )
    db.commit()
    db.refresh(assessment)
    return assessment


@router.get("", response_model=Page[RiskAssessmentRead])
def list_risk_assessments(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    asset_id: UUID | None = None,
    incident_id: UUID | None = None,
    status: RiskAssessmentStatus | None = None,
    risk_level: RiskLevel | None = None,
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(RiskAssessment)
    if asset_id:
        query = query.filter(RiskAssessment.asset_id == str(asset_id))
    if incident_id:
        query = query.filter(RiskAssessment.incident_id == str(incident_id))
    if status:
        query = query.filter(RiskAssessment.status == status.value)
    if risk_level:
        query = query.filter(RiskAssessment.risk_level == risk_level.value)
    if from_:
        query = query.filter(RiskAssessment.assessed_at >= as_utc(from_))
    if to:
        query = query.filter(RiskAssessment.assessed_at <= as_utc(to))
    return paginate(query.order_by(RiskAssessment.assessed_at.desc()), page, page_size)


@router.get("/{assessment_id}", response_model=RiskAssessmentRead)
def get_risk_assessment(assessment_id: UUID, db: Session = Depends(get_db)):
    return get_or_404(db, RiskAssessment, str(assessment_id), "Risk assessment")
