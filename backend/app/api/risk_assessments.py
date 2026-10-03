from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.common import get_or_404, paginate
from app.database.session import get_db
from app.enums import RiskAssessmentStatus, RiskLevel
from app.models import RiskAssessment
from app.schemas import Page, RiskAssessmentRead

router = APIRouter(prefix="/api/risk-assessments", tags=["risk-assessments"])


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
        query = query.filter(RiskAssessment.assessed_at >= from_)
    if to:
        query = query.filter(RiskAssessment.assessed_at <= to)
    return paginate(query.order_by(RiskAssessment.assessed_at.desc()), page, page_size)


@router.get("/{assessment_id}", response_model=RiskAssessmentRead)
def get_risk_assessment(assessment_id: UUID, db: Session = Depends(get_db)):
    return get_or_404(db, RiskAssessment, str(assessment_id), "Risk assessment")