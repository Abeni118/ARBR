from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models import RiskAssessment, SecurityEvent, ThreatIncident
from app.schemas import DashboardSummary, SecurityEventRead

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummary)
def dashboard_summary(db: Session = Depends(get_db)):
    terminal_statuses = ("resolved", "false_positive", "closed")
    active_threats = (
        db.query(func.count(ThreatIncident.id))
        .filter(ThreatIncident.lifecycle_status.notin_(terminal_statuses))
        .scalar()
        or 0
    )
    current_risks = (
        db.query(RiskAssessment.risk_level, func.count(RiskAssessment.id))
        .join(ThreatIncident, ThreatIncident.current_risk_assessment_id == RiskAssessment.id)
        .group_by(RiskAssessment.risk_level)
        .all()
    )
    distribution = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for level, count in current_risks:
        distribution[level] = count

    recent_events = (
        db.query(SecurityEvent)
        .order_by(SecurityEvent.received_at.desc())
        .limit(10)
        .all()
    )
    return DashboardSummary(
        total_security_events=db.query(func.count(SecurityEvent.id)).scalar() or 0,
        active_threats=active_threats,
        high_risk_incidents=distribution["HIGH"],
        critical_risk_incidents=distribution["CRITICAL"],
        risk_distribution=distribution,
        recent_events=[SecurityEventRead.model_validate(item) for item in recent_events],
    )