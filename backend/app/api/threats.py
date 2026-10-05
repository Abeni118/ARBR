from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.common import as_utc, get_or_404, paginate
from app.database.session import get_db
from app.enums import IncidentLifecycleStatus
from app.models import Asset, SecurityEvent, ThreatIncident
from app.schemas import Page, ThreatIncidentCreate, ThreatIncidentRead
from app.services.asset_resolution import resolve_asset
from app.services.audit import record_phase2_audit

router = APIRouter(prefix="/api/threats", tags=["threats"])
internal_router = APIRouter(prefix="/api/internal/threats", tags=["internal-threats"])


def _reject_create(db: Session, payload: ThreatIncidentCreate, detail: str, code: int):
    record_phase2_audit(
        db,
        action="threat_incident.create",
        result_status="rejected",
        resource_type="threat_incident",
        correlation_id=payload.correlation_id or uuid4(),
        reason=detail,
    )
    db.commit()
    raise HTTPException(status_code=code, detail=detail)


@internal_router.post("", response_model=ThreatIncidentRead, status_code=status.HTTP_201_CREATED)
def create_threat(payload: ThreatIncidentCreate, db: Session = Depends(get_db)):
    resolved_assets: dict[str, Asset] = {}
    try:
        if payload.asset_id:
            asset = resolve_asset(db, payload.asset_id)
            resolved_assets[asset.id] = asset
        for asset_id in payload.asset_ids:
            asset = resolve_asset(db, asset_id)
            resolved_assets[asset.id] = asset
        for external_ref in payload.asset_external_refs:
            asset = resolve_asset(db, external_ref=external_ref)
            resolved_assets[asset.id] = asset
    except HTTPException as exc:
        _reject_create(db, payload, exc.detail, exc.status_code)

    event_ids = {str(event_id) for event_id in payload.event_ids}
    events = db.query(SecurityEvent).filter(SecurityEvent.id.in_(event_ids)).all() if event_ids else []
    if len(events) != len(event_ids):
        _reject_create(db, payload, "One or more security events were not found", status.HTTP_404_NOT_FOUND)

    affected_asset_ids = set(resolved_assets)
    for event in events:
        if event.incident_id is not None:
            _reject_create(db, payload, "A referenced security event is already linked to another incident", 409)
        if event.asset_id is not None and event.asset_id not in affected_asset_ids:
            _reject_create(db, payload, "Referenced event asset is not included among incident assets", 409)

    primary_asset = resolved_assets.get(str(payload.asset_id)) if payload.asset_id else next(iter(resolved_assets.values()))
    event_correlation_ids = {event.correlation_id for event in events}
    correlation_id = payload.correlation_id
    if correlation_id is None:
        correlation_id = UUID(next(iter(event_correlation_ids))) if len(event_correlation_ids) == 1 else uuid4()

    incident = ThreatIncident(
        title=payload.title,
        threat_type=payload.threat_type,
        asset_id=primary_asset.id,
        description=payload.description,
        indicators=payload.indicators,
        detection_source=payload.detection_source,
        detected_at=as_utc(payload.detected_at),
        lifecycle_status="new",
        correlation_id=str(correlation_id),
        affected_assets=[item for item in resolved_assets.values() if item.id != primary_asset.id],
    )
    db.add(incident)
    db.flush()
    for event in events:
        event.incident_id = incident.id
    record_phase2_audit(
        db,
        action="threat_incident.create",
        result_status="success",
        resource_type="threat_incident",
        resource_id=incident.id,
        incident_id=incident.id,
        asset_id=primary_asset.id,
        correlation_id=correlation_id,
        actor_id=payload.detection_source,
        source_component=payload.detection_source,
        safe_metadata={"event_count": len(events), "affected_asset_count": len(resolved_assets)},
    )
    db.commit()
    db.refresh(incident)
    return incident


def _apply_transition(incident_id: UUID, *, allowed_from: set[str], target: str, db: Session) -> ThreatIncident:
    incident = get_or_404(db, ThreatIncident, str(incident_id), "Threat incident")
    previous = incident.lifecycle_status
    if previous not in allowed_from:
        record_phase2_audit(
            db,
            action="threat_incident.lifecycle_change",
            result_status="rejected",
            resource_type="threat_incident",
            resource_id=incident.id,
            incident_id=incident.id,
            asset_id=incident.asset_id,
            correlation_id=incident.correlation_id,
            reason=f"Transition from {previous} to {target} is not allowed",
            safe_metadata={"from": previous, "to": target},
        )
        db.commit()
        raise HTTPException(status_code=409, detail=f"Cannot transition incident from {previous} to {target}")

    # Containment and recovery states have no operation in this phase because
    # those actions cannot be confirmed yet.
    incident.lifecycle_status = target
    if target in {"resolved", "false_positive"}:
        incident.resolved_at = datetime.now(timezone.utc)
    record_phase2_audit(
        db,
        action="threat_incident.lifecycle_change",
        result_status="success",
        resource_type="threat_incident",
        resource_id=incident.id,
        incident_id=incident.id,
        asset_id=incident.asset_id,
        correlation_id=incident.correlation_id,
        safe_metadata={"from": previous, "to": target},
    )
    db.commit()
    db.refresh(incident)
    return incident


@router.post("/{incident_id}/triage", response_model=ThreatIncidentRead)
def triage_threat(incident_id: UUID, db: Session = Depends(get_db)):
    return _apply_transition(incident_id, allowed_from={"new"}, target="triaged", db=db)


@router.post("/{incident_id}/investigate", response_model=ThreatIncidentRead)
def investigate_threat(incident_id: UUID, db: Session = Depends(get_db)):
    return _apply_transition(incident_id, allowed_from={"triaged"}, target="investigating", db=db)


@router.post("/{incident_id}/resolve", response_model=ThreatIncidentRead)
def resolve_threat(incident_id: UUID, db: Session = Depends(get_db)):
    return _apply_transition(incident_id, allowed_from={"recovered"}, target="resolved", db=db)


@router.post("/{incident_id}/false-positive", response_model=ThreatIncidentRead)
def mark_false_positive(incident_id: UUID, db: Session = Depends(get_db)):
    return _apply_transition(
        incident_id,
        allowed_from={"new", "triaged", "investigating"},
        target="false_positive",
        db=db,
    )


@router.get("", response_model=Page[ThreatIncidentRead])
def list_threats(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    asset_id: UUID | None = None,
    lifecycle_status: IncidentLifecycleStatus | None = None,
    threat_type: str | None = None,
    detection_source: str | None = None,
    status: IncidentLifecycleStatus | None = None,
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(ThreatIncident)
    if asset_id:
        query = query.filter(
            (ThreatIncident.asset_id == str(asset_id))
            | ThreatIncident.affected_assets.any(Asset.id == str(asset_id))
        )
    selected_status = lifecycle_status or status
    if selected_status:
        query = query.filter(ThreatIncident.lifecycle_status == selected_status.value)
    if threat_type:
        query = query.filter(ThreatIncident.threat_type == threat_type)
    if detection_source:
        query = query.filter(ThreatIncident.detection_source == detection_source)
    if from_:
        query = query.filter(ThreatIncident.detected_at >= as_utc(from_))
    if to:
        query = query.filter(ThreatIncident.detected_at <= as_utc(to))
    return paginate(query.order_by(ThreatIncident.detected_at.desc()), page, page_size)


@router.get("/{incident_id}", response_model=ThreatIncidentRead)
def get_threat(incident_id: UUID, db: Session = Depends(get_db)):
    return get_or_404(db, ThreatIncident, str(incident_id), "Threat incident")
