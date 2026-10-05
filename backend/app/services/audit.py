from uuid import uuid4

from sqlalchemy.orm import Session

from app.models import AuditEvent
from app.schemas import AuditEventCreate


UUID_FIELDS = (
    "resource_id",
    "asset_id",
    "incident_id",
    "event_id",
    "assessment_id",
    "decision_id",
    "action_request_id",
    "backup_id",
    "verification_id",
    "recovery_job_id",
    "correlation_id",
)


def record_audit_event(db: Session, event_data: AuditEventCreate) -> AuditEvent:
    """Add an audit record to the caller's transaction; the caller commits it.

    Callers must sanitize safe_metadata and never put credentials, secrets, or
    file contents into audit metadata.
    """
    values = event_data.model_dump(exclude_none=True)
    for field in UUID_FIELDS:
        if field in values:
            values[field] = str(values[field])
    values.setdefault("correlation_id", str(uuid4()))
    audit_event = AuditEvent(**values)
    db.add(audit_event)
    db.flush()
    return audit_event


def record_phase2_audit(
    db: Session,
    *,
    action: str,
    result_status: str,
    resource_type: str,
    correlation_id,
    resource_id=None,
    asset_id=None,
    incident_id=None,
    event_id=None,
    assessment_id=None,
    decision_id=None,
    actor_id: str | None = None,
    source_component: str | None = None,
    reason: str | None = None,
    safe_metadata: dict | None = None,
) -> AuditEvent:
    """Record a concise, non-sensitive audit entry for an internal workflow."""
    return record_audit_event(
        db,
        AuditEventCreate(
            actor_type="internal_component",
            actor_id=actor_id,
            action=action,
            result_status=result_status,
            resource_type=resource_type,
            resource_id=resource_id,
            asset_id=asset_id,
            incident_id=incident_id,
            event_id=event_id,
            assessment_id=assessment_id,
            decision_id=decision_id,
            source_component=source_component,
            reason=reason,
            safe_metadata=safe_metadata or {},
            correlation_id=correlation_id,
        ),
    )