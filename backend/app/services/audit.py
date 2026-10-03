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