import hmac
import os
from uuid import UUID

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models import IsolationAction, RecoveryJob
from app.schemas import AuditEventCreate
from app.services.audit import record_audit_event


def _audit_denied_component_request(db: Session, request: Request) -> None:
    path = request.url.path
    isolation_action_id = None
    resource_id = None
    asset_id = None
    incident_id = None
    decision_id = None
    action_request_id = None
    recovery_job_id = None
    correlation_id = None
    resource_type = "internal_component_request"
    action = "internal_component.request_rejected"
    if path.startswith("/api/internal/isolation/"):
        action = "isolation.component_result_rejected"
        resource_type = "isolation_action"
        try:
            isolation_action_id = UUID(path.split("/")[4])
            resource_id = isolation_action_id
            isolation_action = db.get(IsolationAction, str(isolation_action_id))
            if isolation_action is not None:
                asset_id = isolation_action.asset_id
                incident_id = isolation_action.incident_id
                decision_id = isolation_action.decision_id
                action_request_id = isolation_action.action_request_id
                correlation_id = UUID(isolation_action.correlation_id)
        except (IndexError, ValueError):
            pass
    elif path.startswith("/api/internal/recovery-jobs/"):
        action = "recovery.component_result_rejected"
        resource_type = "recovery_job"
        try:
            recovery_job_id = UUID(path.split("/")[4])
            resource_id = recovery_job_id
            job = db.get(RecoveryJob, str(recovery_job_id))
            if job is not None:
                asset_id = UUID(job.asset_id)
                incident_id = UUID(job.incident_id)
                action_request_id = UUID(job.action_request_id)
                correlation_id = UUID(job.correlation_id)
        except (IndexError, ValueError):
            pass
    record_audit_event(
        db,
        AuditEventCreate(
            actor_type="internal_component",
            action=action,
            result_status="rejected",
            resource_type=resource_type,
            resource_id=resource_id,
            asset_id=asset_id,
            incident_id=incident_id,
            decision_id=decision_id,
            action_request_id=action_request_id,
            isolation_action_id=isolation_action_id,
            recovery_job_id=recovery_job_id,
            source_component="internal_api",
            reason="Internal component authentication failed or is not configured",
            safe_metadata={"method": request.method, "path": path},
            correlation_id=correlation_id,
        ),
    )
    db.commit()


def require_backup_component(
    request: Request,
    x_internal_component_token: str | None = Header(default=None, alias="X-Internal-Component-Token"),
    db: Session = Depends(get_db),
) -> None:
    """Restrict backup/integrity result endpoints to a configured component token."""
    expected_token = os.getenv("BACKUP_COMPONENT_TOKEN")
    if not expected_token:
        _audit_denied_component_request(db, request)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Backup component reporting is not configured",
        )
    if x_internal_component_token is None or not hmac.compare_digest(x_internal_component_token, expected_token):
        _audit_denied_component_request(db, request)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid internal component credential")