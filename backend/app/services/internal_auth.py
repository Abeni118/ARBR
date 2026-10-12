"""Environment-configured trusted component authentication for internal APIs."""

from dataclasses import dataclass
import hmac
import json
import os
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.enums import StringEnum
from app.models import IsolationAction, RecoveryJob
from app.schemas import AuditEventCreate
from app.services.audit import record_audit_event


class ComponentScope(StringEnum):
    SECURITY_EVENTS_WRITE = "security_events:write"
    THREATS_WRITE = "threats:write"
    RISK_ASSESSMENTS_WRITE = "risk_assessments:write"
    DECISIONS_WRITE = "decisions:write"
    BACKUPS_WRITE = "backups:write"
    VERIFICATION_WRITE = "verification:write"
    ISOLATION_WRITE = "isolation:write"
    RECOVERY_WRITE = "recovery:write"


@dataclass(frozen=True)
class ComponentPrincipal:
    component_id: str
    scopes: frozenset[str]


_LEGACY_SCOPES = frozenset(
    {
        ComponentScope.BACKUPS_WRITE.value,
        ComponentScope.VERIFICATION_WRITE.value,
        ComponentScope.ISOLATION_WRITE.value,
        ComponentScope.RECOVERY_WRITE.value,
    }
)


def _configured_components() -> list[dict[str, object]]:
    """Parse explicit component credentials, plus the legacy Phase 3-5 token."""
    raw_components = os.getenv("MVP_COMPONENT_TOKENS", "")
    try:
        configured = json.loads(raw_components) if raw_components else []
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(configured, list):
        return []

    valid: list[dict[str, object]] = []
    seen_tokens: set[str] = set()
    seen_ids: set[str] = set()
    valid_scopes = {scope.value for scope in ComponentScope}
    for item in configured:
        if not isinstance(item, dict):
            continue
        component_id = item.get("component_id")
        token = item.get("token")
        scopes = item.get("scopes")
        if (
            not isinstance(component_id, str)
            or not component_id.strip()
            or not isinstance(token, str)
            or not token.strip()
            or not isinstance(scopes, list)
            or not scopes
            or not all(isinstance(scope, str) and scope in valid_scopes for scope in scopes)
            or len(set(scopes)) != len(scopes)
        ):
            continue
        if token in seen_tokens or component_id in seen_ids:
            return []
        seen_tokens.add(token)
        seen_ids.add(component_id)
        valid.append({"component_id": component_id, "token": token, "scopes": frozenset(scopes)})

    # Compatibility bridge: the original shared token remains valid for the
    # Phase 3-5 routes only until deployments migrate to scoped component tokens.
    legacy_token = os.getenv("BACKUP_COMPONENT_TOKEN")
    if legacy_token and legacy_token.strip():
        if legacy_token in seen_tokens:
            return []
        valid.append(
            {
                "component_id": "legacy-backup-component",
                "token": legacy_token,
                "scopes": _LEGACY_SCOPES,
            }
        )
    return valid


def _audit_denied_component_request(
    db: Session,
    request: Request,
    *,
    component_id: str | None = None,
    required_scope: str | None = None,
    reason: str,
) -> None:
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
        action = "isolation.component_request_rejected"
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
        action = "recovery.component_request_rejected"
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

    safe_metadata: dict[str, str] = {"method": request.method, "path": path}
    if required_scope:
        safe_metadata["required_scope"] = required_scope
    if component_id:
        safe_metadata["component_id"] = component_id
    record_audit_event(
        db,
        AuditEventCreate(
            actor_type="internal_component",
            actor_id=component_id,
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
            source_component=component_id or "internal_api",
            reason=reason,
            safe_metadata=safe_metadata,
            correlation_id=correlation_id or uuid4(),
        ),
    )
    db.commit()


def _component_auth_error(code: str, message: str, *, unauthorized: bool) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED if unauthorized else status.HTTP_403_FORBIDDEN,
        detail={"code": code, "message": message},
        headers={"WWW-Authenticate": "X-Internal-Component-Token"} if unauthorized else None,
    )


def get_current_component(
    request: Request,
    x_internal_component_token: Annotated[str | None, Header(alias="X-Internal-Component-Token")] = None,
    db: Session = Depends(get_db),
) -> ComponentPrincipal:
    """Resolve an internal caller without exposing its configured token."""
    if not x_internal_component_token:
        _audit_denied_component_request(db, request, reason="Internal component authentication is required")
        raise _component_auth_error(
            "component_authentication_required",
            "Internal component credential is required",
            unauthorized=True,
        )

    for configured in _configured_components():
        configured_token = configured["token"]
        if isinstance(configured_token, str) and hmac.compare_digest(
            x_internal_component_token.encode("utf-8"), configured_token.encode("utf-8")
        ):
            return ComponentPrincipal(
                component_id=str(configured["component_id"]),
                scopes=frozenset(configured["scopes"]),
            )

    _audit_denied_component_request(db, request, reason="Invalid internal component credential")
    raise _component_auth_error(
        "invalid_component_authentication",
        "Invalid internal component credential",
        unauthorized=True,
    )


def require_component_scope(required_scope: ComponentScope):
    """Require a valid component principal with the endpoint's single scope."""

    def dependency(
        request: Request,
        component: ComponentPrincipal = Depends(get_current_component),
        db: Session = Depends(get_db),
    ) -> ComponentPrincipal:
        if required_scope.value not in component.scopes:
            _audit_denied_component_request(
                db,
                request,
                component_id=component.component_id,
                required_scope=required_scope.value,
                reason="Component does not have the required scope",
            )
            raise _component_auth_error(
                "insufficient_component_scope",
                "Component is not authorized for this operation",
                unauthorized=False,
            )
        return component

    return dependency


require_backup_component = require_component_scope(ComponentScope.BACKUPS_WRITE)