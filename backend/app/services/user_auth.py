"""Minimal environment-configured Bearer authentication for the university MVP."""

from dataclasses import dataclass
import hmac
import json
import os
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.enums import StringEnum
from app.schemas import AuditEventCreate
from app.services.audit import record_audit_event

bearer_scheme = HTTPBearer(auto_error=False)


class UserRole(StringEnum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    APPROVER = "approver"
    ADMIN = "admin"


@dataclass(frozen=True)
class UserPrincipal:
    user_id: str
    role: UserRole
    display_name: str | None = None


def _authentication_error(code: str, message: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"code": code, "message": message},
        headers={"WWW-Authenticate": "Bearer"},
    )


def _configured_users() -> list[dict[str, str]]:
    """Read token/principal mappings without logging or returning credentials."""
    raw_users = os.getenv("MVP_USER_TOKENS", "")
    try:
        users = json.loads(raw_users)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(users, list):
        return []
    valid: list[dict[str, str]] = []
    seen_tokens: set[str] = set()
    for item in users:
        if not isinstance(item, dict):
            continue
        token = item.get("token")
        user_id = item.get("user_id")
        role = item.get("role")
        display_name = item.get("display_name")
        if not all(isinstance(value, str) and value.strip() for value in (token, user_id, role)):
            continue
        if display_name is not None and not isinstance(display_name, str):
            continue
        try:
            UserRole(role)
        except ValueError:
            continue
        if token in seen_tokens:
            return []
        seen_tokens.add(token)
        valid.append(
            {
                "token": token,
                "user_id": user_id,
                "role": role,
                **({"display_name": display_name} if display_name is not None else {}),
            }
        )
    return valid


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)] = None,
) -> UserPrincipal:
    """Resolve a human principal from an environment-configured Bearer token."""
    if credentials is None:
        raise _authentication_error("authentication_required", "Bearer authentication is required")
    token = credentials.credentials
    for configured in _configured_users():
        if hmac.compare_digest(token.encode("utf-8"), configured["token"].encode("utf-8")):
            return UserPrincipal(
                user_id=configured["user_id"],
                role=UserRole(configured["role"]),
                display_name=configured.get("display_name"),
            )
    raise _authentication_error("invalid_authentication", "Invalid Bearer authentication")


def _record_authorization_denial(
    db: Session,
    request: Request,
    user: UserPrincipal,
) -> None:
    correlation_id = uuid4()
    raw_correlation_id = request.headers.get("X-Correlation-ID")
    if raw_correlation_id:
        try:
            correlation_id = UUID(raw_correlation_id)
        except ValueError:
            pass
    record_audit_event(
        db,
        AuditEventCreate(
            actor_type="user",
            actor_id=user.user_id,
            action="authorization.denied",
            result_status="rejected",
            resource_type="api_endpoint",
            source_component="api",
            reason="User role does not permit this operation",
            safe_metadata={"method": request.method, "path": request.url.path, "role": user.role.value},
            correlation_id=correlation_id,
        ),
    )
    db.commit()


def require_role(*allowed_roles: UserRole):
    """Return a dependency requiring one of the listed roles or admin."""
    accepted_roles = set(allowed_roles) | {UserRole.ADMIN}

    def dependency(
        request: Request,
        current_user: UserPrincipal = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> UserPrincipal:
        if current_user.role not in accepted_roles:
            _record_authorization_denial(db, request, current_user)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"code": "forbidden", "message": "Insufficient permissions"},
            )
        return current_user

    return dependency
