import hmac
import os

from fastapi import Header, HTTPException, status


def require_backup_component(
    x_internal_component_token: str | None = Header(default=None, alias="X-Internal-Component-Token"),
) -> None:
    """Restrict backup/integrity result endpoints to a configured component token."""
    expected_token = os.getenv("BACKUP_COMPONENT_TOKEN")
    if not expected_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Backup component reporting is not configured",
        )
    if x_internal_component_token is None or not hmac.compare_digest(x_internal_component_token, expected_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid internal component credential")