from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.init_db import DEFAULT_SETTINGS
from app.database.session import get_db
from app.models import SystemSettings
from app.schemas import AuditEventCreate, SystemSettingsRead, SystemSettingsUpdate
from app.services.audit import record_audit_event
from app.services.user_auth import UserPrincipal, UserRole, get_current_user, require_role

router = APIRouter(prefix="/api/settings", tags=["settings"], dependencies=[Depends(get_current_user)])


@router.get("", response_model=SystemSettingsRead)
def get_system_settings(db: Session = Depends(get_db)):
    settings = db.scalar(select(SystemSettings).where(SystemSettings.is_singleton.is_(True)))
    if settings is None:
        settings = SystemSettings(is_singleton=True, **DEFAULT_SETTINGS)
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


@router.put("", response_model=SystemSettingsRead)
def update_system_settings(
    payload: SystemSettingsUpdate,
    current_user: UserPrincipal = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
):
    settings = db.scalar(select(SystemSettings).where(SystemSettings.is_singleton.is_(True)))
    if settings is None:
        settings = SystemSettings(is_singleton=True, **DEFAULT_SETTINGS)
        db.add(settings)
        db.flush()

    changes = payload.model_dump(exclude_unset=True)
    settings.risk_thresholds = changes["risk_thresholds"]
    settings.version += 1
    record_audit_event(
        db,
        AuditEventCreate(
            actor_type="user",
            actor_id=current_user.user_id,
            action="system_settings.updated",
            result_status="success",
            resource_type="system_settings",
            resource_id=settings.id,
            source_component="api",
            reason="Administrator updated system policy configuration",
            safe_metadata={"changed_fields": sorted(changes), "version": settings.version},
        ),
    )
    db.commit()
    db.refresh(settings)
    return settings