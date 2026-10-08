from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.init_db import DEFAULT_SETTINGS
from app.database.session import get_db
from app.models import SystemSettings
from app.schemas import SystemSettingsRead
from app.services.user_auth import get_current_user

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