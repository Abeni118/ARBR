from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.common import as_utc, get_or_404, paginate
from app.database.session import get_db
from app.enums import BackupLifecycleStatus, BackupProtectionStatus
from app.models import Backup
from app.schemas import BackupRead, Page

router = APIRouter(prefix="/api/backups", tags=["backups"])


@router.get("", response_model=Page[BackupRead])
def list_backups(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    asset_id: UUID | None = None,
    status: BackupLifecycleStatus | None = None,
    protection_status: BackupProtectionStatus | None = None,
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(Backup)
    if asset_id:
        query = query.filter(Backup.asset_id == str(asset_id))
    if status:
        query = query.filter(Backup.lifecycle_status == status.value)
    if protection_status:
        query = query.filter(Backup.protection_status == protection_status.value)
    if from_:
        query = query.filter(Backup.backup_created_at >= as_utc(from_))
    if to:
        query = query.filter(Backup.backup_created_at <= as_utc(to))
    return paginate(query.order_by(Backup.backup_created_at.desc()), page, page_size)


@router.get("/{backup_id}", response_model=BackupRead)
def get_backup(backup_id: UUID, db: Session = Depends(get_db)):
    return get_or_404(db, Backup, str(backup_id), "Backup")