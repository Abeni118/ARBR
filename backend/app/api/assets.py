from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.common import get_or_404, paginate
from app.database.session import get_db
from app.models import Asset
from app.schemas import AssetCreate, AssetRead, AuditEventCreate, Page
from app.services.audit import record_audit_event
from app.services.user_auth import UserPrincipal, UserRole, get_current_user, require_role

router = APIRouter(prefix="/api/assets", tags=["assets"], dependencies=[Depends(get_current_user)])


@router.post("", response_model=AssetRead, status_code=status.HTTP_201_CREATED)
def create_asset(
    payload: AssetCreate,
    db: Session = Depends(get_db),
    current_user: UserPrincipal = Depends(require_role(UserRole.ANALYST)),
):
    """Register an asset record; this does not connect to or isolate a host."""
    asset = Asset(**payload.model_dump())
    db.add(asset)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Asset external reference already exists") from exc
    record_audit_event(
        db,
        AuditEventCreate(
            actor_type="user",
            actor_id=current_user.user_id,
            action="asset.created",
            result_status="success",
            resource_type="asset",
            resource_id=asset.id,
            asset_id=asset.id,
            source_component="api",
        ),
    )
    db.commit()
    db.refresh(asset)
    return asset


@router.get("", response_model=Page[AssetRead])
def list_assets(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    hostname: str | None = None,
    environment: str | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(Asset)
    if hostname:
        query = query.filter(Asset.hostname.ilike(f"%{hostname}%"))
    if environment:
        query = query.filter(Asset.environment == environment)
    return paginate(query.order_by(Asset.created_at.desc()), page, page_size)


@router.get("/{asset_id}", response_model=AssetRead)
def get_asset(asset_id: UUID, db: Session = Depends(get_db)):
    return get_or_404(db, Asset, str(asset_id), "Asset")