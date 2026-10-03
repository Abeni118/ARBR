from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.common import get_or_404, paginate
from app.database.session import get_db
from app.models import Asset
from app.schemas import AssetCreate, AssetRead, Page

router = APIRouter(prefix="/api/assets", tags=["assets"])


@router.post("", response_model=AssetRead, status_code=status.HTTP_201_CREATED)
def create_asset(payload: AssetCreate, db: Session = Depends(get_db)):
    """Register an asset record; this does not connect to or isolate a host."""
    asset = Asset(**payload.model_dump())
    db.add(asset)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Asset external reference already exists") from exc
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