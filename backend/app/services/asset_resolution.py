from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Asset
from app.schemas import AssetExternalReference


def resolve_asset(
    db: Session,
    asset_id: UUID | str | None = None,
    external_ref: AssetExternalReference | None = None,
) -> Asset:
    """Resolve an existing asset without creating one implicitly."""
    if asset_id is not None:
        asset = db.get(Asset, str(asset_id))
        if asset is None:
            raise HTTPException(status_code=404, detail="Asset not found")
        return asset
    if external_ref is not None:
        asset = db.scalar(
            select(Asset).where(
                Asset.external_source == external_ref.external_source,
                Asset.external_id == external_ref.external_id,
            )
        )
        if asset is None:
            raise HTTPException(status_code=404, detail="Asset external reference not found")
        return asset
    raise HTTPException(status_code=422, detail="An asset reference is required")