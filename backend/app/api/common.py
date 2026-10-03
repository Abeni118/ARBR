from fastapi import HTTPException
from sqlalchemy.orm import Query, Session

from app.schemas import Page


def paginate(query: Query, page: int, page_size: int) -> Page:
    total = query.order_by(None).count()
    items = query.offset((page - 1) * page_size).limit(page_size).all()
    return Page(items=items, page=page, page_size=page_size, total=total)


def get_or_404(db: Session, model, record_id: str, entity_name: str):
    record = db.get(model, record_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"{entity_name} not found")
    return record