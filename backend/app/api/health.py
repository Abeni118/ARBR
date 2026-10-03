from fastapi import APIRouter

router = APIRouter()


@router.get("/api/health", tags=["health"])
def health_check():
    return {"status": "ok"}