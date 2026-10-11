from app.backup.routes import router as backup_router
from fastapi import FastAPI

app = FastAPI(
    title="Attack-Resistant Backup & Recovery API",
    description="Backend API for the cyber resilience system",
    version="1.0.0"
)
app.include_router(backup_router)

@app.get("/")
def root():
    return {
        "message": "Attack-Resistant Backup & Recovery API is running"
    }
