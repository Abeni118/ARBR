from contextlib import asynccontextmanager
from json import JSONDecodeError, loads
from uuid import UUID, uuid4

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.api import api_router
from app.database.init_db import initialize_database
from app.database.session import SessionLocal
from app.services.audit import record_phase2_audit


@asynccontextmanager
async def lifespan(_app: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title="Attack-Resistant Backup & Recovery API",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    """Avoid reflecting raw request values and audit invalid internal submissions."""
    path = request.url.path
    internal_resources = {
        "/api/internal/security-events": ("security_event.received", "security_event"),
        "/api/internal/threats": ("threat_incident.create", "threat_incident"),
        "/api/internal/risk-assessments": ("risk_assessment.create", "risk_assessment"),
        "/api/internal/decisions": ("decision.create", "decision"),
    }
    if path in internal_resources:
        action, resource_type = internal_resources[path]
        correlation_id = uuid4()
        try:
            body = loads(await request.body())
            if isinstance(body, dict) and body.get("correlation_id"):
                correlation_id = UUID(str(body["correlation_id"]))
        except (JSONDecodeError, UnicodeDecodeError, TypeError, ValueError):
            pass
        with SessionLocal() as db:
            record_phase2_audit(
                db,
                action=action,
                result_status="rejected",
                resource_type=resource_type,
                correlation_id=correlation_id,
                source_component="internal_api",
                reason="Request validation failed",
                safe_metadata={"method": request.method, "path": path},
            )
            db.commit()

    safe_errors = [
        {"loc": error.get("loc", ()), "msg": error.get("msg", "Invalid request"), "type": error.get("type", "value_error")}
        for error in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": safe_errors})


@app.get("/")
def root():
    return {
        "message": "Attack-Resistant Backup & Recovery API is running"
    }
