"""
api.py - Web (HTTP) interface to the Decision Engine.

Why this exists:
    Other team members' components (monitoring, backup, dashboard) may
    not be able to import your Python code directly. An HTTP API lets
    them send events to your engine and receive a decision back.

Endpoints:
    GET  /decision/health    -> is the service alive?
    POST /decision/evaluate  -> send events (+ backups), get a Decision
    GET  /decision/history   -> the most recent decisions

How the file is organised:
    * "Request models" describe the JSON others must send. FastAPI uses
      them to validate input automatically (e.g. severity must be 1-10)
      and answers with an error message if the data is wrong.
    * An APIRouter holds the endpoints. Your teammate building the main
      app can plug it in with:  app.include_router(router)
    * A small `app` at the bottom lets you run this file on its own.

Run it from the PROJECT ROOT:

    python -m uvicorn backend.app.decision.api:app --reload

Then open http://127.0.0.1:8000/docs in your browser. FastAPI builds an
interactive page there where you can try every endpoint with no extra tools.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, FastAPI
from pydantic import BaseModel, Field

from .decision_engine import DecisionEngine
from .decision_logger import DecisionLogger, decision_to_dict
from .models import BackupStatus, SecurityEvent


# ---------------------------------------------------------------------------
# Request models (the JSON shape other components must send)
# ---------------------------------------------------------------------------

class SecurityEventIn(BaseModel):
    """One security event, as received over HTTP."""

    event_id: str
    # If the sender leaves out the timestamp, we use the current time.
    timestamp: Optional[datetime] = None
    source: str
    event_type: str
    # ge/le = "greater or equal" / "less or equal". FastAPI rejects
    # values outside 1-10 automatically with a clear error message.
    severity: int = Field(..., ge=1, le=10)
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class BackupStatusIn(BaseModel):
    """One backup's status, as received over HTTP."""

    backup_id: str
    timestamp: datetime
    integrity_verified: bool
    trusted: bool
    location: str


class EvaluateRequest(BaseModel):
    """The full body of a POST /decision/evaluate request."""

    events: List[SecurityEventIn] = Field(default_factory=list)
    backups: List[BackupStatusIn] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Shared objects (created once, reused by every request)
# ---------------------------------------------------------------------------

engine = DecisionEngine()
audit = DecisionLogger()  # writes to logs/decision_audit.jsonl by default

router = APIRouter(prefix="/decision", tags=["Decision Engine"])


# ---------------------------------------------------------------------------
# Converters: web models -> our own dataclasses from models.py
# ---------------------------------------------------------------------------

def _to_event(item: SecurityEventIn) -> SecurityEvent:
    """Convert a web request event into a SecurityEvent."""
    return SecurityEvent(
        event_id=item.event_id,
        timestamp=item.timestamp or datetime.now(timezone.utc),
        source=item.source,
        event_type=item.event_type,
        severity=item.severity,
        raw_data=item.raw_data,
    )


def _to_backup(item: BackupStatusIn) -> BackupStatus:
    """Convert a web request backup into a BackupStatus."""
    return BackupStatus(
        backup_id=item.backup_id,
        timestamp=item.timestamp,
        integrity_verified=item.integrity_verified,
        trusted=item.trusted,
        location=item.location,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/health")
def health() -> Dict[str, str]:
    """Simple check that the service is running."""
    return {"status": "ok"}


@router.post("/evaluate")
def evaluate(request: EvaluateRequest) -> Dict[str, Any]:
    """Analyse events and backups, log the result, and return a Decision."""
    events = [_to_event(item) for item in request.events]
    backups = [_to_backup(item) for item in request.backups]

    decision = engine.decide(events, backups)
    audit.log(decision)

    # Convert the Decision dataclass into a plain dictionary. FastAPI
    # turns dates and enums into JSON text automatically.
    return decision_to_dict(decision)


@router.get("/history")
def history(limit: int = 10) -> List[Dict[str, Any]]:
    """Return the most recent decisions (newest last).

    Args:
        limit: How many to return (default 10). Use /history?limit=25.
    """
    limit = max(1, min(limit, 100))  # keep it between 1 and 100
    return [decision_to_dict(item) for item in audit.get_recent(limit)]


# ---------------------------------------------------------------------------
# Stand-alone app (for running this file by itself)
# ---------------------------------------------------------------------------

app = FastAPI(title="Cyber Resilience Decision Engine")
app.include_router(router)