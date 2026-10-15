from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from app.decision.actions import DecisionAction
from app.decision.decision_engine import Decision


@dataclass(frozen=True)
class DecisionAudit:
    event_id: str
    host_id: str
    action: DecisionAction
    risk_level: str
    risk_score: float
    reason: str
    success: bool
    message: str
    recorded_at: str

    def to_dict(self) -> dict:
        return asdict(self)


class DecisionAuditLog:
    def __init__(self):
        self._records: list[DecisionAudit] = []

    def record(
        self,
        decision: Decision,
        success: bool,
        message: str,
    ) -> DecisionAudit:
        # A Decision (see models.py) covers a list of events, so the audit
        # record is keyed on the first triggering event. With no events
        # (an ALLOW for a quiet system) it falls back to the decision's own id.
        events = decision.triggering_events
        event_id = events[0].event_id if events else decision.decision_id

        # SecurityEvent has no host field; detectors report it in raw_data.
        host_id = next(
            (e.raw_data["host_id"] for e in events if e.raw_data.get("host_id")),
            "unknown",
        )

        assessment = decision.risk_assessment

        record = DecisionAudit(
            event_id=event_id,
            host_id=host_id,
            action=DecisionAction(decision.action.value),
            risk_level=assessment.risk_level.value,
            risk_score=assessment.risk_score,
            reason=decision.reason,
            success=success,
            message=message,
            recorded_at=datetime.now(timezone.utc).isoformat(),
        )

        self._records.append(record)

        return record

    def all(self) -> list[DecisionAudit]:
        return list(self._records)

    def for_event(self, event_id: str) -> list[DecisionAudit]:
        return [
            record
            for record in self._records
            if record.event_id == event_id
        ]
