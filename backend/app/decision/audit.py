from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from backend.app.decision.actions import DecisionAction
from backend.app.decision.decision_engine import Decision


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
        record = DecisionAudit(
            event_id=decision.event_id,
            host_id=decision.host_id,
            action=decision.action,
            risk_level=decision.risk_level.value,
            risk_score=decision.risk_score,
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