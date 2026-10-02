from dataclasses import dataclass

from backend.app.decision.actions import DecisionAction
from backend.app.decision.policies import RiskLevel, action_for_risk


@dataclass(frozen=True)
class SecurityEvent:
    event_id: str
    host_id: str
    threat_type: str
    risk_level: RiskLevel
    risk_score: float
    backup_verified: bool = False


@dataclass(frozen=True)
class Decision:
    event_id: str
    host_id: str
    action: DecisionAction
    risk_level: RiskLevel
    risk_score: float
    reason: str


class DecisionEngine:
    def decide(self, event: SecurityEvent) -> Decision:
        action = action_for_risk(event.risk_level)

        if (
            event.risk_level == RiskLevel.CRITICAL
            and event.backup_verified
        ):
            action = DecisionAction.ISOLATE

        reason = self._build_reason(event, action)

        return Decision(
            event_id=event.event_id,
            host_id=event.host_id,
            action=action,
            risk_level=event.risk_level,
            risk_score=event.risk_score,
            reason=reason,
        )

    @staticmethod
    def _build_reason(
        event: SecurityEvent,
        action: DecisionAction,
    ) -> str:
        return (
            f"{event.threat_type} activity on host {event.host_id} "
            f"has risk level {event.risk_level.value} "
            f"with score {event.risk_score:.2f}; "
            f"selected action: {action.value}."
        )