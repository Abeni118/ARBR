from enum import Enum

from backend.app.decision.actions import DecisionAction


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


RISK_ACTIONS = {
    RiskLevel.LOW: DecisionAction.ALLOW,
    RiskLevel.MEDIUM: DecisionAction.ALERT,
    RiskLevel.HIGH: DecisionAction.PROTECT,
    RiskLevel.CRITICAL: DecisionAction.ISOLATE,
}


def action_for_risk(risk_level: RiskLevel) -> DecisionAction:
    return RISK_ACTIONS[risk_level]