from backend.app.decision.actions import DecisionAction
from backend.app.decision.action_executor import ActionExecutor

from backend.app.decision.decision_engine import (
    DecisionEngine,
    SecurityEvent,
)
from backend.app.decision.policies import RiskLevel


def test_low_risk_event_is_allowed():
    event = SecurityEvent(
        event_id="event-001",
        host_id="host-01",
        threat_type="normal_file_activity",
        risk_level=RiskLevel.LOW,
        risk_score=10.0,
    )

    decision = DecisionEngine().decide(event)

    assert decision.action == DecisionAction.ALLOW


def test_medium_risk_event_triggers_alert():
    event = SecurityEvent(
        event_id="event-002",
        host_id="host-01",
        threat_type="suspicious_file_activity",
        risk_level=RiskLevel.MEDIUM,
        risk_score=40.0,
    )

    decision = DecisionEngine().decide(event)

    assert decision.action == DecisionAction.ALERT


def test_high_risk_event_triggers_protection():
    event = SecurityEvent(
        event_id="event-003",
        host_id="host-01",
        threat_type="ransomware_behavior",
        risk_level=RiskLevel.HIGH,
        risk_score=70.0,
    )

    decision = DecisionEngine().decide(event)

    assert decision.action == DecisionAction.PROTECT


def test_critical_risk_event_triggers_isolation():
    event = SecurityEvent(
        event_id="event-004",
        host_id="host-01",
        threat_type="ransomware_behavior",
        risk_level=RiskLevel.CRITICAL,
        risk_score=95.0,
    )

    decision = DecisionEngine().decide(event)

    assert decision.action == DecisionAction.ISOLATE


def test_decision_contains_event_context():
    event = SecurityEvent(
        event_id="event-005",
        host_id="host-02",
        threat_type="mass_file_encryption",
        risk_level=RiskLevel.CRITICAL,
        risk_score=98.0,
    )

    decision = DecisionEngine().decide(event)

    assert decision.event_id == "event-005"
    assert decision.host_id == "host-02"
    assert decision.risk_level == RiskLevel.CRITICAL
    assert decision.risk_score == 98.0
    assert "mass_file_encryption" in decision.reason


def test_allow_action_executes_without_handler():
    event = SecurityEvent(
        event_id="event-007",
        host_id="host-01",
        threat_type="normal_activity",
        risk_level=RiskLevel.LOW,
        risk_score=5.0,
    )

    decision = DecisionEngine().decide(event)
    result = ActionExecutor().execute(decision)

    assert result.action == DecisionAction.ALLOW
    assert result.success is True


def test_isolation_action_calls_isolation_handler():
    executed = []

    def isolate(decision):
        executed.append(decision.host_id)
        return True

    event = SecurityEvent(
        event_id="event-008",
        host_id="host-02",
        threat_type="ransomware",
        risk_level=RiskLevel.CRITICAL,
        risk_score=97.0,
    )

    decision = DecisionEngine().decide(event)

    result = ActionExecutor(
        isolate_handler=isolate,
    ).execute(decision)

    assert result.action == DecisionAction.ISOLATE
    assert result.success is True
    assert executed == ["host-02"]


def test_action_fails_when_required_handler_is_missing():
    event = SecurityEvent(
        event_id="event-009",
        host_id="host-03",
        threat_type="ransomware",
        risk_level=RiskLevel.CRITICAL,
        risk_score=99.0,
    )

    decision = DecisionEngine().decide(event)

    result = ActionExecutor().execute(decision)

    assert result.action == DecisionAction.ISOLATE
    assert result.success is False


def test_protection_action_calls_protection_handler():
    executed = []

    def protect(decision):
        executed.append(decision.host_id)
        return True

    event = SecurityEvent(
        event_id="event-010",
        host_id="host-04",
        threat_type="ransomware_behavior",
        risk_level=RiskLevel.HIGH,
        risk_score=85.0,
    )

    decision = DecisionEngine().decide(event)

    result = ActionExecutor(
        protect_handler=protect,
    ).execute(decision)

    assert result.action == DecisionAction.PROTECT
    assert result.success is True
    assert executed == ["host-04"]


def test_alert_action_calls_alert_handler():
    executed = []

    def alert(decision):
        executed.append(decision.event_id)
        return True

    event = SecurityEvent(
        event_id="event-011",
        host_id="host-05",
        threat_type="suspicious_activity",
        risk_level=RiskLevel.MEDIUM,
        risk_score=45.0,
    )

    decision = DecisionEngine().decide(event)

    result = ActionExecutor(
        alert_handler=alert,
    ).execute(decision)

    assert result.action == DecisionAction.ALERT
    assert result.success is True
    assert executed == ["event-011"]


def test_handler_exception_returns_failed_result():
    def isolate(_decision):
        raise RuntimeError("firewall unavailable")

    event = SecurityEvent(
        event_id="event-012",
        host_id="host-06",
        threat_type="ransomware",
        risk_level=RiskLevel.CRITICAL,
        risk_score=99.0,
    )

    decision = DecisionEngine().decide(event)

    result = ActionExecutor(
        isolate_handler=isolate,
    ).execute(decision)

    assert result.action == DecisionAction.ISOLATE
    assert result.success is False
    assert "firewall unavailable" in result.message

def test_critical_event_does_not_recover_automatically():
    event = SecurityEvent(
        event_id="event-006",
        host_id="host-03",
        threat_type="ransomware_behavior",
        risk_level=RiskLevel.CRITICAL,
        risk_score=99.0,
        backup_verified=True,
    )

    decision = DecisionEngine().decide(event)

    assert decision.action == DecisionAction.ISOLATE
    assert decision.action != DecisionAction.RECOVER