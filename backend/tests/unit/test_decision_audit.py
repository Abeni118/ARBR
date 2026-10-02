from backend.app.decision.actions import DecisionAction
from backend.app.decision.audit import DecisionAuditLog
from backend.app.decision.decision_engine import (
    DecisionEngine,
    SecurityEvent,
)
from backend.app.decision.policies import RiskLevel


def create_decision():
    event = SecurityEvent(
        event_id="event-100",
        host_id="host-01",
        threat_type="ransomware_behavior",
        risk_level=RiskLevel.CRITICAL,
        risk_score=96.0,
    )

    return DecisionEngine().decide(event)


def test_audit_records_decision():
    decision = create_decision()
    audit_log = DecisionAuditLog()

    record = audit_log.record(
        decision,
        success=True,
        message="Host isolated successfully.",
    )

    assert record.event_id == "event-100"
    assert record.host_id == "host-01"
    assert record.action == DecisionAction.ISOLATE
    assert record.risk_level == "CRITICAL"
    assert record.risk_score == 96.0
    assert record.success is True
    assert record.message == "Host isolated successfully."
    assert record.recorded_at


def test_audit_returns_all_records():
    decision = create_decision()
    audit_log = DecisionAuditLog()

    audit_log.record(
        decision,
        success=True,
        message="Host isolated.",
    )

    records = audit_log.all()

    assert len(records) == 1
    assert records[0].event_id == "event-100"


def test_audit_can_filter_by_event():
    decision = create_decision()
    audit_log = DecisionAuditLog()

    audit_log.record(
        decision,
        success=True,
        message="Host isolated.",
    )

    records = audit_log.for_event("event-100")

    assert len(records) == 1
    assert records[0].action == DecisionAction.ISOLATE


def test_audit_unknown_event_returns_empty_list():
    audit_log = DecisionAuditLog()

    records = audit_log.for_event("does-not-exist")

    assert records == []


def test_audit_record_can_be_serialized():
    decision = create_decision()
    audit_log = DecisionAuditLog()

    record = audit_log.record(
        decision,
        success=False,
        message="Isolation failed.",
    )

    data = record.to_dict()

    assert data["event_id"] == "event-100"
    assert data["action"] == DecisionAction.ISOLATE
    assert data["success"] is False