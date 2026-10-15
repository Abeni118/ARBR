"""
Unit tests for DecisionAuditLog.

Decisions come from the real DecisionEngine (list-of-events API). The audit
log keys each record on the decision's first triggering event and reads the
host from that event's raw_data["host_id"].

Run from the repo root:

    python -m pytest backend/tests/unit -v
"""

import json
from datetime import datetime, timezone

import pytest

from backend.app.decision.audit import DecisionAuditLog
from backend.app.decision.decision_engine import DecisionEngine
from backend.app.decision.models import SecurityEvent

NOW = datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)


def create_decision():
    """Ransomware with no backups: CRITICAL risk, so the action is ISOLATE."""
    events = [
        SecurityEvent(
            event_id="event-100",
            timestamp=NOW,
            source="file_monitor",
            event_type="mass_file_encryption",
            severity=9,
            raw_data={"host_id": "host-01"},
        ),
        SecurityEvent(
            event_id="event-101",
            timestamp=NOW,
            source="backup_agent",
            event_type="backup_deletion_attempt",
            severity=8,
            raw_data={"host_id": "host-01"},
        ),
    ]

    return DecisionEngine().decide(events, [], now=NOW)


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
    assert record.action.value == "ISOLATE"
    assert record.risk_level == "CRITICAL"
    assert record.risk_score == pytest.approx(decision.risk_assessment.risk_score)
    assert record.reason == decision.reason
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


def test_audit_all_returns_a_copy():
    audit_log = DecisionAuditLog()
    audit_log.record(create_decision(), success=True, message="Host isolated.")

    audit_log.all().clear()

    assert len(audit_log.all()) == 1


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
    assert records[0].action.value == "ISOLATE"


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
    assert data["action"] == "ISOLATE"
    assert data["success"] is False
    assert json.loads(json.dumps(data))["risk_level"] == "CRITICAL"


def test_audit_without_events_falls_back_to_decision_id():
    # A quiet system produces an ALLOW decision with no triggering events.
    decision = DecisionEngine().decide([], now=NOW)
    audit_log = DecisionAuditLog()

    record = audit_log.record(decision, success=True, message="Event allowed.")

    assert record.event_id == decision.decision_id
    assert record.host_id == "unknown"
    assert record.action.value == "ALLOW"
