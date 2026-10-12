"""
Unit tests for the decision pipeline: DecisionEngine -> ActionExecutor.

Written against the dataclass models in backend/app/decision/models.py and
the list-based API DecisionEngine.decide(events, backups, now).

A SecurityEvent has no host field, so tests pass the host through
raw_data={"host_id": ...}, which is where the audit log reads it from.

Run from the repo root:

    python -m pytest backend/tests/unit -v
"""

from datetime import datetime, timedelta, timezone

import pytest

from backend.app.decision.action_executor import ActionExecutor
from backend.app.decision.audit import DecisionAuditLog
from backend.app.decision.decision_engine import DecisionEngine
from backend.app.decision.models import (
    BackupStatus,
    ResponseAction,
    RiskLevel,
    SecurityEvent,
)

# A fixed moment in time so results never depend on when the tests run.
NOW = datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_event(
    event_type: str,
    severity: int,
    source: str = "file_monitor",
    host_id: str = "host-01",
    event_id: str | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id or f"evt-{event_type}",
        timestamp=NOW,
        source=source,
        event_type=event_type,
        severity=severity,
        raw_data={"host_id": host_id},
    )


def low_risk_events(host_id: str = "host-01") -> list:
    return [make_event("failed_login", 5, host_id=host_id)]


def medium_risk_events(host_id: str = "host-01") -> list:
    return [make_event("mass_file_encryption", 10, host_id=host_id)]


def high_risk_events(host_id: str = "host-01") -> list:
    return [
        make_event("privilege_escalation", 10, source="ad_monitor", host_id=host_id),
        make_event("lateral_movement", 10, source="ad_monitor", host_id=host_id),
    ]


def critical_risk_events(host_id: str = "host-01") -> list:
    return [
        make_event("privilege_escalation", 10, host_id=host_id),
        make_event("lateral_movement", 10, host_id=host_id),
        make_event("backup_tampering", 10, host_id=host_id),
    ]


def ransomware_events(host_id: str = "host-01") -> list:
    """Active file damage plus an attack on the backups (CRITICAL)."""
    return [
        make_event("mass_file_encryption", 9, source="file_monitor", host_id=host_id),
        make_event("backup_deletion_attempt", 8, source="backup_agent", host_id=host_id),
    ]


def make_backup(
    backup_id: str = "bkp-1",
    hours_before: float = 2,
    verified: bool = True,
    trusted: bool = True,
) -> BackupStatus:
    return BackupStatus(
        backup_id=backup_id,
        timestamp=NOW - timedelta(hours=hours_before),
        integrity_verified=verified,
        trusted=trusted,
        location=f"/backups/{backup_id}",
    )


# ---------------------------------------------------------------------------
# DecisionEngine: risk level -> action
# ---------------------------------------------------------------------------

def test_low_risk_event_is_allowed():
    decision = DecisionEngine().decide(low_risk_events(), now=NOW)

    assert decision.risk_assessment.risk_level == RiskLevel.LOW
    assert decision.action == ResponseAction.ALLOW


def test_medium_risk_event_triggers_alert():
    decision = DecisionEngine().decide(medium_risk_events(), now=NOW)

    assert decision.risk_assessment.risk_level == RiskLevel.MEDIUM
    assert decision.action == ResponseAction.ALERT


def test_high_risk_event_triggers_protection():
    decision = DecisionEngine().decide(high_risk_events(), now=NOW)

    assert decision.risk_assessment.risk_level == RiskLevel.HIGH
    assert decision.action == ResponseAction.PROTECT


def test_critical_risk_event_triggers_isolation():
    decision = DecisionEngine().decide(critical_risk_events(), now=NOW)

    assert decision.risk_assessment.risk_level == RiskLevel.CRITICAL
    assert decision.action == ResponseAction.ISOLATE


def test_backup_attack_escalates_low_risk_to_protect():
    # backup_deletion_attempt at severity 6 scores LOW, but an attack on the
    # backups must be answered with at least PROTECT.
    decision = DecisionEngine().decide(
        [make_event("backup_deletion_attempt", 6)], now=NOW
    )

    assert decision.risk_assessment.risk_level == RiskLevel.LOW
    assert decision.action == ResponseAction.PROTECT


def test_decision_contains_event_context():
    events = ransomware_events(host_id="host-02")

    decision = DecisionEngine().decide(events, now=NOW)

    assert decision.triggering_events == events
    assert decision.triggering_events[0].raw_data["host_id"] == "host-02"
    assert decision.risk_assessment.risk_level == RiskLevel.CRITICAL
    assert "CRITICAL" in decision.reason


# ---------------------------------------------------------------------------
# DecisionEngine: recovery rules
# ---------------------------------------------------------------------------

def test_damage_with_safe_backup_triggers_recovery():
    decision = DecisionEngine().decide(
        ransomware_events(), [make_backup("bkp-1")], now=NOW
    )

    assert decision.action == ResponseAction.RECOVER
    assert "restore_from_backup:bkp-1" in decision.actions_to_execute


@pytest.mark.parametrize(
    "backups",
    [
        [],
        [make_backup("bkp-unverified", verified=False)],
        [make_backup("bkp-untrusted", trusted=False)],
    ],
    ids=["no-backups", "unverified", "untrusted"],
)
def test_damage_without_safe_backup_does_not_recover(backups):
    decision = DecisionEngine().decide(ransomware_events(), backups, now=NOW)

    assert decision.action == ResponseAction.ISOLATE
    assert decision.action != ResponseAction.RECOVER
    assert not any(
        step.startswith("restore_from_backup")
        for step in decision.actions_to_execute
    )


# ---------------------------------------------------------------------------
# ActionExecutor
# ---------------------------------------------------------------------------

def test_allow_action_executes_without_handler():
    decision = DecisionEngine().decide(low_risk_events(), now=NOW)

    result = ActionExecutor().execute(decision)

    assert result.action == ResponseAction.ALLOW
    assert result.success is True


def test_isolation_action_calls_isolation_handler():
    executed = []

    def isolate(decision):
        executed.append(decision.triggering_events[0].raw_data["host_id"])
        return True

    decision = DecisionEngine().decide(critical_risk_events(host_id="host-02"), now=NOW)

    result = ActionExecutor(isolate_handler=isolate).execute(decision)

    assert result.action == ResponseAction.ISOLATE
    assert result.success is True
    assert executed == ["host-02"]


def test_action_fails_when_required_handler_is_missing():
    decision = DecisionEngine().decide(critical_risk_events(host_id="host-03"), now=NOW)

    result = ActionExecutor().execute(decision)

    assert result.action == ResponseAction.ISOLATE
    assert result.success is False
    assert "No handler configured" in result.message


def test_protection_action_calls_protection_handler():
    executed = []

    def protect(decision):
        executed.append(decision.triggering_events[0].raw_data["host_id"])
        return True

    decision = DecisionEngine().decide(high_risk_events(host_id="host-04"), now=NOW)

    result = ActionExecutor(protect_handler=protect).execute(decision)

    assert result.action == ResponseAction.PROTECT
    assert result.success is True
    assert executed == ["host-04"]


def test_alert_action_calls_alert_handler():
    executed = []

    def alert(decision):
        executed.append(decision.triggering_events[0].event_id)
        return True

    decision = DecisionEngine().decide(medium_risk_events(host_id="host-05"), now=NOW)

    result = ActionExecutor(alert_handler=alert).execute(decision)

    assert result.action == ResponseAction.ALERT
    assert result.success is True
    assert executed == ["evt-mass_file_encryption"]


def test_recover_action_calls_recover_handler():
    executed = []

    def recover(decision):
        executed.append(decision.action)
        return True

    decision = DecisionEngine().decide(
        ransomware_events(), [make_backup("bkp-1")], now=NOW
    )

    result = ActionExecutor(recover_handler=recover).execute(decision)

    assert result.action == ResponseAction.RECOVER
    assert result.success is True
    assert executed == [ResponseAction.RECOVER]


def test_handler_returning_false_marks_action_failed():
    decision = DecisionEngine().decide(critical_risk_events(), now=NOW)

    result = ActionExecutor(isolate_handler=lambda decision: False).execute(decision)

    assert result.action == ResponseAction.ISOLATE
    assert result.success is False
    assert "failed" in result.message


def test_handler_exception_returns_failed_result():
    def isolate(decision):
        raise RuntimeError("firewall unavailable")

    decision = DecisionEngine().decide(critical_risk_events(host_id="host-06"), now=NOW)

    result = ActionExecutor(isolate_handler=isolate).execute(decision)

    assert result.action == ResponseAction.ISOLATE
    assert result.success is False
    assert "firewall unavailable" in result.message


# ---------------------------------------------------------------------------
# ActionExecutor + DecisionAuditLog
# ---------------------------------------------------------------------------

def test_action_execution_creates_audit_record():
    audit_log = DecisionAuditLog()
    decision = DecisionEngine().decide(critical_risk_events(host_id="host-07"), now=NOW)

    result = ActionExecutor(
        isolate_handler=lambda decision: True,
        audit_log=audit_log,
    ).execute(decision)

    assert result.success is True

    records = audit_log.for_event(decision.triggering_events[0].event_id)

    assert len(records) == 1
    assert records[0].action.value == "ISOLATE"
    assert records[0].host_id == "host-07"
    assert records[0].success is True


def test_failed_action_is_audited_as_failed():
    audit_log = DecisionAuditLog()
    decision = DecisionEngine().decide(critical_risk_events(), now=NOW)

    ActionExecutor(audit_log=audit_log).execute(decision)  # no isolate handler

    records = audit_log.all()

    assert len(records) == 1
    assert records[0].success is False
    assert "No handler configured" in records[0].message