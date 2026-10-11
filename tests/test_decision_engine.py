"""
test_decision_engine.py - Automated tests for the Decision Engine.

A "test" is a small function that runs a piece of your code with known
input and checks (with `assert`) that the output is what you expect.
If an assert is false, pytest reports a failure and shows you where.

Every test uses the same fixed "current time" (NOW) so results never
depend on when you run them.

Run from the PROJECT ROOT (the folder containing backend/ and tests/):

    python -m pytest -v
"""

from datetime import datetime, timedelta, timezone

import pytest

from backend.app.decision import (
    BackupStatus,
    Decision,
    DecisionEngine,
    DecisionLogger,
    ResponseAction,
    RiskAssessment,
    RiskLevel,
    RiskScorer,
    SecurityEvent,
)
from backend.app.decision.decision_engine import ACTION_STEPS

# A fixed moment in time used by every test.
NOW = datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Helper functions (build test data quickly)
# ---------------------------------------------------------------------------

def make_event(
    event_type: str,
    severity: int,
    minutes_ago: float = 0,
    source: str = "file_monitor",
) -> SecurityEvent:
    """Create a SecurityEvent that happened `minutes_ago` before NOW."""
    return SecurityEvent(
        event_id=f"evt-{event_type}",
        timestamp=NOW - timedelta(minutes=minutes_ago),
        source=source,
        event_type=event_type,
        severity=severity,
    )


def make_backup(
    backup_id: str,
    hours_before: float,
    verified: bool = True,
    trusted: bool = True,
) -> BackupStatus:
    """Create a BackupStatus made `hours_before` hours before NOW.

    A negative number means the backup was made AFTER NOW.
    """
    return BackupStatus(
        backup_id=backup_id,
        timestamp=NOW - timedelta(hours=hours_before),
        integrity_verified=verified,
        trusted=trusted,
        location=f"/backups/{backup_id}",
    )


def ransomware_events() -> list:
    """Two events from different sources: scores 84.0 (CRITICAL)."""
    return [
        make_event("mass_file_encryption", 9, source="file_monitor"),
        make_event("backup_deletion_attempt", 8, source="backup_agent"),
    ]


# ---------------------------------------------------------------------------
# Tests for models.py
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad_severity", [0, 11, -3])
def test_event_rejects_invalid_severity(bad_severity):
    with pytest.raises(ValueError):
        make_event("failed_login", bad_severity)


@pytest.mark.parametrize("bad_score", [-1, 100.5])
def test_risk_assessment_rejects_invalid_score(bad_score):
    with pytest.raises(ValueError):
        RiskAssessment(bad_score, RiskLevel.LOW)


@pytest.mark.parametrize("bad_confidence", [-0.1, 1.1])
def test_decision_rejects_invalid_confidence(bad_confidence):
    assessment = RiskAssessment(0, RiskLevel.LOW)
    with pytest.raises(ValueError):
        Decision(ResponseAction.ALLOW, "test", assessment, bad_confidence)


@pytest.mark.parametrize(
    "score, expected_level",
    [
        (0, RiskLevel.LOW),
        (24.9, RiskLevel.LOW),
        (25, RiskLevel.MEDIUM),
        (49.9, RiskLevel.MEDIUM),
        (50, RiskLevel.HIGH),
        (74.9, RiskLevel.HIGH),
        (75, RiskLevel.CRITICAL),
        (100, RiskLevel.CRITICAL),
    ],
)
def test_level_from_score_boundaries(score, expected_level):
    assert RiskAssessment.level_from_score(score) == expected_level


@pytest.mark.parametrize(
    "verified, trusted, expected",
    [(True, True, True), (True, False, False),
     (False, True, False), (False, False, False)],
)
def test_backup_safe_only_if_verified_and_trusted(verified, trusted, expected):
    backup = make_backup("bkp", 1, verified=verified, trusted=trusted)
    assert backup.is_safe_to_restore() is expected


def test_decisions_get_unique_ids():
    assessment = RiskAssessment(0, RiskLevel.LOW)
    first = Decision(ResponseAction.ALLOW, "a", assessment, 0.9)
    second = Decision(ResponseAction.ALLOW, "b", assessment, 0.9)
    assert first.decision_id != second.decision_id


# ---------------------------------------------------------------------------
# Tests for risk_scorer.py
# ---------------------------------------------------------------------------

def test_no_events_gives_zero_risk():
    result = RiskScorer().assess([], now=NOW)
    assert result.risk_score == 0
    assert result.risk_level == RiskLevel.LOW


def test_single_severe_event_scores_40():
    result = RiskScorer().assess([make_event("mass_file_encryption", 10)], now=NOW)
    assert result.risk_score == pytest.approx(40.0)
    assert result.risk_level == RiskLevel.MEDIUM


def test_severity_scales_the_score():
    # failed_login weight 5 * (severity 5 / 10) = 2.5
    result = RiskScorer().assess([make_event("failed_login", 5)], now=NOW)
    assert result.risk_score == pytest.approx(2.5)


def test_unknown_event_type_uses_default_weight():
    # default weight 8 * (10 / 10) = 8
    result = RiskScorer().assess([make_event("weird_new_event", 10)], now=NOW)
    assert result.risk_score == pytest.approx(8.0)


@pytest.mark.parametrize(
    "minutes_ago, expected_score",
    [
        (0, 40.0),        # brand new: full weight
        (10, 40.0),       # exactly at the 10-minute boundary: full weight
        (11, 28.0),       # last hour: 70%
        (300, 16.0),      # last 24 hours: 40%
        (4320, 4.0),      # 3 days old: 10%
        (-5, 40.0),       # "from the future" counts as brand new
    ],
)
def test_recency_reduces_score_of_older_events(minutes_ago, expected_score):
    event = make_event("mass_file_encryption", 10, minutes_ago=minutes_ago)
    result = RiskScorer().assess([event], now=NOW)
    assert result.risk_score == pytest.approx(expected_score)


def test_encryption_plus_backup_deletion_gets_correlation_bonus():
    # 36 (encryption) + 28 (deletion) + 20 (correlation bonus) = 84
    result = RiskScorer().assess(ransomware_events(), now=NOW)
    assert result.risk_score == pytest.approx(84.0)
    assert result.risk_level == RiskLevel.CRITICAL
    assert any("Correlated" in factor for factor in result.factors)


def test_many_different_event_types_get_diversity_bonus():
    # 5 + 15 + 8 = 28, plus the 10-point diversity bonus = 38
    events = [
        make_event("failed_login", 10),
        make_event("suspicious_process", 10),
        make_event("weird_new_event", 10),
    ]
    result = RiskScorer().assess(events, now=NOW)
    assert result.risk_score == pytest.approx(38.0)


def test_score_is_capped_at_100():
    events = [
        make_event("mass_file_encryption", 10),
        make_event("ransomware_note_detected", 10),
        make_event("backup_deletion_attempt", 10),
    ]
    result = RiskScorer().assess(events, now=NOW)
    assert result.risk_score == 100.0
    assert result.risk_level == RiskLevel.CRITICAL


def test_naive_timestamps_are_treated_as_utc():
    naive_event = SecurityEvent(
        "evt-naive", datetime(2026, 9, 28, 12, 0), "file_monitor",
        "mass_file_encryption", 10,
    )
    result = RiskScorer().assess([naive_event], now=NOW)
    assert result.risk_score == pytest.approx(40.0)


# ---------------------------------------------------------------------------
# Tests for decision_engine.py
# ---------------------------------------------------------------------------

def test_no_events_means_allow():
    decision = DecisionEngine().decide([], now=NOW)
    assert decision.action == ResponseAction.ALLOW
    assert decision.confidence == 0.95
    assert decision.actions_to_execute == []


def test_low_risk_means_allow():
    decision = DecisionEngine().decide([make_event("failed_login", 5)], now=NOW)
    assert decision.action == ResponseAction.ALLOW
    assert decision.risk_assessment.risk_level == RiskLevel.LOW


def test_medium_risk_means_alert():
    # A lone encryption event scores 40 (MEDIUM). Damage is detected, but
    # recovery only triggers at HIGH or CRITICAL, so the answer is ALERT.
    decision = DecisionEngine().decide(
        [make_event("mass_file_encryption", 10)], now=NOW
    )
    assert decision.action == ResponseAction.ALERT
    assert decision.risk_assessment.risk_score == pytest.approx(40.0)
    assert "notify_security_team" in decision.actions_to_execute


def test_backup_attack_escalates_low_risk_to_protect():
    # backup_deletion_attempt at severity 6 scores only 21 (LOW),
    # but attacks on backups must be at least PROTECT.
    decision = DecisionEngine().decide(
        [make_event("backup_deletion_attempt", 6)], now=NOW
    )
    assert decision.risk_assessment.risk_level == RiskLevel.LOW
    assert decision.action == ResponseAction.PROTECT
    assert "lock_backup_vault" in decision.actions_to_execute


def test_high_risk_without_damage_means_protect():
    # 25 + 25 + 15 (correlation) = 65 -> HIGH
    events = [
        make_event("privilege_escalation", 10, source="ad_monitor"),
        make_event("lateral_movement", 10, source="ad_monitor"),
    ]
    decision = DecisionEngine().decide(events, now=NOW)
    assert decision.risk_assessment.risk_level == RiskLevel.HIGH
    assert decision.action == ResponseAction.PROTECT
    assert decision.confidence == pytest.approx(0.75)


def test_critical_risk_without_damage_means_isolate():
    events = [
        make_event("privilege_escalation", 10),
        make_event("lateral_movement", 10),
        make_event("backup_tampering", 10),
    ]
    decision = DecisionEngine().decide(events, now=NOW)
    assert decision.risk_assessment.risk_level == RiskLevel.CRITICAL
    assert decision.action == ResponseAction.ISOLATE
    assert "disconnect_affected_systems_from_network" in decision.actions_to_execute


def test_damage_with_safe_backup_means_recover():
    backups = [make_backup("bkp-1", hours_before=2)]
    decision = DecisionEngine().decide(ransomware_events(), backups, now=NOW)

    assert decision.action == ResponseAction.RECOVER
    steps = decision.actions_to_execute
    assert "restore_from_backup:bkp-1" in steps
    # The restore step must come right before the final verification step.
    assert steps[-2] == "restore_from_backup:bkp-1"
    assert steps[-1] == "verify_system_after_restore"


def test_recover_picks_newest_safe_backup():
    backups = [
        make_backup("old", hours_before=5),
        make_backup("newer", hours_before=1),
    ]
    decision = DecisionEngine().decide(ransomware_events(), backups, now=NOW)
    assert "restore_from_backup:newer" in decision.actions_to_execute


def test_recover_skips_untrusted_and_unverified_backups():
    backups = [
        make_backup("untrusted", hours_before=1, trusted=False),
        make_backup("unverified", hours_before=1, verified=False),
        make_backup("good", hours_before=3),
    ]
    decision = DecisionEngine().decide(ransomware_events(), backups, now=NOW)
    assert "restore_from_backup:good" in decision.actions_to_execute


def test_damage_with_no_backups_means_isolate():
    decision = DecisionEngine().decide(ransomware_events(), [], now=NOW)
    assert decision.action == ResponseAction.ISOLATE
    assert "NO safe backup" in decision.reason


def test_backups_none_is_handled():
    decision = DecisionEngine().decide(ransomware_events(), None, now=NOW)
    assert decision.action == ResponseAction.ISOLATE


def test_backup_made_after_attack_started_is_not_used():
    # hours_before=-1 means the backup was created AFTER the attack began.
    backups = [make_backup("too-late", hours_before=-1)]
    decision = DecisionEngine().decide(ransomware_events(), backups, now=NOW)
    assert decision.action == ResponseAction.ISOLATE


def test_only_unsafe_backups_means_isolate():
    backups = [make_backup("bad", hours_before=2, trusted=False)]
    decision = DecisionEngine().decide(ransomware_events(), backups, now=NOW)
    assert decision.action == ResponseAction.ISOLATE


def test_confidence_rises_with_independent_sources():
    # CRITICAL base 0.85, plus 0.03 for the second distinct source.
    decision = DecisionEngine().decide(ransomware_events(), [], now=NOW)
    assert decision.confidence == pytest.approx(0.88)


def test_decision_records_triggering_events():
    events = ransomware_events()
    decision = DecisionEngine().decide(events, [], now=NOW)
    assert decision.triggering_events == events


def test_engine_does_not_modify_the_action_steps_template():
    backups = [make_backup("bkp-1", hours_before=2)]
    DecisionEngine().decide(ransomware_events(), backups, now=NOW)
    # The shared template must never gain a restore step.
    assert not any(
        step.startswith("restore_from_backup")
        for step in ACTION_STEPS[ResponseAction.RECOVER]
    )


def test_naive_datetimes_do_not_crash_the_engine():
    naive_now = datetime(2026, 9, 28, 12, 0)  # no timezone
    events = [
        SecurityEvent("e1", naive_now, "file_monitor", "mass_file_encryption", 9),
        SecurityEvent("e2", naive_now, "backup_agent", "backup_deletion_attempt", 8),
    ]
    backups = [
        BackupStatus("bkp-1", naive_now - timedelta(hours=2), True, True, "/b")
    ]
    decision = DecisionEngine().decide(events, backups, now=NOW)
    assert decision.action == ResponseAction.RECOVER


# ---------------------------------------------------------------------------
# Tests for decision_logger.py
# ---------------------------------------------------------------------------
# `tmp_path` is a built-in pytest feature: a temporary folder that is
# created for the test and cleaned up afterwards, so your real logs/
# folder is never touched.

def _make_decision() -> Decision:
    return DecisionEngine().decide(ransomware_events(), [], now=NOW)


def test_logger_keeps_decisions_in_memory(tmp_path):
    audit = DecisionLogger(log_file=str(tmp_path / "audit.jsonl"))
    decision = _make_decision()
    audit.log(decision)

    assert audit.get_history() == [decision]
    assert audit.get_recent(1) == [decision]
    assert audit.get_by_id(decision.decision_id) == decision
    assert audit.get_by_id("does-not-exist") is None


def test_logger_writes_one_json_line_per_decision(tmp_path):
    audit = DecisionLogger(log_file=str(tmp_path / "audit.jsonl"))
    first, second = _make_decision(), _make_decision()
    audit.log(first)
    audit.log(second)

    records = audit.read_file_history()
    assert len(records) == 2
    assert records[0]["decision_id"] == first.decision_id
    assert records[0]["action"] == "ISOLATE"
    assert records[1]["decision_id"] == second.decision_id


def test_logger_trims_memory_but_keeps_everything_in_file(tmp_path):
    audit = DecisionLogger(log_file=str(tmp_path / "audit.jsonl"), max_in_memory=2)
    for _ in range(3):
        audit.log(_make_decision())

    assert len(audit.get_history()) == 2
    assert len(audit.read_file_history()) == 3


def test_logger_can_run_in_memory_only():
    audit = DecisionLogger(log_file=None)
    audit.log(_make_decision())
    assert len(audit.get_history()) == 1
    assert audit.read_file_history() == []