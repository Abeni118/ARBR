from backend.app.risk import RiskEngine, RiskEvent


def test_no_indicators_returns_low_risk():
    event = RiskEvent(
        event_id="event-001",
        host_id="host-01",
        indicators={},
    )

    assessment = RiskEngine().assess(event)

    assert assessment.risk_score == 0.0
    assert assessment.risk_level == "LOW"
    assert assessment.threat_type == "unknown"
    assert assessment.triggered_rules == ()


def test_ransomware_behavior_returns_high_risk():
    event = RiskEvent(
        event_id="event-002",
        host_id="host-01",
        indicators={
            "mass_file_encryption": True,
            "mass_file_modification": True,
        },
    )

    assessment = RiskEngine().assess(event)

    assert assessment.risk_score == 65.0
    assert assessment.risk_level == "HIGH"
    assert assessment.threat_type == "ransomware_behavior"
    assert assessment.triggered_rules == (
        "mass_file_encryption",
        "mass_file_modification",
    )


def test_backup_destruction_increases_risk():
    event = RiskEvent(
        event_id="event-003",
        host_id="host-02",
        indicators={
            "backup_deletion": True,
        },
    )

    assessment = RiskEngine().assess(event)

    assert assessment.risk_score == 35.0
    assert assessment.risk_level == "MEDIUM"
    assert assessment.threat_type == "backup_destruction"
    assert assessment.triggered_rules == ("backup_deletion",)


def test_critical_risk_is_capped_at_100():
    event = RiskEvent(
        event_id="event-004",
        host_id="host-03",
        indicators={
            "mass_file_encryption": True,
            "mass_file_modification": True,
            "backup_deletion": True,
            "privilege_escalation": True,
            "security_service_disabled": True,
        },
    )

    assessment = RiskEngine().assess(event)

    assert assessment.risk_score == 100.0
    assert assessment.risk_level == "CRITICAL"


def test_multiple_threat_indicators_prioritize_ransomware():
    event = RiskEvent(
        event_id="event-005",
        host_id="host-04",
        indicators={
            "mass_file_encryption": True,
            "privilege_escalation": True,
            "security_service_disabled": True,
        },
    )

    assessment = RiskEngine().assess(event)

    assert assessment.risk_level == "CRITICAL"
    assert assessment.threat_type == "ransomware_behavior"
    assert len(assessment.triggered_rules) == 3


def test_event_context_is_preserved():
    event = RiskEvent(
        event_id="event-006",
        host_id="host-05",
        indicators={
            "suspicious_process": True,
        },
    )

    assessment = RiskEngine().assess(event)

    assert assessment.event_id == "event-006"
    assert assessment.host_id == "host-05"