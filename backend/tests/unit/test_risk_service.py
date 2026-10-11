from backend.app.risk import RiskService


def test_risk_service_assesses_security_event():
    service = RiskService()

    assessment = service.assess(
        event_id="event-100",
        host_id="host-10",
        indicators={
            "mass_file_encryption": True,
            "mass_file_modification": True,
        },
    )

    assert assessment.event_id == "event-100"
    assert assessment.host_id == "host-10"
    assert assessment.risk_score == 65.0
    assert assessment.risk_level == "HIGH"
    assert assessment.threat_type == "ransomware_behavior"