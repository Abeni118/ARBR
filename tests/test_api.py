"""
test_api.py - Automated tests for the HTTP endpoints in api.py.

These tests use FastAPI's TestClient, which pretends to be a web browser
and calls your endpoints directly. No server needs to be running, and no
real network is involved.

Important: each test gets a FRESH audit logger that writes into a
temporary folder. That way the tests never touch your real
logs/decision_audit.jsonl and never see each other's records.

Run from the PROJECT ROOT:

    python -m pytest -v
"""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from backend.app.decision import DecisionLogger, api


# ---------------------------------------------------------------------------
# Fixtures (setup code that pytest runs before each test that asks for it)
# ---------------------------------------------------------------------------

@pytest.fixture
def audit_log(tmp_path, monkeypatch):
    """Replace the API's audit logger with a temporary one.

    monkeypatch.setattr swaps `api.audit` for the duration of ONE test
    and puts the original back afterwards, automatically.
    """
    fresh = DecisionLogger(log_file=str(tmp_path / "audit.jsonl"))
    monkeypatch.setattr(api, "audit", fresh)
    return fresh


@pytest.fixture
def client(audit_log):
    """A test client for the API (depends on audit_log, so it is safe)."""
    return TestClient(api.app)


# ---------------------------------------------------------------------------
# Helpers (build request bodies quickly)
# ---------------------------------------------------------------------------

def ransomware_events() -> list:
    """Two events from different sources; the engine scores them 84.0.

    No timestamp is given, so the API treats them as happening right now.
    """
    return [
        {"event_id": "e1", "source": "file_monitor",
         "event_type": "mass_file_encryption", "severity": 9},
        {"event_id": "e2", "source": "backup_agent",
         "event_type": "backup_deletion_attempt", "severity": 8},
    ]


def backup(backup_id: str, hours_ago: float,
           verified: bool = True, trusted: bool = True) -> dict:
    """A backup made `hours_ago` hours ago, as a JSON-ready dictionary."""
    made_at = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return {
        "backup_id": backup_id,
        "timestamp": made_at.isoformat(),
        "integrity_verified": verified,
        "trusted": trusted,
        "location": f"/backups/{backup_id}",
    }


# ---------------------------------------------------------------------------
# GET /decision/health
# ---------------------------------------------------------------------------

def test_health_endpoint(client):
    response = client.get("/decision/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# POST /decision/evaluate - normal behaviour
# ---------------------------------------------------------------------------

def test_empty_request_means_allow(client):
    response = client.post("/decision/evaluate", json={})
    body = response.json()
    assert response.status_code == 200
    assert body["action"] == "ALLOW"
    assert body["risk_assessment"]["risk_score"] == 0
    assert body["actions_to_execute"] == []


def test_response_contains_all_decision_fields(client):
    body = client.post("/decision/evaluate", json={}).json()
    expected_keys = {
        "decision_id", "timestamp", "action", "reason",
        "triggering_events", "risk_assessment", "confidence",
        "actions_to_execute",
    }
    assert expected_keys <= set(body.keys())


def test_ransomware_with_safe_backup_means_recover(client):
    payload = {"events": ransomware_events(), "backups": [backup("bkp-1", 2)]}
    body = client.post("/decision/evaluate", json=payload).json()

    assert body["action"] == "RECOVER"
    assert body["risk_assessment"]["risk_score"] == pytest.approx(84.0)
    assert body["risk_assessment"]["risk_level"] == "CRITICAL"
    assert body["confidence"] == pytest.approx(0.88)
    assert "restore_from_backup:bkp-1" in body["actions_to_execute"]


def test_ransomware_without_backups_means_isolate(client):
    payload = {"events": ransomware_events()}
    body = client.post("/decision/evaluate", json=payload).json()
    assert body["action"] == "ISOLATE"
    assert "NO safe backup" in body["reason"]


def test_untrusted_backup_is_not_used(client):
    payload = {
        "events": ransomware_events(),
        "backups": [backup("bad", 2, trusted=False)],
    }
    body = client.post("/decision/evaluate", json=payload).json()
    assert body["action"] == "ISOLATE"


def test_events_are_echoed_back_as_triggering_events(client):
    payload = {"events": ransomware_events()}
    body = client.post("/decision/evaluate", json=payload).json()
    ids = [event["event_id"] for event in body["triggering_events"]]
    assert ids == ["e1", "e2"]


def test_missing_timestamp_is_filled_with_current_time(client):
    payload = {"events": ransomware_events()}
    body = client.post("/decision/evaluate", json=payload).json()
    assert body["triggering_events"][0]["timestamp"] is not None


def test_old_events_produce_a_low_score(client):
    # 3 days old -> only 10% weight: 40 * 1.0 * 0.1 = 4.0 -> LOW -> ALLOW
    three_days_ago = datetime.now(timezone.utc) - timedelta(days=3)
    payload = {"events": [{
        "event_id": "old", "source": "file_monitor",
        "event_type": "mass_file_encryption", "severity": 10,
        "timestamp": three_days_ago.isoformat(),
    }]}
    body = client.post("/decision/evaluate", json=payload).json()
    assert body["risk_assessment"]["risk_score"] == pytest.approx(4.0)
    assert body["action"] == "ALLOW"


def test_timestamps_without_timezone_are_accepted(client):
    # Naive timestamps (no "Z" or "+00:00") are treated as UTC.
    now_naive = datetime.now(timezone.utc).replace(tzinfo=None)
    two_hours_ago_naive = now_naive - timedelta(hours=2)
    payload = {
        "events": [
            {**event, "timestamp": now_naive.isoformat()}
            for event in ransomware_events()
        ],
        "backups": [{
            "backup_id": "naive-bkp",
            "timestamp": two_hours_ago_naive.isoformat(),
            "integrity_verified": True,
            "trusted": True,
            "location": "/backups/naive-bkp",
        }],
    }
    response = client.post("/decision/evaluate", json=payload)
    assert response.status_code == 200
    assert response.json()["action"] == "RECOVER"


# ---------------------------------------------------------------------------
# POST /decision/evaluate - bad input must be rejected (HTTP 422)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad_severity", [0, 11, 15, -1])
def test_out_of_range_severity_is_rejected(client, bad_severity):
    payload = {"events": [{
        "event_id": "e1", "source": "s",
        "event_type": "failed_login", "severity": bad_severity,
    }]}
    response = client.post("/decision/evaluate", json=payload)
    assert response.status_code == 422


def test_missing_required_field_is_rejected(client):
    # "event_type" is missing.
    payload = {"events": [{"event_id": "e1", "source": "s", "severity": 5}]}
    response = client.post("/decision/evaluate", json=payload)
    assert response.status_code == 422


def test_wrong_data_type_is_rejected(client):
    response = client.post("/decision/evaluate", json={"events": "not a list"})
    assert response.status_code == 422


def test_rejected_request_is_not_logged(client, audit_log):
    client.post("/decision/evaluate", json={"events": "not a list"})
    assert audit_log.get_history() == []


# ---------------------------------------------------------------------------
# Audit trail and GET /decision/history
# ---------------------------------------------------------------------------

def test_evaluate_writes_to_the_audit_log(client, audit_log):
    body = client.post("/decision/evaluate", json={"events": ransomware_events()}).json()

    assert len(audit_log.get_history()) == 1
    saved = audit_log.read_file_history()
    assert len(saved) == 1
    assert saved[0]["decision_id"] == body["decision_id"]


def test_history_starts_empty(client):
    response = client.get("/decision/history")
    assert response.status_code == 200
    assert response.json() == []


def test_history_returns_newest_last(client):
    ids = [
        client.post("/decision/evaluate", json={}).json()["decision_id"]
        for _ in range(3)
    ]
    body = client.get("/decision/history?limit=2").json()
    assert [item["decision_id"] for item in body] == ids[-2:]


def test_history_limit_is_kept_at_least_one(client):
    for _ in range(2):
        client.post("/decision/evaluate", json={})
    # limit=0 is silently raised to 1 by the endpoint.
    assert len(client.get("/decision/history?limit=0").json()) == 1