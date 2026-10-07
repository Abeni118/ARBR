from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database.session import get_db
from app.main import app
from app.models import ActionRequest, Asset, AuditEvent, Base, Decision, IsolationAction, RiskAssessment, ThreatIncident


COMPONENT_TOKEN = "phase4-isolation-component-test-token"


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        yield session
    engine.dispose()


@pytest.fixture
def client(db: Session, monkeypatch):
    monkeypatch.setenv("BACKUP_COMPONENT_TOKEN", COMPONENT_TOKEN)

    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _isolation_request(client: TestClient, asset_id: str, *, incident_id=None, decision_id=None, correlation_id=None, extra=None):
    body = {
            "action_type": "isolate",
            "asset_id": asset_id,
            "incident_id": incident_id,
            "decision_id": decision_id,
            "isolation_mode": "network",
            "requested_by_type": "user",
            "requested_by_id": "operator-4",
            "request_reason": "Contain suspicious endpoint activity",
            "correlation_id": correlation_id,
        }
    body.update(extra or {})
    return client.post("/api/action-requests", json=body)


def _create_isolation(client: TestClient, action_request: dict, asset_id: str, **overrides):
    body = {
        "action_request_id": action_request["id"],
        "asset_id": asset_id,
        "isolation_mode": "network",
        "reason": "Dispatch approved isolation workflow",
        "correlation_id": action_request["correlation_id"],
    }
    body.update(overrides)
    return client.post("/api/isolation-requests", json=body)


def _component_result(client: TestClient, isolation_action_id: str, *, status_value: str, network_state: str, correlation_id: str, component_reference: str = "isolation-job-001", **extra):
    return client.post(
        f"/api/internal/isolation/{isolation_action_id}/result",
        headers={"X-Internal-Component-Token": COMPONENT_TOKEN},
        json={
            "execution_status": status_value,
            "network_state": network_state,
            "component_reference": component_reference,
            "correlation_id": correlation_id,
            **extra,
        },
    )


def test_isolation_approval_confirmed_result_and_idempotency(client: TestClient, db: Session):
    asset = Asset(hostname="phase4-isolation-host")
    db.add(asset)
    db.commit()
    correlation_id = str(uuid4())

    invalid_mode = client.post(
        "/api/action-requests",
        json={
            "action_type": "isolate",
            "asset_id": asset.id,
            "isolation_mode": "remote_shell",
            "requested_by_type": "user",
        },
    )
    assert invalid_mode.status_code == 422

    action_request_response = _isolation_request(
        client,
        asset.id,
        correlation_id=correlation_id,
        extra={"network_state": "isolated", "execution_status": "isolated"},
    )
    assert action_request_response.status_code == 201, action_request_response.text
    action_request = action_request_response.json()
    assert action_request["action_type"] == "isolate"
    assert action_request["approval_status"] == "pending"
    assert action_request["execution_status"] == "not_started"
    assert action_request["correlation_id"] == correlation_id

    created = _create_isolation(client, action_request, asset.id)
    assert created.status_code == 201, created.text
    isolation_action = created.json()
    isolation_id = isolation_action["isolation_action_id"]
    assert isolation_action["execution_status"] == "awaiting_approval"
    assert isolation_action["network_state"] == "unknown"
    assert isolation_action["correlation_id"] == correlation_id
    assert client.get(f"/api/assets/{asset.id}/isolation").json()["isolation_state"] == "isolation_pending"

    unauthenticated = client.post(
        f"/api/internal/isolation/{isolation_id}/result",
        json={
            "execution_status": "executing",
            "network_state": "isolating",
            "component_reference": "isolation-job-001",
            "correlation_id": correlation_id,
        },
    )
    assert unauthenticated.status_code == 401
    not_approved = _component_result(
        client,
        isolation_id,
        status_value="executing",
        network_state="isolating",
        correlation_id=correlation_id,
    )
    assert not_approved.status_code == 409
    assert not_approved.json()["detail"]["code"] == "action_request_not_approved"

    approved = client.post(
        f"/api/action-requests/{action_request['id']}/approve",
        json={"approved_by_id": "approver-4"},
    )
    assert approved.status_code == 200
    assert approved.json()["approval_status"] == "approved"
    assert approved.json()["execution_status"] == "not_started"
    assert db.get(IsolationAction, isolation_id).execution_status == "approved"

    executing = _component_result(
        client,
        isolation_id,
        status_value="executing",
        network_state="isolating",
        correlation_id=correlation_id,
    )
    assert executing.status_code == 200, executing.text
    assert executing.json()["execution_status"] == "executing"
    asset_state = client.get(f"/api/assets/{asset.id}/isolation").json()
    assert asset_state["isolation_state"] == "isolation_pending"
    assert asset_state["execution_status"] == "executing"

    event_count = db.scalar(select(func.count(AuditEvent.id)))
    duplicate_executing = _component_result(
        client,
        isolation_id,
        status_value="executing",
        network_state="isolating",
        correlation_id=correlation_id,
    )
    assert duplicate_executing.status_code == 200
    assert db.scalar(select(func.count(AuditEvent.id))) == event_count

    confirmed = _component_result(
        client,
        isolation_id,
        status_value="isolated",
        network_state="isolated",
        correlation_id=correlation_id,
        acknowledged_at=datetime.now(timezone.utc).isoformat(),
        completed_at=datetime.now(timezone.utc).isoformat(),
    )
    assert confirmed.status_code == 200, confirmed.text
    assert confirmed.json()["execution_status"] == "isolated"
    assert client.get(f"/api/assets/{asset.id}/isolation").json()["isolation_state"] == "isolated"
    assert db.get(ActionRequest, action_request["id"]).execution_status == "succeeded"

    terminal_audit_count = db.scalar(select(func.count(AuditEvent.id)))
    duplicate_confirmed = _component_result(
        client,
        isolation_id,
        status_value="isolated",
        network_state="isolated",
        correlation_id=correlation_id,
        component_reference="isolation-job-001",
    )
    assert duplicate_confirmed.status_code == 200
    assert db.scalar(select(func.count(AuditEvent.id))) == terminal_audit_count

    invalid_transition = _component_result(
        client,
        isolation_id,
        status_value="failed",
        network_state="unknown",
        correlation_id=correlation_id,
        failure_reason="late conflicting result",
        component_reference="isolation-job-conflict",
    )
    assert invalid_transition.status_code == 409
    assert invalid_transition.json()["detail"]["code"] == "invalid_state_transition"
    impossible_release = _component_result(
        client,
        isolation_id,
        status_value="released",
        network_state="connected",
        correlation_id=correlation_id,
        component_reference="isolation-job-001",
    )
    assert impossible_release.status_code == 409
    assert impossible_release.json()["detail"]["code"] == "invalid_state_transition"

    another_request = _isolation_request(client, asset.id)
    assert another_request.status_code == 201
    duplicate_active = _create_isolation(client, another_request.json(), asset.id)
    assert duplicate_active.status_code == 409
    assert duplicate_active.json()["detail"]["code"] == "isolation_already_active"

    listing = client.get("/api/isolation", params={"asset_id": asset.id, "execution_status": "isolated", "isolation_mode": "network"})
    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    assert client.get(f"/api/isolation/{isolation_id}").json()["isolation_action_id"] == isolation_id

    audit_actions = set(db.scalars(select(AuditEvent.action)).all())
    assert {
        "isolation.requested",
        "isolation.approval_requested",
        "isolation.dispatch_requested",
        "isolation.approved",
        "isolation.started",
        "isolation.succeeded",
    } <= audit_actions
    relevant_audit = db.query(AuditEvent).filter(AuditEvent.isolation_action_id == isolation_id).all()
    assert relevant_audit
    assert all(item.correlation_id == correlation_id for item in relevant_audit)


def test_failed_isolation_never_confirms_asset_and_incident_contains_only_after_confirmed(client: TestClient, db: Session):
    asset = Asset(hostname="phase4-failed-host")
    second_asset = Asset(hostname="phase4-other-affected-host")
    db.add_all([asset, second_asset])
    db.commit()
    incident = ThreatIncident(
        title="Containment test",
        threat_type="endpoint_activity",
        asset_id=asset.id,
        detected_at=datetime.now(timezone.utc),
        lifecycle_status="investigating",
        correlation_id=str(uuid4()),
        affected_assets=[second_asset],
    )
    db.add(incident)
    db.commit()

    assessment = RiskAssessment(
        incident_id=incident.id,
        asset_id=asset.id,
        score=90,
        risk_level="CRITICAL",
        status="completed",
        assessed_at=datetime.now(timezone.utc),
        correlation_id=incident.correlation_id,
    )
    db.add(assessment)
    db.commit()
    decision = Decision(
        incident_id=incident.id,
        assessment_id=assessment.id,
        asset_id=asset.id,
        recommended_actions=["isolate"],
        rationale="Contain active threat",
        approval_required=True,
        decision_status="proposed",
        correlation_id=incident.correlation_id,
    )
    db.add(decision)
    db.commit()

    action_request_response = _isolation_request(
        client,
        asset.id,
        incident_id=incident.id,
        decision_id=decision.id,
        correlation_id=incident.correlation_id,
    )
    assert action_request_response.status_code == 201, action_request_response.text
    action_request = action_request_response.json()
    assert action_request["decision_id"] == decision.id
    created = _create_isolation(
        client,
        action_request,
        asset.id,
        incident_id=incident.id,
        decision_id=decision.id,
    )
    assert created.status_code == 201, created.text
    isolation_id = created.json()["isolation_action_id"]
    assert client.post(
        f"/api/action-requests/{action_request['id']}/approve",
        json={"approved_by_id": "incident-approver"},
    ).status_code == 200

    failure = _component_result(
        client,
        isolation_id,
        status_value="failed",
        network_state="connected",
        correlation_id=incident.correlation_id,
        failure_reason="Agent could not apply network policy",
        component_reference="isolation-job-failed",
    )
    assert failure.status_code == 200, failure.text
    assert client.get(f"/api/assets/{asset.id}/isolation").json()["isolation_state"] == "not_isolated"
    assert db.get(ThreatIncident, incident.id).lifecycle_status == "investigating"


def test_rejected_isolation_approval_never_dispatches_or_confirms(client: TestClient, db: Session):
    asset = Asset(hostname="phase4-rejected-host")
    db.add(asset)
    db.commit()
    request = _isolation_request(client, asset.id).json()
    isolation_response = _create_isolation(client, request, asset.id)
    isolation_id = isolation_response.json()["isolation_action_id"]

    rejected = client.post(
        f"/api/action-requests/{request['id']}/reject",
        json={"rejected_by_id": "approver-4", "reason": "Containment was not authorized"},
    )
    assert rejected.status_code == 200
    assert rejected.json()["approval_status"] == "rejected"
    assert rejected.json()["execution_status"] == "not_started"
    assert db.get(IsolationAction, isolation_id).execution_status == "cancelled"
    assert client.get(f"/api/assets/{asset.id}/isolation").json()["isolation_state"] == "not_isolated"
    assert db.query(AuditEvent).filter(
        AuditEvent.action == "isolation.rejected",
        AuditEvent.isolation_action_id == isolation_id,
        AuditEvent.correlation_id == request["correlation_id"],
    ).count() == 1


def test_release_requires_review_for_active_incident_then_component_confirmation(client: TestClient, db: Session):
    asset = Asset(hostname="phase4-release-host")
    db.add(asset)
    db.commit()
    incident = ThreatIncident(
        title="Release review test",
        threat_type="endpoint_activity",
        asset_id=asset.id,
        detected_at=datetime.now(timezone.utc),
        lifecycle_status="contained",
        correlation_id=str(uuid4()),
    )
    db.add(incident)
    db.commit()
    # A confirmed isolation without an active incident is used to exercise the release workflow.
    action_request = _isolation_request(client, asset.id).json()
    created = _create_isolation(client, action_request, asset.id)
    isolation_id = created.json()["isolation_action_id"]
    assert client.post(f"/api/action-requests/{action_request['id']}/approve", json={"approved_by_id": "release-test"}).status_code == 200
    correlation_id = action_request["correlation_id"]
    assert _component_result(client, isolation_id, status_value="executing", network_state="isolating", correlation_id=correlation_id).status_code == 200
    assert _component_result(client, isolation_id, status_value="isolated", network_state="isolated", correlation_id=correlation_id).status_code == 200

    release = client.post(
        f"/api/isolation-requests/{isolation_id}/release",
        json={"requested_by_type": "user", "requested_by_id": "operator-4", "reason": "Release after review"},
    )
    assert release.status_code == 201
    release_action = release.json()
    release_id = release_action["isolation_action_id"]
    release_request_id = release_action["action_request_id"]
    assert release_action["operation"] == "release_isolation"
    assert release_action["execution_status"] == "release_requested"
    assert client.get(f"/api/assets/{asset.id}/isolation").json()["isolation_state"] == "release_pending"

    approved = client.post(
        f"/api/action-requests/{release_request_id}/approve",
        json={"approved_by_id": "release-approver"},
    )
    assert approved.status_code == 200
    assert approved.json()["execution_status"] == "not_started"
    assert db.get(IsolationAction, release_id).execution_status == "approved"
    direct_release = _component_result(
        client,
        release_id,
        status_value="released",
        network_state="connected",
        correlation_id=release_action["correlation_id"],
        component_reference="isolation-release-job-1",
    )
    assert direct_release.status_code == 409
    assert direct_release.json()["detail"]["code"] == "invalid_state_transition"
    executing = _component_result(
        client,
        release_id,
        status_value="executing",
        network_state="releasing",
        correlation_id=release_action["correlation_id"],
        component_reference="isolation-release-job-1",
    )
    assert executing.status_code == 200
    assert client.get(f"/api/assets/{asset.id}/isolation").json()["isolation_state"] == "release_pending"

    failed_release_request = client.post(
        f"/api/isolation-requests/{isolation_id}/release",
        json={"requested_by_type": "user", "reason": "Test failed release attempt"},
    )
    assert failed_release_request.status_code == 200
    assert failed_release_request.json()["isolation_action_id"] == release_id

    released = _component_result(
        client,
        release_id,
        status_value="released",
        network_state="connected",
        correlation_id=release_action["correlation_id"],
        component_reference="isolation-release-job-1",
    )
    assert released.status_code == 200, released.text
    state = client.get(f"/api/assets/{asset.id}/isolation").json()
    assert state["isolation_state"] == "not_isolated"
    assert state["active_isolation_action_id"] is None
    assert db.get(ActionRequest, release_request_id).execution_status == "succeeded"
    release_audit_count = db.scalar(
        select(func.count(AuditEvent.id)).where(
            AuditEvent.action == "isolation.released",
            AuditEvent.isolation_action_id == release_id,
        )
    )
    duplicate_release_result = _component_result(
        client,
        release_id,
        status_value="released",
        network_state="connected",
        correlation_id=release_action["correlation_id"],
        component_reference="isolation-release-job-1",
    )
    assert duplicate_release_result.status_code == 200
    assert db.scalar(
        select(func.count(AuditEvent.id)).where(
            AuditEvent.action == "isolation.released",
            AuditEvent.isolation_action_id == release_id,
        )
    ) == release_audit_count

    later_request = _isolation_request(client, asset.id)
    assert later_request.status_code == 201
    later_isolation = _create_isolation(client, later_request.json(), asset.id)
    assert later_isolation.status_code == 201
    later_request_body = later_request.json()
    later_isolation_body = later_isolation.json()
    assert client.post(
        f"/api/action-requests/{later_request_body['id']}/approve",
        json={"approved_by_id": "later-isolation-approver"},
    ).status_code == 200
    later_correlation = later_request_body["correlation_id"]
    assert _component_result(
        client,
        later_isolation_body["isolation_action_id"],
        status_value="executing",
        network_state="isolating",
        correlation_id=later_correlation,
        component_reference="isolation-job-2",
    ).status_code == 200
    assert _component_result(
        client,
        later_isolation_body["isolation_action_id"],
        status_value="isolated",
        network_state="isolated",
        correlation_id=later_correlation,
        component_reference="isolation-job-2",
    ).status_code == 200
    second_release = client.post(
        f"/api/isolation-requests/{later_isolation_body['isolation_action_id']}/release",
        json={"requested_by_type": "user", "reason": "Second release test"},
    ).json()
    assert client.post(
        f"/api/action-requests/{second_release['action_request_id']}/approve",
        json={"approved_by_id": "release-failure-approver"},
    ).status_code == 200
    second_release_id = second_release["isolation_action_id"]
    assert _component_result(
        client,
        second_release_id,
        status_value="executing",
        network_state="releasing",
        correlation_id=second_release["correlation_id"],
        component_reference="isolation-release-job-failed",
    ).status_code == 200
    release_failure = _component_result(
        client,
        second_release_id,
        status_value="failed",
        network_state="isolated",
        correlation_id=second_release["correlation_id"],
        component_reference="isolation-release-job-failed",
        failure_reason="Component could not reconnect the host",
    )
    assert release_failure.status_code == 200
    assert client.get(f"/api/assets/{asset.id}/isolation").json()["isolation_state"] == "isolated"
    assert "isolation.release.failed" in set(db.scalars(select(AuditEvent.action)).all())

    release_audit_actions = set(db.scalars(select(AuditEvent.action)).all())
    assert {
        "isolation.release.requested",
        "isolation.release.approval_requested",
        "isolation.release.approved",
        "isolation.release.started",
        "isolation.released",
    } <= release_audit_actions


def test_incident_relationship_and_release_policy_review(client: TestClient, db: Session):
    asset_a = Asset(hostname="phase4-asset-a")
    asset_b = Asset(hostname="phase4-asset-b")
    db.add_all([asset_a, asset_b])
    db.commit()
    incident = ThreatIncident(
        title="Active security reason",
        threat_type="endpoint_activity",
        asset_id=asset_a.id,
        detected_at=datetime.now(timezone.utc),
        lifecycle_status="investigating",
        correlation_id=str(uuid4()),
    )
    db.add(incident)
    db.commit()

    mismatched_action_request = ActionRequest(
        action_type="isolate",
        incident_id=incident.id,
        asset_id=asset_b.id,
        isolation_mode="network",
        requested_by_type="user",
        approval_status="pending",
        execution_status="not_started",
        correlation_id=incident.correlation_id,
    )
    db.add(mismatched_action_request)
    db.commit()
    mismatched = client.post(
        "/api/isolation-requests",
        json={
            "action_request_id": mismatched_action_request.id,
            "asset_id": asset_b.id,
            "incident_id": incident.id,
            "isolation_mode": "network",
        },
    )
    assert mismatched.status_code == 409
    assert mismatched.json()["detail"]["code"] == "incident_asset_mismatch"

    action_request_response = _isolation_request(
        client,
        asset_a.id,
        incident_id=incident.id,
        correlation_id=incident.correlation_id,
    )
    assert action_request_response.status_code == 201, action_request_response.text
    action_request = action_request_response.json()
    isolation_response = _create_isolation(
        client,
        action_request,
        asset_a.id,
        incident_id=incident.id,
    )
    assert isolation_response.status_code == 201
    isolation_id = isolation_response.json()["isolation_action_id"]
    client.post(f"/api/action-requests/{action_request['id']}/approve", json={"approved_by_id": "review-test"})
    correlation_id = action_request["correlation_id"]
    assert _component_result(client, isolation_id, status_value="executing", network_state="isolating", correlation_id=correlation_id).status_code == 200
    assert _component_result(client, isolation_id, status_value="isolated", network_state="isolated", correlation_id=correlation_id).status_code == 200
    assert db.get(ThreatIncident, incident.id).lifecycle_status == "contained"
    assert db.get(ThreatIncident, incident.id).lifecycle_status != "resolved"

    # Active security state means release must stop for policy review, not guess at policy.
    release_response = client.post(
        f"/api/isolation-requests/{isolation_id}/release",
        json={"requested_by_type": "user", "reason": "Attempt release"},
    )
    assert release_response.status_code == 409
    assert release_response.json()["detail"]["code"] == "policy_requires_review"


def test_phase4_docs_root_health_and_filters(client: TestClient):
    paths = app.openapi()["paths"]
    assert "/api/isolation" in paths
    assert "/api/isolation/{isolation_action_id}" in paths
    assert "/api/assets/{asset_id}/isolation" in paths
    assert "/api/isolation-requests" in paths
    assert "/api/isolation-requests/{isolation_action_id}/release" in paths
    assert "/api/internal/isolation/{isolation_action_id}/result" in paths
    assert paths["/api/isolation"]["get"]["tags"] == ["Isolation"]
    assert paths["/api/action-requests"]["post"]["tags"] == ["Action Requests"]
    assert "/api/action-requests/{action_request_id}/reject" in paths
    assert paths["/api/audit-logs"]["get"]["tags"] == ["Audit Logs"]
    assert paths["/api/internal/isolation/{isolation_action_id}/result"]["post"]["tags"] == [
        "Internal Isolation Component"
    ]
    assert client.get("/").status_code == 200
    assert client.get("/api/health").json() == {"status": "ok"}
    assert client.get("/docs").status_code == 200