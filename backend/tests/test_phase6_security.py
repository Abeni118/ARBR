from datetime import datetime, timezone
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database.session import get_db
from app.main import app
from app.models import Asset, AuditEvent, Base, ThreatIncident


TEST_COMPONENT_TOKEN = "test-only-component-token"
TEST_USER_TOKENS = {
    "viewer": "test-only-viewer-token",
    "analyst": "test-only-analyst-token",
    "approver": "test-only-approver-token",
    "same_user_approver": "test-only-same-user-approver-token",
    "admin": "test-only-admin-token",
}


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
    users = [
        {"token": TEST_USER_TOKENS["viewer"], "user_id": "viewer-1", "role": "viewer"},
        {"token": TEST_USER_TOKENS["analyst"], "user_id": "analyst-1", "role": "analyst"},
        {"token": TEST_USER_TOKENS["approver"], "user_id": "approver-1", "role": "approver"},
        {"token": TEST_USER_TOKENS["same_user_approver"], "user_id": "analyst-1", "role": "approver"},
        {"token": TEST_USER_TOKENS["admin"], "user_id": "admin-1", "role": "admin"},
    ]
    monkeypatch.setenv("MVP_USER_TOKENS", json.dumps(users))
    monkeypatch.setenv("BACKUP_COMPONENT_TOKEN", TEST_COMPONENT_TOKEN)

    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _auth(role: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {TEST_USER_TOKENS[role]}"}


def _make_asset(db: Session) -> Asset:
    asset = Asset(hostname="phase6-security-test-host")
    db.add(asset)
    db.commit()
    return asset


def test_authentication_fails_closed_and_public_infrastructure_stays_public(client: TestClient):
    assert client.get("/").status_code == 200
    assert client.get("/api/health").status_code == 200
    assert client.get("/docs").status_code == 200
    openapi = client.get("/openapi.json")
    assert openapi.status_code == 200
    openapi_document = openapi.json()
    assert "HTTPBearer" in openapi_document["components"]["securitySchemes"]
    assert openapi_document["paths"]["/api/assets"]["get"]["security"]

    missing = client.get("/api/assets")
    invalid = client.get("/api/assets", headers={"Authorization": "Bearer wrong-test-token"})
    assert missing.status_code == 401
    assert missing.json()["detail"]["code"] == "authentication_required"
    assert invalid.status_code == 401
    assert invalid.json()["detail"]["code"] == "invalid_authentication"
    for response in (missing, invalid):
        assert TEST_USER_TOKENS["analyst"] not in response.text
        assert TEST_COMPONENT_TOKEN not in response.text

    unauthenticated_write = client.post("/api/action-requests", json={"action_type": "isolate"})
    assert unauthenticated_write.status_code == 401


def test_all_browser_read_surfaces_require_authentication(client: TestClient):
    asset_id = "5e08e898-8f56-4d93-8a0c-4b38101c14ee"
    protected_reads = (
        "/api/assets",
        "/api/security-events",
        "/api/security-events/summary",
        "/api/threats",
        "/api/threats/summary",
        "/api/risk-assessments",
        "/api/decisions",
        "/api/action-requests",
        "/api/backups",
        "/api/integrity-verifications",
        "/api/isolation",
        "/api/recovery-jobs",
        "/api/audit-logs",
        "/api/dashboard/summary",
        "/api/settings",
        "/api/users",
        f"/api/assets/{asset_id}/recovery-points",
        f"/api/assets/{asset_id}/isolation",
    )
    for path in protected_reads:
        response = client.get(path)
        assert response.status_code == 401, (path, response.status_code, response.text)


def test_viewer_reads_but_cannot_write_and_analyst_write_is_audited(client: TestClient, db: Session):
    asset = _make_asset(db)
    assert client.get("/api/assets", headers=_auth("viewer")).status_code == 200

    forbidden = client.post(
        "/api/assets",
        headers=_auth("viewer"),
        json={"hostname": "viewer-cannot-create"},
    )
    assert forbidden.status_code == 403
    assert forbidden.json()["detail"] == {"code": "forbidden", "message": "Insufficient permissions"}
    assert TEST_USER_TOKENS["analyst"] not in forbidden.text
    denial_audit = db.scalar(
        select(AuditEvent).where(
            AuditEvent.action == "authorization.denied",
            AuditEvent.actor_id == "viewer-1",
        )
    )
    assert denial_audit is not None

    created = client.post(
        "/api/assets",
        headers=_auth("analyst"),
        json={"hostname": "analyst-created-host"},
    )
    assert created.status_code == 201, created.text
    audit = db.scalar(
        select(AuditEvent).where(
            AuditEvent.action == "asset.created",
            AuditEvent.asset_id == created.json()["id"],
        )
    )
    assert audit is not None
    assert audit.actor_type == "user"
    assert audit.actor_id == "analyst-1"

    incident = ThreatIncident(
        title="Phase 6 analyst lifecycle test",
        threat_type="test",
        asset_id=asset.id,
        detected_at=datetime.now(timezone.utc),
        correlation_id="3da689f6-4f9d-4289-8893-277594203bb1",
    )
    db.add(incident)
    db.commit()
    triaged = client.post(f"/api/threats/{incident.id}/triage", headers=_auth("analyst"))
    assert triaged.status_code == 200
    transition_audit = db.scalar(
        select(AuditEvent).where(
            AuditEvent.action == "threat_incident.lifecycle_change",
            AuditEvent.incident_id == incident.id,
        )
    )
    assert transition_audit.actor_id == "analyst-1"


def test_request_actor_is_server_derived_and_approval_is_role_separated(client: TestClient, db: Session):
    asset = _make_asset(db)
    request = client.post(
        "/api/action-requests",
        headers=_auth("analyst"),
        json={
            "action_type": "isolate",
            "asset_id": asset.id,
            "isolation_mode": "network",
            "requested_by_type": "admin",
            "requested_by_id": "admin-pretender",
            "request_reason": "Contain a test asset",
        },
    )
    assert request.status_code == 201, request.text
    action_request = request.json()
    assert action_request["requested_by_type"] == "user"
    assert action_request["requested_by_id"] == "analyst-1"

    analyst_cannot_approve = client.post(
        f"/api/action-requests/{action_request['id']}/approve",
        headers=_auth("analyst"),
        json={"approved_by_id": "admin-pretender"},
    )
    assert analyst_cannot_approve.status_code == 403
    analyst_cannot_reject = client.post(
        f"/api/action-requests/{action_request['id']}/reject",
        headers=_auth("analyst"),
        json={"rejected_by_id": "admin-pretender", "reason": "Not authorized"},
    )
    assert analyst_cannot_reject.status_code == 403

    self_approval = client.post(
        f"/api/action-requests/{action_request['id']}/approve",
        headers=_auth("same_user_approver"),
        json={"approved_by_id": "some-other-user"},
    )
    assert self_approval.status_code == 409
    assert self_approval.json()["detail"]["code"] == "requester_cannot_approve"
    self_rejection = client.post(
        f"/api/action-requests/{action_request['id']}/reject",
        headers=_auth("same_user_approver"),
        json={"rejected_by_id": "some-other-user", "reason": "Attempted self-rejection"},
    )
    assert self_rejection.status_code == 409
    assert self_rejection.json()["detail"]["code"] == "requester_cannot_approve"

    approved = client.post(
        f"/api/action-requests/{action_request['id']}/approve",
        headers=_auth("approver"),
        json={"approved_by_id": "spoofed-admin-id"},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["approved_by_id"] == "approver-1"
    approval_audit = db.scalar(
        select(AuditEvent).where(
            AuditEvent.action == "isolation.approved",
            AuditEvent.action_request_id == action_request["id"],
        )
    )
    assert approval_audit.actor_id == "approver-1"


def test_approver_can_reject_but_cannot_impersonate_requester(client: TestClient, db: Session):
    asset = _make_asset(db)
    request = client.post(
        "/api/action-requests",
        headers=_auth("analyst"),
        json={
            "action_type": "recover",
            "asset_id": asset.id,
            "incident_id": "7bffb07e-0c4c-4aac-ae30-8a6f44f8221a",
            "backup_id": "80be491e-e27d-46de-a12e-852170132ec3",
            "verification_id": "136a10f8-79a6-42dc-9e04-1f319ca69fc2",
            "requested_by_id": "spoofed-requester",
        },
    )
    # The unavailable related records are rejected before an ActionRequest is created.
    assert request.status_code == 404

    simple_request = client.post(
        "/api/action-requests",
        headers=_auth("analyst"),
        json={
            "action_type": "isolate",
            "asset_id": asset.id,
            "isolation_mode": "network",
        },
    ).json()
    rejected = client.post(
        f"/api/action-requests/{simple_request['id']}/reject",
        headers=_auth("approver"),
        json={"rejected_by_id": "spoofed-actor", "reason": "Not approved"},
    )
    assert rejected.status_code == 200
    assert rejected.json()["approval_status"] == "rejected"
    rejection_audit = db.scalar(
        select(AuditEvent).where(
            AuditEvent.action == "isolation.rejected",
            AuditEvent.action_request_id == simple_request["id"],
        )
    )
    assert rejection_audit.actor_id == "approver-1"


def test_internal_component_routes_keep_component_auth(client: TestClient, db: Session):
    asset = _make_asset(db)
    payload = {
        "asset_id": asset.id,
        "created_by_component": "backup-agent-test",
        "external_backup_id": "phase6-backup-001",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "backup_type": "full",
        "size_bytes": 1024,
        "protection_status": "unknown",
        "lifecycle_status": "available",
        "encryption_status": "encrypted",
    }
    user_bearer_is_not_component_auth = client.post(
        "/api/internal/backups",
        headers=_auth("admin"),
        json=payload,
    )
    assert user_bearer_is_not_component_auth.status_code == 401
    assert TEST_COMPONENT_TOKEN not in user_bearer_is_not_component_auth.text

    registered = client.post(
        "/api/internal/backups",
        headers={"X-Internal-Component-Token": TEST_COMPONENT_TOKEN},
        json=payload,
    )
    assert registered.status_code == 201, registered.text
    assert registered.json()["asset_id"] == asset.id
