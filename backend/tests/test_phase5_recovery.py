from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database.session import get_db
from app.main import app
from app.models import (
    ActionRequest,
    Asset,
    AuditEvent,
    Backup,
    Base,
    Decision,
    IntegrityVerification,
    IsolationAction,
    RecoveryJob,
    ThreatIncident,
)


COMPONENT_TOKEN = "phase5-recovery-component-test-token"


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


def _context(db: Session, *, isolation="isolated", verification_status="passed", verification_age_hours=1, lifecycle="available"):
    asset = Asset(hostname=f"phase5-{uuid4().hex[:8]}")
    other_asset = Asset(hostname=f"phase5-other-{uuid4().hex[:8]}")
    db.add_all([asset, other_asset])
    db.flush()
    incident = ThreatIncident(
        title="Phase 5 recovery incident",
        threat_type="endpoint_activity",
        asset_id=asset.id,
        detected_at=datetime.now(timezone.utc),
        lifecycle_status="contained",
        correlation_id=str(uuid4()),
    )
    db.add(incident)
    backup = Backup(
        asset_id=asset.id,
        source_component="backup-agent",
        external_backup_id=str(uuid4()),
        lifecycle_status=lifecycle,
        protection_status="protected",
        encryption_status="encrypted",
        backup_created_at=datetime.now(timezone.utc),
        correlation_id=incident.correlation_id,
    )
    other_backup = Backup(
        asset_id=asset.id,
        source_component="backup-agent",
        external_backup_id=str(uuid4()),
        lifecycle_status="available",
        protection_status="protected",
        encryption_status="encrypted",
        backup_created_at=datetime.now(timezone.utc),
        correlation_id=incident.correlation_id,
    )
    db.add_all([backup, other_backup])
    db.flush()
    verified_at = datetime.now(timezone.utc) - timedelta(hours=verification_age_hours)
    verification = IntegrityVerification(
        backup_id=backup.id,
        result_status=verification_status,
        expected_digest="trusted-digest",
        observed_digest="observed-digest",
        created_at=verified_at,
        started_at=verified_at,
        completed_at=verified_at if verification_status in {"passed", "failed"} else None,
        correlation_id=incident.correlation_id,
    )
    other_verification = IntegrityVerification(
        backup_id=other_backup.id,
        result_status="passed",
        expected_digest="trusted-other-digest",
        observed_digest="observed-other-digest",
        created_at=verified_at,
        started_at=verified_at,
        completed_at=verified_at,
        correlation_id=incident.correlation_id,
    )
    db.add_all([verification, other_verification])

    if isolation in {"isolated", "released"}:
        isolation_request = ActionRequest(
            action_type="isolate",
            asset_id=asset.id,
            incident_id=incident.id,
            requested_by_type="user",
            approval_status="approved",
            execution_status="succeeded",
            correlation_id=incident.correlation_id,
        )
        db.add(isolation_request)
        db.flush()
        confirmed_isolation = IsolationAction(
            action_request_id=isolation_request.id,
            asset_id=asset.id,
            incident_id=incident.id,
            execution_status="isolated",
            network_state="isolated",
            correlation_id=incident.correlation_id,
        )
        db.add(confirmed_isolation)
        db.flush()
        if isolation == "released":
            release_request = ActionRequest(
                action_type="release_isolation",
                asset_id=asset.id,
                incident_id=incident.id,
                requested_by_type="user",
                approval_status="approved",
                execution_status="succeeded",
                correlation_id=incident.correlation_id,
            )
            db.add(release_request)
            db.flush()
            db.add(
                IsolationAction(
                    action_request_id=release_request.id,
                    parent_isolation_action_id=confirmed_isolation.id,
                    asset_id=asset.id,
                    incident_id=incident.id,
                    execution_status="released",
                    network_state="connected",
                    correlation_id=incident.correlation_id,
                )
            )
    elif isolation == "pending":
        isolation_request = ActionRequest(
            action_type="isolate",
            asset_id=asset.id,
            incident_id=incident.id,
            requested_by_type="user",
            approval_status="approved",
            execution_status="executing",
            correlation_id=incident.correlation_id,
        )
        db.add(isolation_request)
        db.flush()
        db.add(
            IsolationAction(
                action_request_id=isolation_request.id,
                asset_id=asset.id,
                incident_id=incident.id,
                execution_status="executing",
                network_state="isolating",
                correlation_id=incident.correlation_id,
            )
        )
    db.commit()
    return {
        "asset": asset,
        "other_asset": other_asset,
        "incident": incident,
        "backup": backup,
        "other_backup": other_backup,
        "verification": verification,
        "other_verification": other_verification,
    }


def _request(client: TestClient, context: dict, **overrides):
    body = {
        "action_type": "recover",
        "asset_id": context["asset"].id,
        "incident_id": context["incident"].id,
        "backup_id": context["backup"].id,
        "verification_id": context["verification"].id,
        "requested_by_type": "user",
        "requested_by_id": "recovery-operator",
        "request_reason": "Restore the contained asset from the selected verified point",
        "correlation_id": context["incident"].correlation_id,
    }
    body.update(overrides)
    return client.post("/api/action-requests", json=body)


def _create_job(client: TestClient, action_request: dict, context: dict, **overrides):
    body = {
        "action_request_id": action_request["id"],
        "asset_id": context["asset"].id,
        "incident_id": context["incident"].id,
        "backup_id": context["backup"].id,
        "verification_id": context["verification"].id,
        "recovery_environment": "isolated-recovery-network",
        "correlation_id": action_request["correlation_id"],
    }
    body.update(overrides)
    return client.post("/api/recovery-jobs", json=body)


def _claim(client: TestClient, job: dict, *, component="recovery-agent-1"):
    return client.post(
        f"/api/internal/recovery-jobs/{job['id']}/claim",
        headers={"X-Internal-Component-Token": COMPONENT_TOKEN},
        json={"component_reference": component, "correlation_id": job["correlation_id"]},
    )


def _result(client: TestClient, job: dict, *, status_value="scanning", component="recovery-agent-1", **overrides):
    body = {
        "job_status": status_value,
        "asset_id": job["asset_id"],
        "incident_id": job["incident_id"],
        "backup_id": job["backup_id"],
        "verification_id": job["verification_id"],
        "correlation_id": job["correlation_id"],
        "component_reference": component,
        "malware_scan_status": "running" if status_value == "scanning" else "passed",
        "security_validation_status": "running" if status_value == "scanning" else "passed",
    }
    if status_value == "completed":
        body.update(
            outcome="Restoration and validation completed by trusted component",
            result_evidence_reference="evidence://recovery/result-001",
        )
    if status_value == "failed":
        body.update(failure_reason="Trusted component reported recovery failure")
    body.update(overrides)
    return client.post(
        f"/api/internal/recovery-jobs/{job['id']}/result",
        headers={"X-Internal-Component-Token": COMPONENT_TOKEN},
        json=body,
    )


def test_recovery_request_is_pending_and_recommendation_is_not_approval(client: TestClient, db: Session):
    context = _context(db)
    request = _request(client, context)
    assert request.status_code == 201, request.text
    body = request.json()
    assert body["action_type"] == "recover"
    assert body["approval_status"] == "pending"
    assert body["execution_status"] == "not_started"
    assert db.scalar(select(func.count(RecoveryJob.id))) == 0

    not_approved = _create_job(client, body, context)
    assert not_approved.status_code == 409
    assert not_approved.json()["detail"]["code"] == "recovery_not_approved"

    rejected = client.post(
        f"/api/action-requests/{body['id']}/reject",
        json={"rejected_by_id": "approver", "reason": "Recovery not authorized"},
    )
    assert rejected.status_code == 200
    assert rejected.json()["approval_status"] == "rejected"
    assert _create_job(client, body, context).status_code == 409

    request_events = db.scalars(
        select(AuditEvent.action).where(AuditEvent.action_request_id == body["id"])
    ).all()
    assert "recovery.requested" in request_events
    assert "recovery.rejected" in request_events


def test_recovery_job_creation_requires_all_gates_and_preserves_correlation(client: TestClient, db: Session):
    context = _context(db)
    request = _request(client, context).json()
    approved = client.post(
        f"/api/action-requests/{request['id']}/approve",
        json={"approved_by_id": "recovery-approver"},
    )
    assert approved.status_code == 200
    created = _create_job(client, approved.json(), context)
    assert created.status_code == 201, created.text
    job = created.json()
    assert job["job_status"] == "approved"
    assert job["correlation_id"] == context["incident"].correlation_id
    assert job["started_at"] is None
    assert job["completed_at"] is None
    assert job["cutover_status"] == "not_requested"
    duplicate = _create_job(client, approved.json(), context)
    assert duplicate.status_code == 200
    assert duplicate.json()["id"] == job["id"]

    assert db.query(AuditEvent).filter(
        AuditEvent.action == "recovery.job_created",
        AuditEvent.recovery_job_id == job["id"],
        AuditEvent.correlation_id == job["correlation_id"],
    ).count() == 1


@pytest.mark.parametrize(
    ("isolation", "lifecycle", "verification_status", "age", "expected"),
    [
        ("none", "available", "passed", 1, "asset_not_confirmed_isolated"),
        ("pending", "available", "passed", 1, "asset_not_confirmed_isolated"),
        ("released", "available", "passed", 1, "asset_not_confirmed_isolated"),
        ("isolated", "unavailable", "passed", 1, "backup_unavailable"),
        ("isolated", "available", "failed", 1, "verification_not_passed"),
        ("isolated", "available", "passed", 25, "verification_stale"),
    ],
)
def test_recovery_job_creation_rejects_invalid_safety_gates(
    client: TestClient,
    db: Session,
    isolation: str,
    lifecycle: str,
    verification_status: str,
    age: int,
    expected: str,
):
    context = _context(
        db,
        isolation=isolation,
        lifecycle=lifecycle,
        verification_status=verification_status,
        verification_age_hours=age,
    )
    request = _request(client, context)
    # A failed/unavailable/stale input is rejected before an ActionRequest exists;
    # absence or loss of confirmed isolation is deferred to job creation.
    if request.status_code != 201:
        assert request.status_code == 409, request.text
        assert request.json()["detail"]["code"] == expected
        return
    request_body = request.json()
    approved = client.post(
        f"/api/action-requests/{request_body['id']}/approve",
        json={"approved_by_id": "approver"},
    ).json()
    response = _create_job(client, approved, context)
    assert response.status_code == 409, response.text
    assert response.json()["detail"]["code"] == expected
    assert db.scalar(select(func.count(RecoveryJob.id))) == 0


def test_request_rejects_missing_and_mismatched_resources(client: TestClient, db: Session):
    context = _context(db)
    unknown = str(uuid4())
    for field, value, status_code in (
        ("asset_id", unknown, 404),
        ("incident_id", unknown, 404),
        ("backup_id", unknown, 404),
        ("verification_id", unknown, 404),
    ):
        response = _request(client, context, **{field: value})
        assert response.status_code == status_code, (field, response.text)

    mismatch = _request(client, context, asset_id=context["other_asset"].id)
    assert mismatch.status_code == 409
    other_verification = _request(client, context, verification_id=context["other_verification"].id)
    assert other_verification.status_code == 409


def test_recovery_action_request_reference_and_decision_mismatches_are_rejected(client: TestClient, db: Session):
    context = _context(db)
    other_incident = ThreatIncident(
        title="Other incident",
        threat_type="endpoint_activity",
        asset_id=context["other_asset"].id,
        detected_at=datetime.now(timezone.utc),
        lifecycle_status="contained",
        correlation_id=str(uuid4()),
    )
    db.add(other_incident)
    decision = Decision(
        incident_id=context["incident"].id,
        assessment_id=(
            db.query(Decision).filter_by(incident_id=context["incident"].id).first().assessment_id
            if db.query(Decision).filter_by(incident_id=context["incident"].id).first()
            else "missing-assessment"
        ),
        asset_id=context["asset"].id,
        recommended_actions=["recover"],
        rationale="Recovery recommendation only",
        approval_required=True,
        decision_status="proposed",
        correlation_id=context["incident"].correlation_id,
    )
    # Use a decision without relying on an assessment FK by only validating a
    # mismatched existing decision generated with a minimal valid assessment.
    from app.models import RiskAssessment

    assessment = RiskAssessment(
        incident_id=context["incident"].id,
        asset_id=context["asset"].id,
        score=90,
        risk_level="CRITICAL",
        status="completed",
        assessed_at=datetime.now(timezone.utc),
        correlation_id=context["incident"].correlation_id,
    )
    db.add(assessment)
    db.flush()
    decision.assessment_id = assessment.id
    db.add(decision)
    db.commit()

    bad_decision = _request(client, context, decision_id=decision.id, incident_id=other_incident.id)
    assert bad_decision.status_code == 409

    action_request = _request(client, context, decision_id=decision.id)
    assert action_request.status_code == 201, action_request.text
    request_body = action_request.json()
    db_request = db.get(ActionRequest, request_body["id"])
    db_request.backup_id = context["other_backup"].id
    db.commit()
    approved = client.post(
        f"/api/action-requests/{request_body['id']}/approve",
        json={"approved_by_id": "approver"},
    ).json()
    result = _create_job(client, approved, context)
    assert result.status_code == 409
    assert result.json()["detail"]["code"] == "action_request_mismatch"


@pytest.mark.parametrize("field", ["asset_id", "incident_id", "backup_id", "verification_id"])
def test_recovery_job_rejects_action_request_reference_mismatch(client: TestClient, db: Session, field: str):
    context = _context(db)
    request = _request(client, context).json()
    client.post(f"/api/action-requests/{request['id']}/approve", json={"approved_by_id": "approver"})
    action_request = db.get(ActionRequest, request["id"])
    if field == "asset_id":
        action_request.asset_id = context["other_asset"].id
    elif field == "incident_id":
        other_incident = ThreatIncident(
            title="Mismatched incident",
            threat_type="endpoint_activity",
            asset_id=context["other_asset"].id,
            detected_at=datetime.now(timezone.utc),
            correlation_id=str(uuid4()),
        )
        db.add(other_incident)
        db.flush()
        action_request.incident_id = other_incident.id
    elif field == "backup_id":
        action_request.backup_id = context["other_backup"].id
    else:
        action_request.verification_id = context["other_verification"].id
    db.commit()
    response = _create_job(client, request, context)
    assert response.status_code == 409, response.text
    assert response.json()["detail"]["code"] in {"action_request_mismatch", "incident_asset_mismatch"}


def test_recovery_dispatch_revalidates_before_queueing(client: TestClient, db: Session):
    context = _context(db)
    request = _request(client, context).json()
    client.post(f"/api/action-requests/{request['id']}/approve", json={"approved_by_id": "approver"})
    job = _create_job(client, request, context).json()

    context["backup"].lifecycle_status = "quarantined"
    db.commit()
    response = client.post(f"/api/recovery-jobs/{job['id']}/dispatch")
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "backup_unavailable"
    assert db.get(RecoveryJob, job["id"]).job_status == "approved"


def test_dispatch_and_trusted_component_result_lifecycle(client: TestClient, db: Session):
    context = _context(db)
    request = _request(client, context).json()
    client.post(f"/api/action-requests/{request['id']}/approve", json={"approved_by_id": "approver"})
    job = _create_job(client, request, context).json()

    queued = client.post(f"/api/recovery-jobs/{job['id']}/dispatch")
    assert queued.status_code == 200, queued.text
    assert queued.json()["job_status"] == "queued"
    assert queued.json()["started_at"] is None
    assert queued.json()["completed_at"] is None
    assert queued.json()["outcome"] is None

    unauthenticated = client.post(
        f"/api/internal/recovery-jobs/{job['id']}/claim",
        json={"component_reference": "recovery-agent-1", "correlation_id": job["correlation_id"]},
    )
    assert unauthenticated.status_code == 401

    claimed = _claim(client, job)
    assert claimed.status_code == 200, claimed.text
    assert claimed.json()["job_status"] == "restoring"
    assert claimed.json()["started_at"] is not None
    assert claimed.json()["correlation_id"] == job["correlation_id"]

    not_scanning = _result(client, job, status_value="completed")
    assert not_scanning.status_code == 409
    assert not_scanning.json()["detail"]["code"] == "invalid_state_transition"

    mismatch = _result(client, job, status_value="scanning", backup_id=str(uuid4()))
    assert mismatch.status_code == 409
    assert mismatch.json()["detail"]["code"] == "recovery_reference_mismatch"

    scanning = _result(client, job, status_value="scanning")
    assert scanning.status_code == 200, scanning.text
    assert scanning.json()["job_status"] == "scanning"
    completed = _result(client, job, status_value="completed")
    assert completed.status_code == 200, completed.text
    assert completed.json()["job_status"] == "completed"
    assert completed.json()["completed_at"] is not None
    assert completed.json()["outcome"] == "Restoration and validation completed by trusted component"

    audit_count = db.scalar(select(func.count(AuditEvent.id)))
    exact_duplicate = _result(client, job, status_value="completed")
    assert exact_duplicate.status_code == 200
    assert db.scalar(select(func.count(AuditEvent.id))) == audit_count

    conflict = _result(
        client,
        job,
        status_value="completed",
        outcome="Conflicting terminal result",
        result_evidence_reference="evidence://recovery/conflict",
    )
    assert conflict.status_code == 409
    assert conflict.json()["detail"]["code"] == "invalid_state_transition"

    job_audit = db.scalars(select(AuditEvent).where(AuditEvent.recovery_job_id == job["id"])).all()
    assert {row.action for row in job_audit} >= {
        "recovery.job_created",
        "recovery.dispatched",
        "recovery.restoring",
        "recovery.scanning",
        "recovery.completed",
        "recovery.component_result_rejected",
    }
    assert all(row.correlation_id == job["correlation_id"] for row in job_audit)
    assert db.get(ActionRequest, request["id"]).execution_status == "succeeded"


def test_failed_recovery_is_terminal_and_audited(client: TestClient, db: Session):
    context = _context(db)
    request = _request(client, context).json()
    client.post(f"/api/action-requests/{request['id']}/approve", json={"approved_by_id": "approver"})
    job = _create_job(client, request, context).json()
    assert client.post(f"/api/recovery-jobs/{job['id']}/dispatch").status_code == 200
    assert _claim(client, job).status_code == 200

    failed = _result(client, job, status_value="failed")
    assert failed.status_code == 200, failed.text
    assert failed.json()["job_status"] == "failed"
    repeated = _result(client, job, status_value="failed")
    assert repeated.status_code == 200
    conflict = _result(client, job, status_value="completed")
    assert conflict.status_code == 409
    assert db.query(AuditEvent).filter(
        AuditEvent.action == "recovery.failed",
        AuditEvent.recovery_job_id == job["id"],
        AuditEvent.correlation_id == job["correlation_id"],
    ).count() == 1


def test_dispatch_requires_current_confirmed_isolation(client: TestClient, db: Session):
    context = _context(db)
    request = _request(client, context).json()
    client.post(f"/api/action-requests/{request['id']}/approve", json={"approved_by_id": "approver"})
    job = _create_job(client, request, context).json()
    # A release after job creation invalidates isolation before dispatch.
    original = db.query(IsolationAction).filter_by(asset_id=context["asset"].id).one()
    release_request = ActionRequest(
        action_type="release_isolation",
        asset_id=context["asset"].id,
        requested_by_type="user",
        approval_status="approved",
        execution_status="succeeded",
        correlation_id=context["incident"].correlation_id,
    )
    db.add(release_request)
    db.flush()
    db.add(
        IsolationAction(
            action_request_id=release_request.id,
            parent_isolation_action_id=original.id,
            asset_id=context["asset"].id,
            execution_status="released",
            network_state="connected",
            correlation_id=context["incident"].correlation_id,
        )
    )
    db.commit()
    response = client.post(f"/api/recovery-jobs/{job['id']}/dispatch")
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "asset_not_confirmed_isolated"


def test_recovery_job_read_routes_are_registered(client: TestClient):
    paths = app.openapi()["paths"]
    assert "/api/recovery-jobs" in paths
    assert "/api/recovery-jobs/{recovery_job_id}/dispatch" in paths
    assert "/api/internal/recovery-jobs/{recovery_job_id}/claim" in paths
    assert "/api/internal/recovery-jobs/{recovery_job_id}/result" in paths
    assert "/api/recovery-jobs/{recovery_job_id}/cancel" in paths
