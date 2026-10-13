from datetime import datetime, timedelta, timezone
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database.session import get_db
from app.main import app
from app.models import Asset, AuditEvent, Base, RiskAssessment, SecurityEvent, ThreatIncident, UserAccount, UserPasswordOverride, UserSession
from app.services.user_auth import CSRF_COOKIE_NAME, SESSION_COOKIE_NAME, hash_password


TEST_PASSWORD = "test-only-password-with-sufficient-length"
TEST_PASSWORD_HASH = hash_password(TEST_PASSWORD)


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
    credentials = [
        {"username": "viewer", "user_id": "viewer-1", "role": "viewer", "password_hash": TEST_PASSWORD_HASH},
        {"username": "analyst", "user_id": "analyst-1", "role": "analyst", "password_hash": TEST_PASSWORD_HASH},
        {"username": "approver", "user_id": "approver-1", "role": "approver", "password_hash": TEST_PASSWORD_HASH},
        {"username": "admin", "user_id": "admin-1", "role": "admin", "password_hash": TEST_PASSWORD_HASH},
    ]
    monkeypatch.setenv("MVP_USER_CREDENTIALS", json.dumps(credentials))
    monkeypatch.setenv("AUTH_COOKIE_SECURE", "false")
    monkeypatch.setenv("BACKUP_COMPONENT_TOKEN", "login-test-component-secret")

    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _login(client: TestClient, username: str = "analyst"):
    return client.post("/api/auth/login", json={"username": username, "password": TEST_PASSWORD})


def _csrf_headers(client: TestClient) -> dict[str, str]:
    return {"X-CSRF-Token": client.cookies[CSRF_COOKIE_NAME]}


def test_login_issues_opaque_http_only_session_and_resolves_principal(client: TestClient):
    response = _login(client)
    assert response.status_code == 200, response.text
    assert {key: response.json()[key] for key in ("user_id", "role", "display_name")} == {
        "user_id": "analyst-1",
        "role": "analyst",
        "display_name": None,
    }
    assert response.json()["csrf_token"]
    assert SESSION_COOKIE_NAME in client.cookies
    assert CSRF_COOKIE_NAME in client.cookies
    set_cookie = response.headers.get_list("set-cookie")
    session_cookie = next(value for value in set_cookie if value.startswith(f"{SESSION_COOKIE_NAME}="))
    assert "httponly" in session_cookie.lower()
    assert "samesite=lax" in session_cookie.lower()
    assert "session_token" not in response.json()
    assert "access_token" not in response.json()

    current_user = client.get("/api/auth/me")
    assert current_user.status_code == 200
    assert current_user.json()["user_id"] == "analyst-1"
    assert current_user.json()["csrf_token"] == client.cookies[CSRF_COOKIE_NAME]
    repeated_check = client.get("/api/auth/me")
    assert repeated_check.status_code == 200
    assert repeated_check.json()["csrf_token"] == current_user.json()["csrf_token"]
    assert client.get("/api/assets").status_code == 200


def test_login_allows_vite_fallback_origin_on_port_5174(client: TestClient):
    origin = "http://localhost:5174"
    preflight = client.options(
        "/api/auth/login",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert preflight.status_code == 200
    assert preflight.headers["access-control-allow-origin"] == origin

    response = client.post(
        "/api/auth/login",
        headers={"Origin": origin},
        json={"username": "analyst", "password": TEST_PASSWORD},
    )
    assert response.status_code == 200, response.text
    assert response.json()["user_id"] == "analyst-1"


def test_security_event_summary_reports_real_counts_and_activity(client: TestClient, db: Session):
    now = datetime.now(timezone.utc)
    asset = Asset(hostname="summary-test-host", monitoring_status="online")
    db.add(asset)
    db.flush()
    db.add_all(
        [
            SecurityEvent(
                source="summary-test",
                source_event_id="critical-event",
                asset_id=asset.id,
                occurred_at=now,
                event_type="authentication_failure",
                event_severity="critical",
                processing_status="received",
                summary="Critical test event",
            ),
            SecurityEvent(
                source="summary-test",
                source_event_id="processed-event",
                asset_id=asset.id,
                occurred_at=now,
                event_type="backup_check",
                event_severity="info",
                processing_status="processed",
                summary="Processed test event",
            ),
        ]
    )
    db.commit()

    assert _login(client).status_code == 200
    response = client.get("/api/security-events/summary?period=24h")

    assert response.status_code == 200, response.text
    result = response.json()
    assert result["total_events"] == 2
    assert result["critical_events"] == 1
    assert result["pending_processing_events"] == 1
    assert result["events_today"] == 2
    assert result["monitored_assets"] == 1
    assert len(result["activity"]) == 12
    assert sum(point["events"] for point in result["activity"]) == 2
    assert sum(point["critical_events"] for point in result["activity"]) == 1

    filtered = client.get("/api/security-events/summary?period=24h&event_severity=info")
    assert filtered.status_code == 200, filtered.text
    filtered_result = filtered.json()
    assert filtered_result["total_events"] == 1
    assert filtered_result["critical_events"] == 0
    assert filtered_result["pending_processing_events"] == 0
    assert sum(point["events"] for point in filtered_result["activity"]) == 1


def test_threat_summary_uses_lifecycle_and_current_risk_records(client: TestClient, db: Session):
    asset = Asset(hostname="threat-summary-test-host")
    db.add(asset)
    db.flush()
    active = ThreatIncident(
        title="Active summary test",
        threat_type="test",
        asset_id=asset.id,
        detected_at=datetime.now(timezone.utc),
        lifecycle_status="investigating",
    )
    resolved = ThreatIncident(
        title="Resolved summary test",
        threat_type="test",
        asset_id=asset.id,
        detected_at=datetime.now(timezone.utc),
        lifecycle_status="resolved",
    )
    db.add_all([active, resolved])
    db.flush()
    assessment = RiskAssessment(
        incident_id=active.id,
        asset_id=asset.id,
        score=95,
        risk_level="CRITICAL",
        factors=[],
        assessed_at=datetime.now(timezone.utc),
    )
    db.add(assessment)
    db.flush()
    active.current_risk_assessment_id = assessment.id
    db.commit()

    assert _login(client).status_code == 200
    response = client.get("/api/threats/summary")

    assert response.status_code == 200, response.text
    assert response.json() == {
        "total_incidents": 2,
        "active_threats": 1,
        "critical_risk_incidents": 1,
        "resolved_incidents": 1,
    }


def test_only_admin_can_persist_settings_and_reads_remain_available(client: TestClient, db: Session):
    viewer_login = _login(client, "viewer")
    assert viewer_login.status_code == 200
    assert client.get("/api/settings").status_code == 200
    denied = client.put(
        "/api/settings",
        headers=_csrf_headers(client),
        json={"risk_thresholds": {"low_min": 0, "low_max": 19, "medium_min": 20, "medium_max": 49, "high_min": 50, "high_max": 79, "critical_min": 80, "critical_max": 100}},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["code"] == "forbidden"

    client.post("/api/auth/logout", headers=_csrf_headers(client))
    assert _login(client, "admin").status_code == 200
    updated = client.put(
        "/api/settings",
        headers=_csrf_headers(client),
        json={"risk_thresholds": {"low_min": 0, "low_max": 19, "medium_min": 20, "medium_max": 49, "high_min": 50, "high_max": 79, "critical_min": 80, "critical_max": 100}},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["risk_thresholds"]["medium_max"] == 49
    assert updated.json()["version"] == 2
    assert db.scalar(select(AuditEvent).where(AuditEvent.action == "system_settings.updated")) is not None

    unsupported_policy = client.put(
        "/api/settings",
        headers=_csrf_headers(client),
        json={"backup_policy": {"automatic_backup": True}},
    )
    assert unsupported_policy.status_code == 422


def test_admin_provisions_non_admin_account_and_duplicate_names_are_rejected(client: TestClient, db: Session):
    public_registration = client.post("/api/auth/register", json={})
    assert public_registration.status_code == 422

    assert _login(client, "viewer").status_code == 200
    forbidden = client.post(
        "/api/users",
        headers=_csrf_headers(client),
        json={"username": "new.operator", "role": "analyst", "initial_password": "initial-operator-password-2026"},
    )
    assert forbidden.status_code == 403
    assert client.get("/api/users").status_code == 403

    client.post("/api/auth/logout", headers=_csrf_headers(client))
    assert _login(client, "admin").status_code == 200
    configured_username = client.post(
        "/api/users",
        headers=_csrf_headers(client),
        json={"username": "VIEWER", "role": "analyst", "initial_password": "initial-operator-password-2026"},
    )
    assert configured_username.status_code == 409
    invalid_username = client.post(
        "/api/users",
        headers=_csrf_headers(client),
        json={"username": "!not-valid!", "role": "viewer", "initial_password": "initial-operator-password-2026"},
    )
    assert invalid_username.status_code == 422
    created = client.post(
        "/api/users",
        headers=_csrf_headers(client),
        json={"username": "New.Operator", "display_name": "New Operator", "role": "analyst", "initial_password": "initial-operator-password-2026"},
    )
    assert created.status_code == 201, created.text
    assert created.json()["role"] == "analyst"
    assert created.json()["username"] == "New.Operator"
    assert "password_hash" not in created.json()
    assert "initial_password" not in created.json()
    assert "csrf_token" not in created.json()
    stored_account = db.get(UserAccount, created.json()["user_id"])
    assert stored_account is not None
    assert stored_account.password_hash.startswith("pbkdf2_sha256$")
    assert "initial-operator-password-2026" not in stored_account.password_hash

    rejected_login = client.post("/api/auth/login", json={"username": "new.operator", "password": "wrong-initial-password"})
    assert rejected_login.status_code == 401

    duplicate = client.post(
        "/api/users",
        headers=_csrf_headers(client),
        json={"username": "new.operator", "role": "viewer", "initial_password": "another-initial-password-2026"},
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["detail"]["code"] == "username_already_exists"

    role_escalation = client.post(
        "/api/users",
        headers=_csrf_headers(client),
        json={"username": "new.admin", "role": "admin", "initial_password": "another-initial-password-2026"},
    )
    assert role_escalation.status_code == 422

    client.post("/api/auth/logout", headers=_csrf_headers(client))
    signed_in = client.post("/api/auth/login", json={"username": " new.operator ", "password": "initial-operator-password-2026"})
    assert signed_in.status_code == 200, signed_in.text
    assert signed_in.json()["user_id"] == created.json()["user_id"]
    assert signed_in.json()["role"] == "analyst"
    assert client.get("/api/assets").status_code == 200


def test_login_rejects_invalid_and_missing_credentials(client: TestClient):
    invalid = client.post("/api/auth/login", json={"username": "analyst", "password": "wrong-password"})
    assert invalid.status_code == 401
    assert invalid.json()["detail"]["code"] == "invalid_credentials"
    assert SESSION_COOKIE_NAME not in client.cookies

    missing = client.post("/api/auth/login", json={})
    assert missing.status_code == 422
    assert SESSION_COOKIE_NAME not in client.cookies


def test_login_rejects_untrusted_origin_and_forged_session_cookie(client: TestClient):
    untrusted_origin = client.post(
        "/api/auth/login",
        headers={"Origin": "https://attacker.example"},
        json={"username": "analyst", "password": TEST_PASSWORD},
    )
    assert untrusted_origin.status_code == 403
    assert untrusted_origin.json()["detail"]["code"] == "untrusted_origin"

    client.cookies.set(SESSION_COOKIE_NAME, "forged-session-cookie")
    invalid_session = client.get("/api/auth/me")
    assert invalid_session.status_code == 401
    assert invalid_session.json()["detail"]["code"] == "invalid_session"


def test_protected_routes_require_authentication_and_cookie_requests_require_csrf(client: TestClient):
    unauthenticated = client.get("/api/dashboard/summary")
    assert unauthenticated.status_code == 401
    assert unauthenticated.json()["detail"]["code"] == "authentication_required"

    assert _login(client).status_code == 200
    rejected = client.post("/api/assets", json={"hostname": "csrf-protected-host"})
    assert rejected.status_code == 403
    assert rejected.json()["detail"]["code"] == "csrf_validation_failed"

    accepted = client.post(
        "/api/assets",
        headers=_csrf_headers(client),
        json={"hostname": "analyst-cookie-created-host"},
    )
    assert accepted.status_code == 201, accepted.text


def test_authenticated_roles_preserve_existing_authorization(client: TestClient):
    viewer_login = _login(client, "viewer")
    assert viewer_login.status_code == 200
    assert client.get("/api/assets").status_code == 200
    viewer_write = client.post(
        "/api/assets",
        headers=_csrf_headers(client),
        json={"hostname": "viewer-cookie-cannot-create"},
    )
    assert viewer_write.status_code == 403
    assert viewer_write.json()["detail"]["code"] == "forbidden"

    client.post("/api/auth/logout", headers=_csrf_headers(client))
    analyst_login = _login(client, "analyst")
    assert analyst_login.status_code == 200
    analyst_write = client.post(
        "/api/assets",
        headers=_csrf_headers(client),
        json={"hostname": "analyst-cookie-can-create"},
    )
    assert analyst_write.status_code == 201


def test_logout_revokes_session_and_prevents_subsequent_access(client: TestClient, db: Session):
    assert _login(client).status_code == 200
    assert db.scalar(select(UserSession)) is not None

    logout = client.post("/api/auth/logout", headers=_csrf_headers(client))
    assert logout.status_code == 204
    assert SESSION_COOKIE_NAME not in client.cookies
    assert CSRF_COOKIE_NAME not in client.cookies
    assert db.scalar(select(UserSession)) is None

    protected = client.get("/api/assets")
    assert protected.status_code == 401


def test_expired_session_is_rejected_and_human_session_cannot_authenticate_component(client: TestClient, db: Session):
    assert _login(client).status_code == 200
    session = db.scalar(select(UserSession))
    assert session is not None
    session.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()

    expired = client.get("/api/assets")
    assert expired.status_code == 401
    assert expired.json()["detail"]["code"] == "session_expired"

    client.post("/api/auth/logout", headers=_csrf_headers(client))
    assert _login(client).status_code == 200
    component_request = client.post(
        "/api/internal/security-events",
        json={"source": "test", "source_event_id": "event-1"},
    )
    assert component_request.status_code == 401
    assert component_request.json()["detail"]["code"] == "component_authentication_required"


def test_password_change_requires_current_password_hashes_new_password_and_revokes_sessions(client: TestClient, db: Session):
    new_password = "new-test-password-with-more-than-12-chars"
    assert _login(client).status_code == 200
    failed = client.post(
        "/api/auth/change-password",
        headers=_csrf_headers(client),
        json={"current_password": "wrong-current-password", "new_password": new_password},
    )
    assert failed.status_code == 400
    assert failed.json()["detail"]["code"] == "password_change_rejected"

    changed = client.post(
        "/api/auth/change-password",
        headers=_csrf_headers(client),
        json={"current_password": TEST_PASSWORD, "new_password": new_password},
    )
    assert changed.status_code == 204
    assert db.scalar(select(UserSession)) is None
    password_override = db.get(UserPasswordOverride, "analyst-1")
    assert password_override is not None
    assert password_override.password_hash != new_password
    assert password_override.password_hash.startswith("pbkdf2_sha256$")
    assert new_password not in password_override.password_hash

    assert client.get("/api/assets").status_code == 401
    old_password_login = client.post(
        "/api/auth/login", json={"username": "analyst", "password": TEST_PASSWORD}
    )
    assert old_password_login.status_code == 401
    new_password_login = client.post(
        "/api/auth/login", json={"username": "analyst", "password": new_password}
    )
    assert new_password_login.status_code == 200