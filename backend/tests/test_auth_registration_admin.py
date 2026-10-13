from datetime import datetime, timedelta, timezone
import json
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database.session import get_db
from app.main import app
from app.models import AuditEvent, Base, UserAccount, UserSession
from app.services.user_auth import CSRF_COOKIE_NAME, SESSION_COOKIE_NAME, hash_password


TEST_PASSWORD = "test-operator-secure-password-2026"
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
        {"username": "admin", "user_id": "admin-1", "role": "admin", "password_hash": TEST_PASSWORD_HASH, "display_name": "Admin Principal"},
        {"username": "analyst", "user_id": "analyst-1", "role": "analyst", "password_hash": TEST_PASSWORD_HASH, "display_name": "Analyst Principal"},
        {"username": "viewer", "user_id": "viewer-1", "role": "viewer", "password_hash": TEST_PASSWORD_HASH, "display_name": "Viewer Principal"},
    ]
    monkeypatch.setenv("MVP_USER_CREDENTIALS", json.dumps(credentials))
    monkeypatch.setenv("AUTH_COOKIE_SECURE", "false")

    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _login(client: TestClient, username: str = "admin", password: str = TEST_PASSWORD):
    return client.post("/api/auth/login", json={"username": username, "password": password})


def _csrf_headers(client: TestClient) -> dict[str, str]:
    token = client.cookies.get(CSRF_COOKIE_NAME, "")
    return {"X-CSRF-Token": token}


# 1. Successful registration for permitted users
def test_successful_registration_assigns_viewer_role(client: TestClient, db: Session):
    reg_response = client.post(
        "/api/auth/register",
        json={
            "username": "new_registered_user",
            "password": "valid-secure-registration-password-123",
            "display_name": "New Registered",
        },
    )
    assert reg_response.status_code == 201, reg_response.text
    data = reg_response.json()
    assert data["username"] == "new_registered_user"
    assert data["display_name"] == "New Registered"
    assert data["role"] == "viewer"
    assert data["is_active"] is True
    assert "password" not in data
    assert "password_hash" not in data

    # Verify audit event recorded
    audit = db.scalar(select(AuditEvent).where(AuditEvent.action == "user_account.registered"))
    assert audit is not None
    assert audit.resource_id == data["user_id"]

    # Verify user can sign in immediately
    login_response = client.post(
        "/api/auth/login",
        json={"username": "new_registered_user", "password": "valid-secure-registration-password-123"},
    )
    assert login_response.status_code == 200
    assert login_response.json()["role"] == "viewer"


# 2. Duplicate usernames
def test_duplicate_usernames_rejected(client: TestClient):
    reg_1 = client.post(
        "/api/auth/register",
        json={
            "username": "unique_username",
            "password": "valid-secure-registration-password-123",
        },
    )
    assert reg_1.status_code == 201

    # Exact duplicate
    reg_2 = client.post(
        "/api/auth/register",
        json={
            "username": "unique_username",
            "password": "another-password-123456",
        },
    )
    assert reg_2.status_code == 409
    assert reg_2.json()["detail"]["code"] == "username_already_exists"

    # Case-insensitive duplicate
    reg_3 = client.post(
        "/api/auth/register",
        json={
            "username": "UNIQUE_USERNAME",
            "password": "another-password-123456",
        },
    )
    assert reg_3.status_code == 409
    assert reg_3.json()["detail"]["code"] == "username_already_exists"

    # Duplicate of configured user
    reg_configured = client.post(
        "/api/auth/register",
        json={
            "username": "ADMIN",
            "password": "another-password-123456",
        },
    )
    assert reg_configured.status_code == 409


# 3. Invalid registration input
def test_invalid_registration_input(client: TestClient):
    # Short password (< 12 chars)
    short_pw = client.post(
        "/api/auth/register",
        json={"username": "valid_name", "password": "short"},
    )
    assert short_pw.status_code == 422

    # Short username (< 3 chars)
    short_user = client.post(
        "/api/auth/register",
        json={"username": "ab", "password": "valid-secure-registration-password-123"},
    )
    assert short_user.status_code == 422

    # Invalid characters in username
    bad_chars = client.post(
        "/api/auth/register",
        json={"username": "bad user@name!", "password": "valid-secure-registration-password-123"},
    )
    assert bad_chars.status_code == 422


# 4. Incorrect login credentials
def test_incorrect_login_credentials(client: TestClient):
    wrong_pw = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "wrong-password-here"},
    )
    assert wrong_pw.status_code == 401
    assert wrong_pw.json()["detail"]["code"] == "invalid_credentials"

    nonexistent_user = client.post(
        "/api/auth/login",
        json={"username": "does_not_exist", "password": TEST_PASSWORD},
    )
    assert nonexistent_user.status_code == 401


# 5. Successful login and authenticated access
def test_successful_login_and_authenticated_access(client: TestClient):
    login_res = _login(client, "admin")
    assert login_res.status_code == 200
    user_info = login_res.json()
    assert user_info["role"] == "admin"
    assert user_info["user_id"] == "admin-1"

    # Verify session cookie and csrf
    assert SESSION_COOKIE_NAME in client.cookies
    assert CSRF_COOKIE_NAME in client.cookies

    me_res = client.get("/api/auth/me")
    assert me_res.status_code == 200
    assert me_res.json()["user_id"] == "admin-1"


# 6. Unauthorized access to the Admin Panel
def test_unauthorized_access_to_admin_panel(client: TestClient):
    # Unauthenticated access to admin overview
    unauth_overview = client.get("/api/admin/overview")
    assert unauth_overview.status_code == 401

    # Unauthenticated access to users list
    unauth_users = client.get("/api/users")
    assert unauth_users.status_code == 401

    # Ordinary user (viewer) access to admin overview
    assert _login(client, "viewer").status_code == 200
    viewer_overview = client.get("/api/admin/overview")
    assert viewer_overview.status_code == 403
    assert viewer_overview.json()["detail"]["code"] == "forbidden"

    # Ordinary user (analyst) access to admin overview
    client.post("/api/auth/logout", headers=_csrf_headers(client))
    assert _login(client, "analyst").status_code == 200
    analyst_overview = client.get("/api/admin/overview")
    assert analyst_overview.status_code == 403


# 7. Attempts by ordinary users to perform administrative actions
def test_ordinary_users_cannot_perform_admin_actions(client: TestClient):
    assert _login(client, "analyst").status_code == 200

    # Analyst cannot list users
    list_res = client.get("/api/users")
    assert list_res.status_code == 403

    # Analyst cannot provision accounts
    create_res = client.post(
        "/api/users",
        headers=_csrf_headers(client),
        json={"username": "analyst_created", "role": "viewer", "initial_password": "valid-secure-registration-password-123"},
    )
    assert create_res.status_code == 403

    # Analyst cannot update system settings
    settings_res = client.put(
        "/api/settings",
        headers=_csrf_headers(client),
        json={"risk_thresholds": {"low_min": 0, "low_max": 25, "medium_min": 26, "medium_max": 50, "high_min": 51, "high_max": 75, "critical_min": 76, "critical_max": 100}},
    )
    assert settings_res.status_code == 403


# 8. Attempts to assign an administrator role through public registration
def test_public_registration_cannot_choose_admin_or_elevated_role(client: TestClient):
    # Attempt to register with role="admin"
    admin_attempt = client.post(
        "/api/auth/register",
        json={
            "username": "hacker_admin",
            "password": "valid-secure-registration-password-123",
            "role": "admin",
        },
    )
    assert admin_attempt.status_code == 422

    # Attempt to register with role="analyst"
    analyst_attempt = client.post(
        "/api/auth/register",
        json={
            "username": "hacker_analyst",
            "password": "valid-secure-registration-password-123",
            "role": "analyst",
        },
    )
    assert analyst_attempt.status_code == 422


# 9. Authorized administrator user management
def test_authorized_administrator_user_management(client: TestClient, db: Session):
    assert _login(client, "admin").status_code == 200

    # List users (returns both configured and database users)
    users_res = client.get("/api/users")
    assert users_res.status_code == 200
    user_list = users_res.json()
    assert len(user_list) >= 3
    assert any(u["username"] == "admin" for u in user_list)

    # Admin overview returns real aggregated data
    overview_res = client.get("/api/admin/overview")
    assert overview_res.status_code == 200
    overview_data = overview_res.json()
    assert overview_data["user_counts"]["total"] >= 3
    assert overview_data["system_health"]["database"]["connected"] is True
    assert "wazuh_integration" in overview_data["system_health"]

    # Admin provisions a new operator account
    created_res = client.post(
        "/api/users",
        headers=_csrf_headers(client),
        json={
            "username": "ops_operator",
            "display_name": "Operations Operator",
            "role": "analyst",
            "initial_password": "valid-secure-operator-password-123",
        },
    )
    assert created_res.status_code == 201
    created_id = created_res.json()["user_id"]

    # View user details
    detail_res = client.get(f"/api/users/{created_id}")
    assert detail_res.status_code == 200
    assert detail_res.json()["username"] == "ops_operator"

    # Admin updates user role to approver
    update_role_res = client.patch(
        f"/api/users/{created_id}",
        headers=_csrf_headers(client),
        json={"role": "approver"},
    )
    assert update_role_res.status_code == 200
    assert update_role_res.json()["role"] == "approver"

    # Admin promotes user to admin
    promote_res = client.patch(
        f"/api/users/{created_id}",
        headers=_csrf_headers(client),
        json={"role": "admin"},
    )
    assert promote_res.status_code == 200
    assert promote_res.json()["role"] == "admin"

    # Admin deactivates the user
    deactivate_res = client.patch(
        f"/api/users/{created_id}",
        headers=_csrf_headers(client),
        json={"is_active": False},
    )
    assert deactivate_res.status_code == 200
    assert deactivate_res.json()["is_active"] is False

    # Prevent removing last active administrator test:
    # First, verify that trying to mutate a configured identity fails closed
    configured_update = client.patch(
        "/api/users/admin-1",
        headers=_csrf_headers(client),
        json={"is_active": False},
    )
    assert configured_update.status_code == 400

    # Demote our newly created admin back to viewer
    client.patch(
        f"/api/users/{created_id}",
        headers=_csrf_headers(client),
        json={"role": "viewer", "is_active": True},
    )

    # Now create a lone database admin with no other configured admins
    db_admin = UserAccount(
        username="lone_admin",
        username_normalized="lone_admin",
        role="admin",
        password_hash=TEST_PASSWORD_HASH,
        is_active=True,
        created_by_user_id="test",
    )
    db.add(db_admin)
    db.commit()

    # If there is only this active admin in the DB and configured admin is absent:
    # Let's test the protection against removing last active administrator:
    # We create a scenario where lone_admin is the ONLY active admin
    app_admin_id = db_admin.user_id


def test_cannot_remove_last_active_administrator(client: TestClient, db: Session, monkeypatch):
    # Configure with NO configured admins
    monkeypatch.setenv("MVP_USER_CREDENTIALS", json.dumps([]))

    sole_admin = UserAccount(
        username="sole_admin",
        username_normalized="sole_admin",
        role="admin",
        password_hash=TEST_PASSWORD_HASH,
        is_active=True,
        created_by_user_id="test",
    )
    db.add(sole_admin)
    db.commit()

    # Login as sole_admin
    login_res = client.post("/api/auth/login", json={"username": "sole_admin", "password": TEST_PASSWORD})
    assert login_res.status_code == 200

    # Attempt to deactivate the sole admin
    deactivate_attempt = client.patch(
        f"/api/users/{sole_admin.user_id}",
        headers=_csrf_headers(client),
        json={"is_active": False},
    )
    assert deactivate_attempt.status_code == 400
    assert deactivate_attempt.json()["detail"]["code"] == "cannot_remove_last_admin"

    # Attempt to demote the sole admin to viewer
    demote_attempt = client.patch(
        f"/api/users/{sole_admin.user_id}",
        headers=_csrf_headers(client),
        json={"role": "viewer"},
    )
    assert demote_attempt.status_code == 400
    assert demote_attempt.json()["detail"]["code"] == "cannot_remove_last_admin"


# 10. Token expiration and invalid-token behavior
def test_token_expiration_and_deactivated_account_behavior(client: TestClient, db: Session):
    reg = client.post(
        "/api/auth/register",
        json={"username": "expiring_user", "password": "valid-secure-registration-password-123"},
    )
    assert reg.status_code == 201
    user_id = reg.json()["user_id"]

    login_res = client.post("/api/auth/login", json={"username": "expiring_user", "password": "valid-secure-registration-password-123"})
    assert login_res.status_code == 200

    # 1. Manually expire session in DB
    session = db.scalar(select(UserSession).where(UserSession.user_id == user_id))
    assert session is not None
    session.expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
    db.commit()

    # Call /me with expired session
    expired_res = client.get("/api/auth/me")
    assert expired_res.status_code == 401
    assert expired_res.json()["detail"]["code"] == "session_expired"

    # 2. Deactivated account rejection
    client.post("/api/auth/logout", headers={"X-CSRF-Token": "irrelevant"})
    login_again = client.post("/api/auth/login", json={"username": "expiring_user", "password": "valid-secure-registration-password-123"})
    assert login_again.status_code == 200

    account = db.get(UserAccount, user_id)
    account.is_active = False
    db.commit()

    # Next authenticated request rejects deactivated user
    deactivated_req = client.get("/api/auth/me")
    assert deactivated_req.status_code == 401
    assert deactivated_req.json()["detail"]["code"] == "account_disabled"

    # Cannot sign in when deactivated
    signin_attempt = client.post("/api/auth/login", json={"username": "expiring_user", "password": "valid-secure-registration-password-123"})
    assert signin_attempt.status_code == 401
