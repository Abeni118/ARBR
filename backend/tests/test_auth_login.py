from datetime import datetime, timedelta, timezone
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database.session import get_db
from app.main import app
from app.models import Base, UserPasswordOverride, UserSession
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