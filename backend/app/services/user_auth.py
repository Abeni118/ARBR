"""Minimal environment-configured Bearer authentication for the university MVP."""

from dataclasses import dataclass
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
import secrets
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.enums import StringEnum
from app.models import UserAccount, UserPasswordOverride, UserSession
from app.schemas import AuditEventCreate
from app.services.audit import record_audit_event

bearer_scheme = HTTPBearer(auto_error=False)
SESSION_COOKIE_NAME = "arbr_session"
CSRF_COOKIE_NAME = "arbr_csrf"
CSRF_HEADER_NAME = "X-CSRF-Token"
PASSWORD_HASH_ITERATIONS = 600_000
_DUMMY_PASSWORD_HASH = "pbkdf2_sha256$600000$MDAwMDAwMDAwMDAwMDAwMA$" + base64.urlsafe_b64encode(
    hashlib.pbkdf2_hmac("sha256", b"not-a-real-password", b"0000000000000000", PASSWORD_HASH_ITERATIONS)
).decode("ascii").rstrip("=")


class UserRole(StringEnum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    APPROVER = "approver"
    ADMIN = "admin"


@dataclass(frozen=True)
class UserPrincipal:
    user_id: str
    role: UserRole
    display_name: str | None = None


def _authentication_error(code: str, message: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"code": code, "message": message},
        headers={"WWW-Authenticate": "Bearer"},
    )


def _configured_users() -> list[dict[str, str]]:
    """Read token/principal mappings without logging or returning credentials."""
    raw_users = os.getenv("MVP_USER_TOKENS", "")
    try:
        users = json.loads(raw_users)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(users, list):
        return []
    valid: list[dict[str, str]] = []
    seen_tokens: set[str] = set()
    for item in users:
        if not isinstance(item, dict):
            continue
        token = item.get("token")
        user_id = item.get("user_id")
        role = item.get("role")
        display_name = item.get("display_name")
        if not all(isinstance(value, str) and value.strip() for value in (token, user_id, role)):
            continue
        if display_name is not None and not isinstance(display_name, str):
            continue
        try:
            UserRole(role)
        except ValueError:
            continue
        if token in seen_tokens:
            return []
        seen_tokens.add(token)
        valid.append(
            {
                "token": token,
                "user_id": user_id,
                "role": role,
                **({"display_name": display_name} if display_name is not None else {}),
            }
        )
    return valid


def _configured_credentials() -> list[dict[str, str]]:
    """Read username, password-hash, and role mappings; malformed config fails closed."""
    raw_users = os.getenv("MVP_USER_CREDENTIALS", "")
    try:
        users = json.loads(raw_users)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(users, list):
        return []
    valid: list[dict[str, str]] = []
    seen_usernames: set[str] = set()
    for item in users:
        if not isinstance(item, dict):
            return []
        username = item.get("username")
        user_id = item.get("user_id")
        role = item.get("role")
        password_hash = item.get("password_hash")
        display_name = item.get("display_name")
        if not all(isinstance(value, str) and value.strip() for value in (username, user_id, role, password_hash)):
            return []
        if display_name is not None and not isinstance(display_name, str):
            return []
        try:
            UserRole(role)
            _parse_password_hash(password_hash)
        except (ValueError, TypeError):
            return []
        normalized_username = username.casefold()
        if normalized_username in seen_usernames:
            return []
        seen_usernames.add(normalized_username)
        valid.append(
            {
                "username": username,
                "user_id": user_id,
                "role": role,
                "password_hash": password_hash,
                **({"display_name": display_name} if display_name is not None else {}),
            }
        )
    return valid


def _decode_hash_part(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _parse_password_hash(encoded: str) -> tuple[int, bytes, bytes]:
    algorithm, rounds, salt, digest = encoded.split("$", 3)
    iterations = int(rounds)
    salt_bytes = _decode_hash_part(salt)
    digest_bytes = _decode_hash_part(digest)
    if algorithm != "pbkdf2_sha256" or not 200_000 <= iterations <= 2_000_000 or len(salt_bytes) < 16 or len(digest_bytes) != 32:
        raise ValueError("Unsupported password hash")
    return iterations, salt_bytes, digest_bytes


def hash_password(password: str) -> str:
    """Create a PBKDF2-SHA256 password hash for credential provisioning."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_HASH_ITERATIONS)
    encoded_salt = base64.urlsafe_b64encode(salt).decode("ascii").rstrip("=")
    encoded_digest = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"pbkdf2_sha256${PASSWORD_HASH_ITERATIONS}${encoded_salt}${encoded_digest}"


def _verify_password(password: str, encoded: str) -> bool:
    try:
        iterations, salt, expected = _parse_password_hash(encoded)
    except (ValueError, TypeError):
        iterations, salt, expected = _parse_password_hash(_DUMMY_PASSWORD_HASH)
        password = "invalid-password-hash"
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(actual, expected)


def _configured_credential_for_user_id(user_id: str) -> dict[str, str] | None:
    return next((entry for entry in _configured_credentials() if entry["user_id"] == user_id), None)


def is_configured_username(username: str) -> bool:
    normalized_username = username.strip().casefold()
    return any(entry["username"].casefold() == normalized_username for entry in _configured_credentials())


def authenticate_password(username: str, password: str, db: Session | None = None) -> UserPrincipal | None:
    """Resolve an environment-managed or administrator-provisioned human identity."""
    configured_users = _configured_credentials()
    normalized_username = username.strip().casefold()
    configured = next((entry for entry in configured_users if entry["username"].casefold() == normalized_username), None)
    account = (
        db.query(UserAccount).filter(UserAccount.username_normalized == normalized_username).one_or_none()
        if db
        else None
    )
    if account is not None and configured is not None:
        _verify_password(password, _DUMMY_PASSWORD_HASH)
        return None
    if account is not None:
        if not account.is_active:
            _verify_password(password, _DUMMY_PASSWORD_HASH)
            return None
        if not _verify_password(password, account.password_hash):
            return None
        try:
            role = UserRole(account.role)
        except ValueError:
            _verify_password(password, _DUMMY_PASSWORD_HASH)
            return None
        return UserPrincipal(account.user_id, role, account.display_name)

    user = configured
    password_override = db.get(UserPasswordOverride, user["user_id"]) if user and db else None
    encoded_hash = password_override.password_hash if password_override else user["password_hash"] if user else _DUMMY_PASSWORD_HASH
    password_matches = _verify_password(password, encoded_hash)
    if user is None or not password_matches:
        return None
    return UserPrincipal(
        user_id=user["user_id"],
        role=UserRole(user["role"]),
        display_name=user.get("display_name"),
    )


def change_user_password(db: Session, user: UserPrincipal, current_password: str, new_password: str) -> bool:
    """Verify the current password, persist only a new hash, and revoke sessions."""
    account = db.get(UserAccount, user.user_id)
    if account is not None:
        if not _verify_password(current_password, account.password_hash):
            return False
        if hmac.compare_digest(current_password.encode("utf-8"), new_password.encode("utf-8")):
            return False
        account.password_hash = hash_password(new_password)
        db.query(UserSession).filter(UserSession.user_id == user.user_id).delete(synchronize_session=False)
        db.commit()
        return True

    configured = _configured_credential_for_user_id(user.user_id)
    if configured is None:
        return False
    override = db.get(UserPasswordOverride, user.user_id)
    current_hash = override.password_hash if override else configured["password_hash"]
    if not _verify_password(current_password, current_hash):
        return False
    if hmac.compare_digest(current_password.encode("utf-8"), new_password.encode("utf-8")):
        return False
    if override is None:
        override = UserPasswordOverride(user_id=user.user_id, password_hash=hash_password(new_password))
        db.add(override)
    else:
        override.password_hash = hash_password(new_password)
        override.updated_at = datetime.now(timezone.utc)
    db.query(UserSession).filter(UserSession.user_id == user.user_id).delete(synchronize_session=False)
    db.commit()
    return True


def _hash_opaque_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_user_session(db: Session, user: UserPrincipal) -> tuple[str, str, int]:
    """Create a high-entropy opaque session and its separate CSRF token."""
    session_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    ttl_seconds = _session_ttl_seconds()
    db.add(
        UserSession(
            token_hash=_hash_opaque_token(session_token),
            csrf_token_hash=_hash_opaque_token(csrf_token),
            user_id=user.user_id,
            role=user.role.value,
            display_name=user.display_name,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds),
        )
    )
    db.commit()
    return session_token, csrf_token, ttl_seconds


def _session_ttl_seconds() -> int:
    try:
        ttl = int(os.getenv("MVP_SESSION_TTL_SECONDS", "28800"))
    except ValueError:
        return 28_800
    return min(max(ttl, 300), 86_400)


def _session_for_token(db: Session, token: str) -> UserSession | None:
    return db.get(UserSession, _hash_opaque_token(token))


def get_session_csrf_token(db: Session, token: str, csrf_token: str) -> str | None:
    """Return the stable CSRF nonce when it matches an active session hash."""
    session = _session_for_token(db, token)
    if session is None:
        return None
    expires_at = session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= datetime.now(timezone.utc):
        return None
    if not csrf_token or not hmac.compare_digest(_hash_opaque_token(csrf_token), session.csrf_token_hash):
        return None
    # The CSRF cookie is intentionally readable, but is not an auth credential;
    # only the separate HttpOnly session cookie authenticates requests.
    return csrf_token


def _verify_csrf(session: UserSession, request: Request) -> bool:
    csrf_cookie = request.cookies.get(CSRF_COOKIE_NAME, "")
    csrf_header = request.headers.get(CSRF_HEADER_NAME, "")
    if not csrf_header or not csrf_cookie:
        return False
    if not hmac.compare_digest(csrf_header, csrf_cookie):
        return False
    return hmac.compare_digest(_hash_opaque_token(csrf_header), session.csrf_token_hash)


def revoke_user_session(db: Session, request: Request) -> bool:
    """Revoke a cookie session only when the double-submit CSRF token is valid."""
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return True
    session = _session_for_token(db, token)
    if session is None:
        return True
    if not _verify_csrf(session, request):
        return False
    db.delete(session)
    db.commit()
    return True


def cookie_secure() -> bool:
    return os.getenv("AUTH_COOKIE_SECURE", "true").strip().lower() not in {"0", "false", "no"}

def cookie_samesite() -> str:
    value = os.getenv("AUTH_COOKIE_SAMESITE", "lax").strip().lower()
    if value not in {"lax", "strict", "none"}:
        return "lax"
    return value

def validate_login_origin(request: Request) -> bool:
    """Reject browser login submissions originating outside configured UI origins."""
    origin = request.headers.get("origin")
    if origin is None:
        return True
    allowed = {
        value.strip().rstrip("/")
        for value in os.getenv(
            "CORS_ALLOWED_ORIGINS",
            "http://localhost:5173,http://localhost:5174",
        ).split(",")
        if value.strip()
    }
    return origin.rstrip("/") in allowed


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)] = None,
) -> UserPrincipal:
    """Resolve a cookie session or legacy environment-configured Bearer principal."""
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if session_token:
        session = _session_for_token(db, session_token)
        if session is None:
            raise _authentication_error("invalid_session", "The sign-in session is invalid. Please sign in again.")
        expires_at = session.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= datetime.now(timezone.utc):
            db.delete(session)
            db.commit()
            raise _authentication_error("session_expired", "Your sign-in session expired. Please sign in again.")
        if request.method.upper() not in {"GET", "HEAD", "OPTIONS"} and not _verify_csrf(session, request):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"code": "csrf_validation_failed", "message": "The request could not be verified. Refresh and try again."},
            )
        db_account = db.get(UserAccount, session.user_id)
        if db_account is not None and not db_account.is_active:
            db.delete(session)
            db.commit()
            raise _authentication_error("account_disabled", "Your account has been deactivated. Please contact an administrator.")
        try:
            role = UserRole(session.role)
        except ValueError:
            db.delete(session)
            db.commit()
            raise _authentication_error("invalid_session", "The sign-in session is invalid. Please sign in again.")
        return UserPrincipal(session.user_id, role, session.display_name)

    if credentials is None:
        raise _authentication_error("authentication_required", "Bearer authentication is required")
    token = credentials.credentials
    for configured in _configured_users():
        if hmac.compare_digest(token.encode("utf-8"), configured["token"].encode("utf-8")):
            return UserPrincipal(
                user_id=configured["user_id"],
                role=UserRole(configured["role"]),
                display_name=configured.get("display_name"),
            )
    raise _authentication_error("invalid_authentication", "Invalid Bearer authentication")


def get_configured_credentials() -> list[dict[str, str]]:
    """Return configured user credentials without sensitive passwords/hashes."""
    return [
        {
            "username": item["username"],
            "user_id": item["user_id"],
            "role": item["role"],
            **({"display_name": item["display_name"]} if "display_name" in item else {}),
        }
        for item in _configured_credentials()
    ]


def count_active_admins(db: Session) -> int:
    """Return total active administrators across configured identities and database accounts."""
    configured_admins = sum(1 for entry in _configured_credentials() if entry.get("role") == UserRole.ADMIN.value)
    db_admins = (
        db.query(UserAccount)
        .filter(UserAccount.role == UserRole.ADMIN.value, UserAccount.is_active.is_(True))
        .count()
    )
    return configured_admins + db_admins


def _record_authorization_denial(
    db: Session,
    request: Request,
    user: UserPrincipal,
) -> None:
    correlation_id = uuid4()
    raw_correlation_id = request.headers.get("X-Correlation-ID")
    if raw_correlation_id:
        try:
            correlation_id = UUID(raw_correlation_id)
        except ValueError:
            pass
    record_audit_event(
        db,
        AuditEventCreate(
            actor_type="user",
            actor_id=user.user_id,
            action="authorization.denied",
            result_status="rejected",
            resource_type="api_endpoint",
            source_component="api",
            reason="User role does not permit this operation",
            safe_metadata={"method": request.method, "path": request.url.path, "role": user.role.value},
            correlation_id=correlation_id,
        ),
    )
    db.commit()


def require_role(*allowed_roles: UserRole):
    """Return a dependency requiring one of the listed roles or admin."""
    accepted_roles = set(allowed_roles) | {UserRole.ADMIN}

    def dependency(
        request: Request,
        current_user: UserPrincipal = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> UserPrincipal:
        if current_user.role not in accepted_roles:
            _record_authorization_denial(db, request, current_user)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"code": "forbidden", "message": "Insufficient permissions"},
            )
        return current_user

    return dependency
