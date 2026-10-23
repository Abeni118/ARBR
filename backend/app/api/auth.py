from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models import UserAccount
from app.schemas import (
    AuditEventCreate,
    AuthenticatedUser,
    ChangePasswordRequest,
    LoginRequest,
    RegisterRequest,
    UserAccountRead,
)
from app.services.audit import record_audit_event
from app.services.user_auth import (
    CSRF_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    UserPrincipal,
    UserRole,
    authenticate_password,
    cookie_secure,
    cookie_samesite,
    change_user_password,
    get_session_csrf_token,
    get_current_user,
    hash_password,
    is_configured_username,
    issue_user_session,
    revoke_user_session,
    validate_login_origin,
)


router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post("/register", response_model=UserAccountRead, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    """Register a new user account with least-privileged viewer role."""
    if not validate_login_origin(request):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "untrusted_origin", "message": "Registration request origin is not allowed."},
        )

    normalized_username = payload.username.strip().casefold()
    if is_configured_username(normalized_username):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "username_already_exists", "message": "An account with this username already exists."},
        )

    existing = db.query(UserAccount).filter(UserAccount.username_normalized == normalized_username).first()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "username_already_exists", "message": "An account with this username already exists."},
        )

    # Always enforce the least-privileged permitted role (viewer) for self-registration
    account = UserAccount(
        username=payload.username.strip(),
        username_normalized=normalized_username,
        display_name=payload.display_name,
        role=UserRole.VIEWER.value,
        password_hash=hash_password(payload.password),
        is_active=True,
        created_by_user_id="public_registration",
    )
    db.add(account)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "username_already_exists", "message": "An account with this username already exists."},
        ) from exc

    record_audit_event(
        db,
        AuditEventCreate(
            actor_type="user",
            actor_id=account.user_id,
            action="user_account.registered",
            result_status="success",
            resource_type="user_account",
            resource_id=account.user_id,
            source_component="api",
            reason="Public user completed self-registration with least-privileged viewer role",
            safe_metadata={"username": account.username, "role": account.role},
            correlation_id=uuid4(),
        ),
    )
    db.commit()
    db.refresh(account)
    return UserAccountRead.model_validate(account)


def _authenticated_user(user: UserPrincipal, csrf_token: str) -> AuthenticatedUser:
    return AuthenticatedUser(
        user_id=user.user_id,
        role=user.role.value,
        display_name=user.display_name,
        csrf_token=csrf_token,
    )


@router.post("/login", response_model=AuthenticatedUser)
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    if not validate_login_origin(request):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail={"code": "untrusted_origin", "message": "Sign-in request origin is not allowed."})
    user = authenticate_password(payload.username, payload.password, db)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "invalid_credentials", "message": "Username or password is incorrect."},
        )
    session_token, csrf_token, ttl_seconds = issue_user_session(db, user)
    secure = cookie_secure()
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_token,
        max_age=ttl_seconds,
        httponly=True,
        secure=secure,
        samesite=cookie_samesite(),
        path="/",
    )
    response.set_cookie(
        CSRF_COOKIE_NAME,
        csrf_token,
        max_age=ttl_seconds,
        httponly=False,
        secure=secure,
        samesite=cookie_samesite(),
        path="/",
    )
    return _authenticated_user(user, csrf_token)


@router.get("/me", response_model=AuthenticatedUser)
def current_user(
    request: Request,
    db: Session = Depends(get_db),
    user: UserPrincipal = Depends(get_current_user),
):
    session_token = request.cookies.get(SESSION_COOKIE_NAME, "")
    csrf_header = request.headers.get("X-CSRF-Token", "")
    csrf_cookie = request.cookies.get(CSRF_COOKIE_NAME, "")
    csrf_token = get_session_csrf_token(db, session_token, csrf_cookie or csrf_header) if session_token else None
    return _authenticated_user(user, csrf_token or "")


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, db: Session = Depends(get_db)):
    if not revoke_user_session(db, request):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "csrf_validation_failed", "message": "The request could not be verified. Refresh and try again."},
        )
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    secure = cookie_secure()
    response.delete_cookie(SESSION_COOKIE_NAME, path="/", secure=secure, httponly=True, samesite=cookie_samesite())
    response.delete_cookie(CSRF_COOKIE_NAME, path="/", secure=secure, httponly=False, samesite=cookie_samesite())
    return response


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: UserPrincipal = Depends(get_current_user),
):
    if not validate_login_origin(request):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail={"code": "untrusted_origin", "message": "Password change request origin is not allowed."})
    if not change_user_password(db, user, payload.current_password, payload.new_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "password_change_rejected", "message": "Current password is incorrect, or the new password is not acceptable."},
        )
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    secure = cookie_secure()
    response.delete_cookie(SESSION_COOKIE_NAME, path="/", secure=secure, httponly=True, samesite=cookie_samesite())
    response.delete_cookie(CSRF_COOKIE_NAME, path="/", secure=secure, httponly=False, samesite=cookie_samesite())
    return response