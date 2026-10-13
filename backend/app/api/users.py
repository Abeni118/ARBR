from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models import UserAccount, UserSession
from app.schemas import AuditEventCreate, UserAccountCreate, UserAccountRead, UserAccountUpdate
from app.services.audit import record_audit_event
from app.services.user_auth import (
    UserPrincipal,
    UserRole,
    count_active_admins,
    get_configured_credentials,
    get_current_user,
    hash_password,
    is_configured_username,
    require_role,
)

router = APIRouter(prefix="/api/users", tags=["Human user administration"], dependencies=[Depends(get_current_user)])


@router.get("", response_model=list[UserAccountRead])
def list_users(
    _admin: UserPrincipal = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
):
    """List all user accounts including database-provisioned and configured identities."""
    results: list[UserAccountRead] = []

    # Configured identities from environment
    for item in get_configured_credentials():
        results.append(
            UserAccountRead(
                user_id=item["user_id"],
                username=item["username"],
                display_name=item.get("display_name"),
                role=item["role"],
                is_active=True,
                created_by_user_id="system",
                created_at=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
                source="configured",
            )
        )

    # Database-managed accounts
    db_accounts = db.query(UserAccount).order_by(UserAccount.created_at.desc(), UserAccount.username_normalized).all()
    for account in db_accounts:
        results.append(UserAccountRead.model_validate(account))

    return results


@router.get("/{user_id}", response_model=UserAccountRead)
def get_user_details(
    user_id: str,
    _admin: UserPrincipal = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
):
    """View details of a specific account without exposing password hashes or secrets."""
    account = db.get(UserAccount, user_id)
    if account is not None:
        return UserAccountRead.model_validate(account)

    for item in get_configured_credentials():
        if item["user_id"] == user_id:
            return UserAccountRead(
                user_id=item["user_id"],
                username=item["username"],
                display_name=item.get("display_name"),
                role=item["role"],
                is_active=True,
                created_by_user_id="system",
                created_at=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
                source="configured",
            )

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"code": "user_not_found", "message": "User not found."})


@router.post("", response_model=UserAccountRead, status_code=status.HTTP_201_CREATED)
def create_provisioned_user(
    payload: UserAccountCreate,
    current_user: UserPrincipal = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
):
    """Create an operations account at an admin's direction; public registration is not supported."""
    normalized_username = payload.username.casefold()
    if is_configured_username(normalized_username):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "username_already_exists", "message": "An account with this username already exists."},
        )

    account = UserAccount(
        username=payload.username,
        username_normalized=normalized_username,
        display_name=payload.display_name,
        role=payload.role,
        password_hash=hash_password(payload.initial_password),
        is_active=True,
        created_by_user_id=current_user.user_id,
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
            actor_id=current_user.user_id,
            action="user_account.created",
            result_status="success",
            resource_type="user_account",
            resource_id=account.user_id,
            source_component="api",
            reason="Administrator provisioned a non-admin operations account",
            safe_metadata={"username": account.username, "role": account.role},
            correlation_id=uuid4(),
        ),
    )
    db.commit()
    db.refresh(account)
    return UserAccountRead.model_validate(account)


@router.patch("/{user_id}", response_model=UserAccountRead)
def update_user_account(
    user_id: str,
    payload: UserAccountUpdate,
    current_user: UserPrincipal = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
):
    """Update role or account status; prevents removing the last active administrator."""
    # Check if this is an environment-configured identity
    for item in get_configured_credentials():
        if item["user_id"] == user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "code": "configured_account_immutable",
                    "message": "Environment-managed identities must be modified through system configuration.",
                },
            )

    account = db.get(UserAccount, user_id)
    if account is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "user_not_found", "message": "User not found."},
        )

    # Check if deactivating or demoting the last active administrator
    is_active_admin = account.role == UserRole.ADMIN.value and account.is_active
    will_deactivate = payload.is_active is False and is_active_admin
    will_demote = payload.role is not None and payload.role != UserRole.ADMIN.value and is_active_admin

    if will_deactivate or will_demote:
        total_admins = count_active_admins(db)
        if total_admins <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "code": "cannot_remove_last_admin",
                    "message": "Cannot deactivate or demote the last active administrator.",
                },
            )

    old_role = account.role
    old_active = account.is_active

    if payload.role is not None:
        account.role = payload.role
    if payload.is_active is not None:
        account.is_active = payload.is_active
    if payload.display_name is not None:
        account.display_name = payload.display_name

    # If account was deactivated or role changed, revoke active sessions
    if (payload.is_active is False and old_active) or (payload.role is not None and payload.role != old_role):
        db.query(UserSession).filter(UserSession.user_id == account.user_id).delete(synchronize_session=False)

    record_audit_event(
        db,
        AuditEventCreate(
            actor_type="user",
            actor_id=current_user.user_id,
            action="user_account.updated",
            result_status="success",
            resource_type="user_account",
            resource_id=account.user_id,
            source_component="api",
            reason="Administrator updated user account role or activation status",
            safe_metadata={
                "username": account.username,
                "role": account.role,
                "is_active": account.is_active,
                "previous_role": old_role,
                "previous_active": old_active,
            },
            correlation_id=uuid4(),
        ),
    )
    db.commit()
    db.refresh(account)
    return UserAccountRead.model_validate(account)
