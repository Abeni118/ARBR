"""Secure CLI bootstrap tool to provision the initial system administrator.

This tool is strictly intended for authorized system operators running locally.
It provisions an administrator account directly in the application database
without relying on hardcoded credentials or exposing public admin endpoints.
"""

import argparse
import getpass
import re
import sys
from uuid import uuid4

from sqlalchemy.orm import Session

from app.database.init_db import initialize_database
from app.database.session import SessionLocal
from app.models import AuditEvent, UserAccount
from app.services.audit import record_audit_event
from app.services.user_auth import UserRole, hash_password, is_configured_username
from app.schemas import AuditEventCreate


def parse_args():
    parser = argparse.ArgumentParser(description="Bootstrap an initial administrator account for ARBR.")
    parser.add_argument("--username", help="Administrator username (3–64 alphanumeric characters, dot, dash, underscore)")
    parser.add_argument("--password", help="Administrator password (minimum 12 characters)")
    parser.add_argument("--display-name", help="Optional display name for the administrator")
    return parser.parse_args()


def main():
    args = parse_args()

    # Ensure database tables exist
    initialize_database()

    username = args.username
    if not username:
        username = input("Administrator username: ").strip()
    else:
        username = username.strip()

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}", username):
        print("Error: Username must be 3–64 characters and contain only letters, numbers, '.', '_', or '-'.", file=sys.stderr)
        sys.exit(1)

    password = args.password
    if not password:
        password = getpass.getpass("Administrator password (min 12 chars): ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Error: Passwords do not match.", file=sys.stderr)
            sys.exit(1)

    if len(password) < 12:
        print("Error: Password must be at least 12 characters long.", file=sys.stderr)
        sys.exit(1)

    display_name = args.display_name
    if not display_name and not args.username:
        display_name = input("Display name (optional, press Enter for 'System Administrator'): ").strip() or "System Administrator"
    elif not display_name:
        display_name = "System Administrator"

    normalized_username = username.casefold()

    with SessionLocal() as db:
        if is_configured_username(normalized_username):
            print(f"Notice: Username '{username}' is already configured via environment variables.", file=sys.stderr)

        existing_account = (
            db.query(UserAccount)
            .filter(UserAccount.username_normalized == normalized_username)
            .one_or_none()
        )

        hashed = hash_password(password)

        if existing_account:
            existing_account.role = UserRole.ADMIN.value
            existing_account.is_active = True
            existing_account.password_hash = hashed
            if display_name:
                existing_account.display_name = display_name
            target_id = existing_account.user_id
            action_desc = "Updated existing account to active administrator"
        else:
            new_account = UserAccount(
                username=username,
                username_normalized=normalized_username,
                display_name=display_name,
                role=UserRole.ADMIN.value,
                password_hash=hashed,
                is_active=True,
                created_by_user_id="bootstrap_cli",
            )
            db.add(new_account)
            db.flush()
            target_id = new_account.user_id
            action_desc = "Provisioned new initial administrator account"

        record_audit_event(
            db,
            AuditEventCreate(
                actor_type="system",
                actor_id="bootstrap_cli",
                action="user_account.bootstrapped",
                result_status="success",
                resource_type="user_account",
                resource_id=target_id,
                source_component="cli",
                reason=action_desc,
                safe_metadata={"username": username, "role": UserRole.ADMIN.value},
                correlation_id=uuid4(),
            ),
        )
        db.commit()

        print(f"Success: {action_desc} for '{username}' (ID: {target_id}).")


if __name__ == "__main__":
    main()
