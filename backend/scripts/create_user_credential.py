"""Interactively generate one password-hashed MVP user configuration entry."""

import getpass
import json

from app.services.user_auth import UserRole, hash_password


def main() -> None:
    username = input("Username: ").strip()
    user_id = input("Stable user ID: ").strip()
    role = input(f"Role ({', '.join(role.value for role in UserRole)}): ").strip()
    display_name = input("Display name (optional): ").strip()
    if not username or not user_id:
        raise SystemExit("Username and stable user ID are required.")
    try:
        UserRole(role)
    except ValueError as exc:
        raise SystemExit("Choose a supported role.") from exc

    password = getpass.getpass("Password (minimum 12 characters): ")
    confirmation = getpass.getpass("Confirm password: ")
    if len(password) < 12:
        raise SystemExit("Password must be at least 12 characters.")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")

    entry = {
        "username": username,
        "user_id": user_id,
        "role": role,
        "password_hash": hash_password(password),
    }
    if display_name:
        entry["display_name"] = display_name
    print(json.dumps(entry))


if __name__ == "__main__":
    main()