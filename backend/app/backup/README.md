# Backup Protection & Integrity

This module handles backup creation, verification, tamper detection, and
immutable locking for recovery points.

## Files

- integrity.py — SHA-256 hashing for files and directory trees
- verification.py — Trust-on-first-hash workflow and tamper detection
- protection.py — Immutable lock via Linux chattr +i (FR-B03)
- backup_manager.py — rsync-based backup creation (Naaol)
- storage_manager.py — Recovery point storage layout (Naaol)
- recovery_point.py — RecoveryPoint data model (Naaol)

## Requirements Covered

- FR-B01 — Create and manage scheduled backups
- FR-B02 — Generate and store a cryptographic hash for every backup set
- FR-B03 — Apply an immutable lock to backups when risk is High or Critical
- FR-B04 — Detect and alert on any backup tampering
- FR-B06 — Retain a rolling history of recovery points

## Quick Usage

### Hashing and verification

`python
from backend.app.backup.integrity import calculate_directory_sha256
from backend.app.backup.verification import (
    write_trusted_hash,
    verify_recovery_point,
)

# Record a trusted hash after creating a backup:
write_trusted_hash(destination_path, backup_id, storage_dir)

# Verify later, before recovery:
result = verify_recovery_point(recovery_point, storage_dir)
if result.is_intact:
    ...