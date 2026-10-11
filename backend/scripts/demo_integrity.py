"""
Live demo of backup integrity verification.

Run from the repository root:

    py backend/scripts/demo_integrity.py
"""

import shutil
import sys
import tempfile
from pathlib import Path

# Allow running as py backend/scripts/demo_integrity.py from the repo root.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.app.backup.recovery_point import RecoveryPoint
from backend.app.backup.verification import (
    verify_recovery_point,
    write_trusted_hash,
)


LINE = "=" * 68


def make_recovery_point(backup_id, destination):
    return RecoveryPoint.create(
        backup_id=backup_id,
        source_path="/demo/source",
        destination_path=str(destination),
        status="COMPLETED",
        file_count=2,
        size_bytes=64,
    )


def show(label, result):
    icon = {
        "VERIFIED": "[OK]",
        "TAMPERED": "[!!]",
        "MISSING": "[XX]",
        "UNVERIFIED": "[??]",
    }.get(result.status, "[??]")

    print(f"  {icon} {label}")
    print(f"      status        : {result.status}")
    print(f"      is_intact     : {result.is_intact}")
    print(f"      expected_hash : {result.expected_hash}")
    print(f"      actual_hash   : {result.actual_hash}")
    if result.error:
        print(f"      error         : {result.error}")


def main():
    print()
    print(LINE)
    print("  BACKUP INTEGRITY DEMO - Attack-Resistant Backup & Recovery")
    print(LINE)

    with tempfile.TemporaryDirectory(prefix="integrity_demo_") as tmp:
        workspace = Path(tmp)
        storage_dir = workspace / "storage"
        backup_dir = workspace / "recovery-point-001"
        backup_id = "demo-backup-001"

        storage_dir.mkdir(parents=True, exist_ok=True)
        backup_dir.mkdir(parents=True, exist_ok=True)
        (backup_dir / "database.sql").write_text("important customer data")
        (backup_dir / "config.yaml").write_text("app: demo")

        write_trusted_hash(backup_dir, backup_id, storage_dir)
        recovery_point = make_recovery_point(backup_id, backup_dir)

        print()
        print("  SCENARIO 1: Intact backup (should be VERIFIED)")
        print("  " + "-" * 64)
        result = verify_recovery_point(recovery_point, storage_dir)
        show("Result", result)

        print()
        print("  SCENARIO 2: Tampered backup (should be TAMPERED)")
        print("  " + "-" * 64)
        (backup_dir / "database.sql").write_text("important customer data TAMPERED")
        result = verify_recovery_point(recovery_point, storage_dir)
        show("Result", result)

        print()
        print("  SCENARIO 3: Deleted backup (should be MISSING)")
        print("  " + "-" * 64)
        shutil.rmtree(backup_dir)
        result = verify_recovery_point(recovery_point, storage_dir)
        show("Result", result)

        print()
        print("  SCENARIO 4: No trusted hash (should be UNVERIFIED)")
        print("  " + "-" * 64)
        orphan_dir = workspace / "orphan-backup"
        orphan_dir.mkdir()
        (orphan_dir / "database.sql").write_text("data")
        orphan_rp = make_recovery_point("orphan-backup", orphan_dir)
        result = verify_recovery_point(orphan_rp, storage_dir)
        show("Result", result)

    print()
    print(LINE)
    print("  DEMO COMPLETE")
    print(LINE)
    print()


if __name__ == "__main__":
    main()