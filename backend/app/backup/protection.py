"""
Backup protection via Linux immutable file attributes.

Implements FR-B03: apply an immutable lock to backup sets when the risk
level is High or Critical. Uses the Linux chattr +i command, which sets
the immutable flag on files. Immutable files cannot be modified, deleted,
or renamed — even by root — until the flag is removed.

On non-Linux systems (e.g. Windows during development), the underlying
chattr/lsattr commands are unavailable. All functions handle that
gracefully and return a structured result rather than raising.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import logging
import platform
import subprocess


logger = logging.getLogger(__name__)

CHATTR_COMMAND = "chattr"
LSATTR_COMMAND = "lsattr"
IMMUTABLE_FLAG = "i"


@dataclass
class LockResult:
    path: str
    success: bool
    file_count: int
    attempted_at: str
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "success": self.success,
            "file_count": self.file_count,
            "attempted_at": self.attempted_at,
            "error": self.error,
        }


def _is_linux() -> bool:
    return platform.system() == "Linux"


def _iter_targets(root: Path):
    """Yield every file and directory under root (including root itself)."""
    yield root
    for item in root.rglob("*"):
        yield item


def _run_chattr(flag: str, target: Path) -> None:
    """Run chattr <flag> <target> and raise on failure."""
    subprocess.run(
        [CHATTR_COMMAND, flag, str(target)],
        check=True,
        capture_output=True,
        text=True,
    )


def lock_backup(directory_path: str | Path) -> LockResult:
    """
    Recursively apply the immutable flag to a backup directory.

    Files are processed first, then directories, then the root. This order
    matters: chattr refuses to modify a directory that has immutable
    children until they are handled.

    Returns a LockResult — never raises for the common failure modes.
    """
    root = Path(directory_path)
    attempted_at = datetime.now(timezone.utc).isoformat()

    if not root.exists():
        return LockResult(
            path=str(root),
            success=False,
            file_count=0,
            attempted_at=attempted_at,
            error="Backup directory does not exist.",
        )

    if not root.is_dir():
        return LockResult(
            path=str(root),
            success=False,
            file_count=0,
            attempted_at=attempted_at,
            error="Path is not a directory.",
        )

    if not _is_linux():
        return LockResult(
            path=str(root),
            success=False,
            file_count=0,
            attempted_at=attempted_at,
            error=f"Immutable locking requires Linux; current OS is {platform.system()}.",
        )

    # Files first, then directories deepest-first, then root.
    all_items = list(_iter_targets(root))
    files = [p for p in all_items if p.is_file()]
    directories = sorted(
        (p for p in all_items if p.is_dir()),
        key=lambda p: len(p.parts),
        reverse=True,
    )

    processed = 0
    try:
        for target in files + directories:
            _run_chattr(f"+{IMMUTABLE_FLAG}", target)
            processed += 1
    except subprocess.CalledProcessError as error:
        logger.error("chattr failed on %s: %s", target, error.stderr)
        return LockResult(
            path=str(root),
            success=False,
            file_count=processed,
            attempted_at=attempted_at,
            error=f"chattr failed: {error.stderr.strip()}",
        )
    except FileNotFoundError:
        return LockResult(
            path=str(root),
            success=False,
            file_count=processed,
            attempted_at=attempted_at,
            error="chattr command not found on this system.",
        )
    logger.info("Locked %d items under %s", processed, root)
    return LockResult(
        path=str(root),
        success=True,
        file_count=processed,
        attempted_at=attempted_at,
    )


def unlock_backup(directory_path: str | Path) -> LockResult:
    """
    Recursively remove the immutable flag from a backup directory.

    Must be called before recovery can restore or replace files. Order is
    reversed from locking: root directory first, then deeper directories,
    then files.
    """
    root = Path(directory_path)
    attempted_at = datetime.now(timezone.utc).isoformat()

    if not root.exists():
        return LockResult(
            path=str(root),
            success=False,
            file_count=0,
            attempted_at=attempted_at,
            error="Backup directory does not exist.",
        )

    if not _is_linux():
        return LockResult(
            path=str(root),
            success=False,
            file_count=0,
            attempted_at=attempted_at,
            error=f"Immutable locking requires Linux; current OS is {platform.system()}.",
        )

    all_items = list(_iter_targets(root))
    directories = sorted(
        (p for p in all_items if p.is_dir()),
        key=lambda p: len(p.parts),
    )
    files = [p for p in all_items if p.is_file()]

    processed = 0
    try:
        for target in directories + files:
            _run_chattr(f"-{IMMUTABLE_FLAG}", target)
            processed += 1
    except subprocess.CalledProcessError as error:
        return LockResult(
            path=str(root),
            success=False,
            file_count=processed,
            attempted_at=attempted_at,
            error=f"chattr failed: {error.stderr.strip()}",
        )
    except FileNotFoundError:
        return LockResult(
            path=str(root),
            success=False,
            file_count=processed,
            attempted_at=attempted_at,
            error="chattr command not found on this system.",
        )

    logger.info("Unlocked %d items under %s", processed, root)
    return LockResult(
        path=str(root),
        success=True,
        file_count=processed,
        attempted_at=attempted_at,
    )


def is_locked(directory_path: str | Path) -> bool:
    """
    Return True if the directory currently has the immutable flag set.

    Uses lsattr -d on the directory itself. Returns False on any error
    (non-Linux, missing path, permission denied).
    """
    root = Path(directory_path)

    if not root.exists() or not _is_linux():
        return False

    try:
        result = subprocess.run(
            [LSATTR_COMMAND, "-d", str(root)],
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

    # lsattr output format: "<flags> <path>" — immutable flag is 'i'.
    first_line = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
    flags = first_line.split(maxsplit=1)[0] if first_line else ""
    return IMMUTABLE_FLAG in flags