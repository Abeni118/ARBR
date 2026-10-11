"""
demo.py - Runs realistic attack scenarios through the Decision Engine.

Purpose:
    Lets you (and your team) SEE the engine working without needing the
    other members' components. Each scenario builds fake events and
    backups, asks the engine for a decision, and prints the result.

Run it from the PROJECT ROOT (the folder that contains backend/):

    python -m backend.app.decision.demo

Note: use `-m` with dots, NOT `python backend/app/decision/demo.py`.
The `-m` form is what makes the relative imports inside the package work.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List, Optional

from .decision_engine import DecisionEngine
from .decision_logger import DecisionLogger
from .models import BackupStatus, Decision, SecurityEvent


# ---------------------------------------------------------------------------
# Helpers to build fake data quickly
# ---------------------------------------------------------------------------

def make_event(
    event_id: str,
    event_type: str,
    severity: int,
    source: str,
    minutes_ago: float = 2,
) -> SecurityEvent:
    """Create a SecurityEvent that happened `minutes_ago` minutes ago.

    We keep events within the last 10 minutes so they count at full
    weight in the risk scorer (older events are weighted less).
    """
    return SecurityEvent(
        event_id=event_id,
        timestamp=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago),
        source=source,
        event_type=event_type,
        severity=severity,
    )


def make_backup(
    backup_id: str,
    hours_ago: float,
    verified: bool = True,
    trusted: bool = True,
) -> BackupStatus:
    """Create a BackupStatus that was made `hours_ago` hours ago."""
    return BackupStatus(
        backup_id=backup_id,
        timestamp=datetime.now(timezone.utc) - timedelta(hours=hours_ago),
        integrity_verified=verified,
        trusted=trusted,
        location=f"/backups/{backup_id}",
    )


# ---------------------------------------------------------------------------
# Printing
# ---------------------------------------------------------------------------

def print_decision(title: str, decision: Decision) -> None:
    """Show one decision in a readable layout."""
    line = "=" * 70
    print(f"\n{line}\n{title}\n{line}")
    print(f"Action     : {decision.action.value}")
    print(
        f"Risk       : {decision.risk_assessment.risk_score} "
        f"({decision.risk_assessment.risk_level.value})"
    )
    print(f"Confidence : {decision.confidence:.2f}")
    print(f"Reason     : {decision.reason}")

    print("Risk factors:")
    for factor in decision.risk_assessment.factors:
        print(f"  - {factor}")

    print("Steps to execute:")
    if decision.actions_to_execute:
        for step in decision.actions_to_execute:
            print(f"  -> {step}")
    else:
        print("  (none)")


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

def run_demo() -> None:
    """Run every scenario and print a summary table at the end."""
    engine = DecisionEngine()
    # log_file=None keeps the demo's records in memory only, so running
    # the demo never creates files in your project.
    audit = DecisionLogger(log_file=None)

    # A list of (title, events, backups) for each scenario.
    scenarios: List[tuple] = []

    # 1. A quiet day: nothing detected.
    scenarios.append(("1. Quiet day (no events)", [], []))

    # 2. Someone is guessing passwords and then gets in.
    scenarios.append((
        "2. Suspected brute-force login",
        [
            make_event("e2a", "failed_login", 8, "auth_service", 5),
            make_event("e2b", "failed_login", 8, "auth_service", 4),
            make_event("e2c", "failed_login", 8, "auth_service", 3),
            make_event("e2d", "unauthorized_access", 9, "network_ids", 1),
        ],
        [],
    ))

    # 3. A single event, but it targets the backups themselves.
    scenarios.append((
        "3. Someone tries to delete a backup",
        [make_event("e3a", "backup_deletion_attempt", 6, "backup_agent")],
        [make_backup("bkp-1", 3)],
    ))

    # 4. An attacker is spreading and tampering with backups.
    scenarios.append((
        "4. Attacker spreading through the network",
        [
            make_event("e4a", "privilege_escalation", 9, "ad_monitor", 6),
            make_event("e4b", "lateral_movement", 8, "ad_monitor", 4),
            make_event("e4c", "backup_tampering", 10, "backup_agent", 1),
        ],
        [make_backup("bkp-1", 3)],
    ))

    # 5. Ransomware, and safe backups exist -> RECOVER.
    scenarios.append((
        "5. Ransomware attack, safe backup available",
        [
            make_event("e5a", "mass_file_encryption", 9, "file_monitor", 3),
            make_event("e5b", "backup_deletion_attempt", 8, "backup_agent", 2),
        ],
        [
            make_backup("bkp-0", 24),                 # good but older
            make_backup("bkp-1", 6),                  # good and newest safe one
            make_backup("bkp-2", 3, trusted=False),   # newer but NOT trusted
        ],
    ))

    # 6. Same ransomware, but no backup is safe -> ISOLATE, not RECOVER.
    scenarios.append((
        "6. Ransomware attack, NO safe backup",
        [
            make_event("e6a", "mass_file_encryption", 9, "file_monitor", 3),
            make_event("e6b", "backup_deletion_attempt", 8, "backup_agent", 2),
        ],
        [
            make_backup("bkp-1", 6, verified=False),
            make_backup("bkp-2", 3, trusted=False),
        ],
    ))

    # Run them all.
    results: List[tuple] = []
    for title, events, backups in scenarios:
        decision = engine.decide(events, backups)
        audit.log(decision)
        print_decision(title, decision)
        results.append((title, decision))

    # Summary table.
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"{'Scenario':<47} {'Risk':>6}  {'Action':<8}")
    for title, decision in results:
        print(
            f"{title:<47} "
            f"{decision.risk_assessment.risk_score:>6}  "
            f"{decision.action.value:<8}"
        )
    print(f"\nDecisions recorded in the audit trail: {len(audit.get_history())}")


if __name__ == "__main__":
    run_demo()