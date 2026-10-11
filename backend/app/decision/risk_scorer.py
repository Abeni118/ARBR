"""
risk_scorer.py - Turns security events into a risk score (0-100).

How the scoring works, in plain English:

    1. Every event type has a BASE WEIGHT (ransomware behaviour is worse
       than a single failed login).
    2. That weight is scaled by the event's SEVERITY (1-10).
    3. It is scaled again by RECENCY: fresh events matter more than old ones.
    4. All event scores are added up.
    5. CORRELATION BONUSES are added when events combine in dangerous ways
       (e.g. file encryption + backup deletion = classic ransomware).
    6. The total is capped at 100 and converted to a RiskLevel label.

Everything is kept simple and in one place so you can tune the numbers
easily and explain them to your team.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Tuple

from .models import RiskAssessment, SecurityEvent


# ---------------------------------------------------------------------------
# Tunable settings (change these numbers to adjust the engine's behaviour)
# ---------------------------------------------------------------------------

# Base danger of each event type, on a rough 0-40 scale.
# Event types not in this dict use DEFAULT_EVENT_WEIGHT.
EVENT_WEIGHTS: Dict[str, float] = {
    "mass_file_encryption": 40,
    "ransomware_note_detected": 40,
    "backup_deletion_attempt": 35,
    "backup_tampering": 35,
    "privilege_escalation": 25,
    "lateral_movement": 25,
    "suspicious_process": 15,
    "unauthorized_access": 15,
    "failed_login": 5,
}
DEFAULT_EVENT_WEIGHT: float = 8

# Recency multipliers: (maximum age in minutes, multiplier).
# Checked from top to bottom; the first match wins.
RECENCY_BRACKETS: List[Tuple[float, float]] = [
    (10, 1.0),        # last 10 minutes  -> full weight
    (60, 0.7),        # last hour        -> 70%
    (24 * 60, 0.4),   # last 24 hours    -> 40%
]
OLD_EVENT_MULTIPLIER: float = 0.1  # anything older still counts a little

# Bonus points when certain event types appear TOGETHER.
# Each entry: (set of required event types, bonus points, explanation).
CORRELATION_RULES: List[Tuple[frozenset, float, str]] = [
    (
        frozenset({"mass_file_encryption", "backup_deletion_attempt"}),
        20,
        "Correlated: file encryption together with backup deletion "
        "(typical ransomware pattern)",
    ),
    (
        frozenset({"privilege_escalation", "lateral_movement"}),
        15,
        "Correlated: privilege escalation with lateral movement "
        "(attacker spreading through the network)",
    ),
    (
        frozenset({"failed_login", "unauthorized_access"}),
        10,
        "Correlated: failed logins followed by unauthorized access "
        "(possible brute-force success)",
    ),
]

# Bonus when many DIFFERENT kinds of events happen at once.
DIVERSITY_THRESHOLD: int = 3
DIVERSITY_BONUS: float = 10


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _recency_multiplier(event_time: datetime, now: datetime) -> float:
    """Return how much an event should count based on how old it is.

    Args:
        event_time: When the event happened.
        now:        The current time (passed in so tests can control it).

    Returns:
        A number between 0.1 and 1.0.
    """
    # If a timestamp has no timezone info ("naive"), assume it is UTC.
    # Without this, subtracting naive and aware datetimes would crash.
    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=timezone.utc)

    age_minutes = (now - event_time).total_seconds() / 60

    # Events "from the future" (clock differences) count as brand new.
    if age_minutes < 0:
        age_minutes = 0

    for max_age, multiplier in RECENCY_BRACKETS:
        if age_minutes <= max_age:
            return multiplier
    return OLD_EVENT_MULTIPLIER


def _score_single_event(event: SecurityEvent, now: datetime) -> float:
    """Calculate the risk points contributed by ONE event.

    Formula:  base_weight * (severity / 10) * recency_multiplier
    """
    base_weight = EVENT_WEIGHTS.get(event.event_type, DEFAULT_EVENT_WEIGHT)
    severity_factor = event.severity / 10  # 1-10 becomes 0.1-1.0
    return base_weight * severity_factor * _recency_multiplier(event.timestamp, now)


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class RiskScorer:
    """Calculates a RiskAssessment from a list of SecurityEvents.

    Example:
        scorer = RiskScorer()
        assessment = scorer.assess(events)
        print(assessment.risk_score, assessment.risk_level)
    """

    def assess(
        self,
        events: List[SecurityEvent],
        now: datetime | None = None,
    ) -> RiskAssessment:
        """Analyse events and return a RiskAssessment.

        Args:
            events: The security events to analyse (can be empty).
            now:    Optional "current time". Leave it out in real use;
                    it exists so you can test with fixed times.

        Returns:
            A RiskAssessment with score, level, factors and timestamp.
        """
        if now is None:
            now = datetime.now(timezone.utc)

        # No events means nothing suspicious: lowest possible risk.
        if not events:
            return RiskAssessment(
                risk_score=0,
                risk_level=RiskAssessment.level_from_score(0),
                factors=["No security events detected"],
                timestamp=now,
            )

        total = 0.0
        factors: List[str] = []

        # Step 1-3: score each event and record why.
        for event in events:
            points = _score_single_event(event, now)
            total += points
            factors.append(
                f"{event.event_type} from {event.source} "
                f"(severity {event.severity}/10): +{points:.1f}"
            )

        # Step 5: correlation bonuses for dangerous combinations.
        present_types = {event.event_type for event in events}
        for required_types, bonus, explanation in CORRELATION_RULES:
            # issubset: are ALL required types present in this batch?
            if required_types.issubset(present_types):
                total += bonus
                factors.append(f"{explanation}: +{bonus:.1f}")

        # Bonus for many different event types at the same time.
        if len(present_types) >= DIVERSITY_THRESHOLD:
            total += DIVERSITY_BONUS
            factors.append(
                f"{len(present_types)} different event types detected "
                f"at once: +{DIVERSITY_BONUS:.1f}"
            )

        # Step 6: cap at 100 (and never go below 0), then round for tidiness.
        final_score = round(max(0.0, min(100.0, total)), 1)

        return RiskAssessment(
            risk_score=final_score,
            risk_level=RiskAssessment.level_from_score(final_score),
            factors=factors,
            timestamp=now,
        )