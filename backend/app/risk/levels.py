from app.enums import RiskLevel

DEFAULT_RISK_THRESHOLDS = {
    "low_min": 0,
    "low_max": 29,
    "medium_min": 30,
    "medium_max": 59,
    "high_min": 60,
    "high_max": 79,
    "critical_min": 80,
    "critical_max": 100,
}


def risk_level_for_score(score: int, thresholds: dict[str, int] | None = None) -> RiskLevel:
    """Map an integer 0–100 risk score to the shared project risk band."""
    if not 0 <= score <= 100:
        raise ValueError("Risk score must be between 0 and 100")
    bands = thresholds or DEFAULT_RISK_THRESHOLDS
    if score <= bands["low_max"]:
        return RiskLevel.LOW
    if score <= bands["medium_max"]:
        return RiskLevel.MEDIUM
    if score <= bands["high_max"]:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL