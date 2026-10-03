from .enums import RiskLevel


def risk_level_for_score(score: int) -> RiskLevel:
    """Map an integer 0–100 risk score to the shared project risk band."""
    if not 0 <= score <= 100:
        raise ValueError("Risk score must be between 0 and 100")
    if score <= 29:
        return RiskLevel.LOW
    if score <= 59:
        return RiskLevel.MEDIUM
    if score <= 79:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL