from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class RiskRule:
    name: str
    score: float
    threat_type: str
    condition: Callable[[dict], bool]


RISK_RULES = (
    RiskRule(
        name="mass_file_encryption",
        score=40.0,
        threat_type="ransomware_behavior",
        condition=lambda indicators: indicators.get("mass_file_encryption", False),
    ),
    RiskRule(
        name="mass_file_modification",
        score=25.0,
        threat_type="ransomware_behavior",
        condition=lambda indicators: indicators.get("mass_file_modification", False),
    ),
    RiskRule(
        name="backup_deletion",
        score=35.0,
        threat_type="backup_destruction",
        condition=lambda indicators: indicators.get("backup_deletion", False),
    ),
    RiskRule(
        name="suspicious_process",
        score=20.0,
        threat_type="suspicious_activity",
        condition=lambda indicators: indicators.get("suspicious_process", False),
    ),
    RiskRule(
        name="privilege_escalation",
        score=30.0,
        threat_type="privilege_escalation",
        condition=lambda indicators: indicators.get("privilege_escalation", False),
    ),
    RiskRule(
        name="security_service_disabled",
        score=35.0,
        threat_type="defense_evasion",
        condition=lambda indicators: indicators.get("security_service_disabled", False),
    ),
)