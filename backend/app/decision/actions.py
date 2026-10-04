from enum import Enum


class DecisionAction(str, Enum):
    ALLOW = "ALLOW"
    ALERT = "ALERT"
    PROTECT = "PROTECT"
    ISOLATE = "ISOLATE"
    RECOVER = "RECOVER"