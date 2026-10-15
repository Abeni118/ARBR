
from dataclasses import dataclass
from typing import Callable

from backend.app.isolation.isolation_manager import IsolationManager
from backend.app.recovery.recovery_manager import RecoveryManager


@dataclass(frozen=True)
class RecoveryRequest:
    backup_path: str
    restore_path: str
    expected_hashes: dict[str, str]
    expected_files: list[str] | None = None


class IsolationRecoveryHandlers:
    def __init__(
        self,
        isolation_manager: IsolationManager,
        recovery_manager: RecoveryManager,
        recovery_request_provider: (
            Callable[[object], RecoveryRequest | None] | None
        ) = None,
    ):
        self.isolation_manager = isolation_manager
        self.recovery_manager = recovery_manager
        self.recovery_request_provider = recovery_request_provider

        self.last_isolation_result = None
        self.last_recovery_result = None

    def isolate(self, decision: object) -> bool:
        risk_level = decision.risk_level
        risk_level = getattr(risk_level, "value", risk_level)

        self.last_isolation_result = (
            self.isolation_manager.isolate_host(
                host_id=decision.host_id,
                reason=decision.reason,
                risk_level=str(risk_level),
            )
        )

        return bool(
            self.last_isolation_result.get("success", False)
        )

    def recover(self, decision: object) -> bool:
        if self.recovery_request_provider is None:
            self.last_recovery_result = {
                "success": False,
                "reason": "RECOVERY_REQUEST_NOT_CONFIGURED",
            }
            return False

        request = self.recovery_request_provider(decision)

        if request is None:
            self.last_recovery_result = {
                "success": False,
                "reason": "RECOVERY_REQUEST_UNAVAILABLE",
            }
            return False

        self.last_recovery_result = self.recovery_manager.recover(
            backup_path=request.backup_path,
            restore_path=request.restore_path,
            expected_hashes=request.expected_hashes,
            expected_files=request.expected_files,
        )

        return bool(
            self.last_recovery_result.get("success", False)
        )