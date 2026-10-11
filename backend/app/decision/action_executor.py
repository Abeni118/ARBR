from dataclasses import dataclass
from typing import Callable

from backend.app.decision.actions import DecisionAction
from backend.app.decision.audit import DecisionAuditLog
from backend.app.decision.decision_engine import Decision


@dataclass(frozen=True)
class ActionResult:
    action: DecisionAction
    success: bool
    message: str


class ActionExecutor:
    def __init__(
        self,
        alert_handler: Callable[[Decision], bool] | None = None,
        protect_handler: Callable[[Decision], bool] | None = None,
        isolate_handler: Callable[[Decision], bool] | None = None,
        recover_handler: Callable[[Decision], bool] | None = None,
        audit_log: DecisionAuditLog | None = None,
    ):
        self.alert_handler = alert_handler
        self.protect_handler = protect_handler
        self.isolate_handler = isolate_handler
        self.recover_handler = recover_handler
        self.audit_log = audit_log

    def execute(self, decision: Decision) -> ActionResult:
        if decision.action == DecisionAction.ALLOW:
            result = ActionResult(
                action=decision.action,
                success=True,
                message="Event allowed.",
            )
        else:
            handlers = {
                DecisionAction.ALERT: self.alert_handler,
                DecisionAction.PROTECT: self.protect_handler,
                DecisionAction.ISOLATE: self.isolate_handler,
                DecisionAction.RECOVER: self.recover_handler,
            }

            handler = handlers.get(decision.action)

            if handler is None:
                result = ActionResult(
                    action=decision.action,
                    success=False,
                    message=(
                        f"No handler configured for "
                        f"{decision.action.value}."
                    ),
                )
            else:
                try:
                    success = bool(handler(decision))

                    result = ActionResult(
                        action=decision.action,
                        success=success,
                        message=(
                            f"{decision.action.value} action completed."
                            if success
                            else f"{decision.action.value} action failed."
                        ),
                    )

                except Exception as error:
                    result = ActionResult(
                        action=decision.action,
                        success=False,
                        message=(
                            f"{decision.action.value} action raised an error: "
                            f"{error}"
                        ),
                    )

        if self.audit_log is not None:
            self.audit_log.record(
                decision,
                success=result.success,
                message=result.message,
            )

        return result