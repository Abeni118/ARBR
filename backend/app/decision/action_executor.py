from dataclasses import dataclass
from typing import Callable

from backend.app.decision.actions import DecisionAction
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
    ):
        self.alert_handler = alert_handler
        self.protect_handler = protect_handler
        self.isolate_handler = isolate_handler
        self.recover_handler = recover_handler

    def execute(self, decision: Decision) -> ActionResult:
        if decision.action == DecisionAction.ALLOW:
            return ActionResult(
                action=decision.action,
                success=True,
                message="Event allowed.",
            )

        handlers = {
            DecisionAction.ALERT: self.alert_handler,
            DecisionAction.PROTECT: self.protect_handler,
            DecisionAction.ISOLATE: self.isolate_handler,
            DecisionAction.RECOVER: self.recover_handler,
        }

        handler = handlers.get(decision.action)

        if handler is None:
            return ActionResult(
                action=decision.action,
                success=False,
                message=f"No handler configured for {decision.action.value}.",
            )

        try:
            success = bool(handler(decision))
        except Exception as error:
            return ActionResult(
                action=decision.action,
                success=False,
                message=(
                    f"{decision.action.value} action raised an error: "
                    f"{error}"
                ),
            )

        return ActionResult(
            action=decision.action,
            success=success,
            message=(
                f"{decision.action.value} action completed."
                if success
                else f"{decision.action.value} action failed."
            ),
        )