from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import IsolationAction


ACTIVE_ISOLATION_STATUSES = (
    "requested",
    "awaiting_approval",
    "approved",
    "executing",
    "isolated",
    "release_requested",
)


@dataclass(frozen=True)
class AssetIsolationState:
    isolation_state: str
    current_action: IsolationAction | None


def get_asset_isolation_state(db: Session, asset_id: str) -> AssetIsolationState:
    """Derive asset isolation solely from the latest persisted operation result."""
    actions = db.scalars(
        select(IsolationAction)
        .where(IsolationAction.asset_id == asset_id)
        .order_by(IsolationAction.requested_at.desc(), IsolationAction.id.desc())
    ).all()
    if not actions:
        return AssetIsolationState("not_isolated", None)

    latest = actions[0]
    operation = latest.action_request.action_type
    # A requested/failed release does not undo the component's prior confirmed isolation.
    if operation == "release_isolation":
        if latest.execution_status == "released":
            return AssetIsolationState("not_isolated", None)
        if latest.execution_status in {"failed", "cancelled"}:
            previously_isolated = next(
                (
                    action
                    for action in actions[1:]
                    if action.action_request.action_type == "isolate" and action.execution_status == "isolated"
                ),
                None,
            )
            if previously_isolated is not None:
                return AssetIsolationState("isolated", previously_isolated)
            return AssetIsolationState("not_isolated", None)
        return AssetIsolationState("release_pending", latest)

    if latest.execution_status == "isolated":
        return AssetIsolationState("isolated", latest)
    if latest.execution_status in ACTIVE_ISOLATION_STATUSES:
        return AssetIsolationState("isolation_pending", latest)
    return AssetIsolationState("not_isolated", None)
