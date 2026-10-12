from datetime import datetime, timedelta, timezone
from typing import NoReturn
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.common import as_utc
from app.enums import ActionType
from app.models import ActionRequest, Asset, Backup, Decision, IntegrityVerification, ThreatIncident
from app.services.backup_readiness import assess_recovery_eligibility
from app.services.isolation_state import get_asset_isolation_state


# MVP freshness rule: a passed verification is valid for 24 hours, provided no
# verification created later has superseded it (including queued/running checks).
VERIFICATION_MAX_AGE = timedelta(hours=24)


def _reject(code: str, message: str, status_code: int = 409) -> NoReturn:
    raise HTTPException(status_code=status_code, detail={"code": code, "message": message})


def validate_recovery_prerequisites(
    db: Session,
    *,
    asset_id: str | UUID,
    incident_id: str | UUID,
    backup_id: str | UUID,
    verification_id: str | UUID,
    decision_id: str | UUID | None = None,
    action_request: ActionRequest | None = None,
    require_approval: bool = True,
    require_isolation: bool = True,
) -> tuple[Asset, ThreatIncident, Backup, IntegrityVerification, Decision | None]:
    """Validate all recovery gates against persisted state at the time of use."""
    asset = db.get(Asset, str(asset_id))
    if asset is None:
        _reject("asset_not_found", "Asset not found", 404)

    incident = db.get(ThreatIncident, str(incident_id))
    if incident is None:
        _reject("incident_not_found", "Threat incident not found", 404)
    affected_asset_ids = {incident.asset_id, *(item.id for item in incident.affected_assets)}
    if asset.id not in affected_asset_ids:
        _reject("incident_asset_mismatch", "Incident is not associated with the target asset")

    backup = db.get(Backup, str(backup_id))
    if backup is None:
        _reject("backup_not_found", "Backup not found", 404)
    if backup.asset_id != asset.id:
        _reject("backup_asset_mismatch", "Backup does not belong to the target asset")
    if backup.lifecycle_status != "available":
        _reject("backup_unavailable", "Backup is not available for recovery")

    verification = db.get(IntegrityVerification, str(verification_id))
    if verification is None:
        _reject("verification_not_found", "Integrity verification not found", 404)
    if verification.backup_id != backup.id:
        _reject("verification_backup_mismatch", "Verification does not belong to the exact backup")
    if verification.result_status != "passed":
        _reject("verification_not_passed", "Integrity verification must have PASSED")
    if verification.completed_at is None:
        _reject("verification_incomplete", "Integrity verification has not completed")

    newer_verification = db.scalar(
        select(IntegrityVerification)
        .where(
            IntegrityVerification.backup_id == backup.id,
            or_(
                IntegrityVerification.created_at > verification.created_at,
                (
                    (IntegrityVerification.created_at == verification.created_at)
                    & (IntegrityVerification.id > verification.id)
                ),
            ),
        )
        .limit(1)
    )
    if newer_verification is not None:
        _reject(
            "verification_superseded",
            "A newer integrity verification exists for this backup; use its result",
        )
    completed_at = as_utc(verification.completed_at)
    if completed_at > datetime.now(timezone.utc) or datetime.now(timezone.utc) - completed_at > VERIFICATION_MAX_AGE:
        _reject("verification_stale", "Integrity verification is older than the 24-hour freshness window")

    # Keep the established recovery eligibility policy in force as well as the
    # stronger selected-verification checks above.
    eligibility = assess_recovery_eligibility(db, backup)
    if not eligibility.eligible:
        _reject("backup_not_recovery_eligible", "Backup is not recovery-eligible")

    decision: Decision | None = None
    if decision_id is not None:
        decision = db.get(Decision, str(decision_id))
        if decision is None:
            _reject("decision_not_found", "Decision not found", 404)
        if decision.asset_id != asset.id or decision.incident_id != incident.id:
            _reject("decision_mismatch", "Decision does not match the target asset and incident")
        if ActionType.RECOVER.value not in decision.recommended_actions:
            _reject("decision_mismatch", "Decision does not recommend recovery")

    if action_request is not None:
        expected = {
            "asset_id": asset.id,
            "incident_id": incident.id,
            "backup_id": backup.id,
            "verification_id": verification.id,
        }
        if action_request.action_type != ActionType.RECOVER.value:
            _reject("action_request_invalid", "ActionRequest must be a recovery request")
        for field, expected_id in expected.items():
            if getattr(action_request, field) != expected_id:
                _reject("action_request_mismatch", f"ActionRequest {field} does not match the recovery request")
        if action_request.decision_id != (decision.id if decision else None):
            _reject("action_request_mismatch", "ActionRequest decision does not match the recovery request")
        if require_approval and action_request.approval_status != "approved":
            _reject("recovery_not_approved", "Recovery ActionRequest must be approved")

    if require_isolation:
        isolation = get_asset_isolation_state(db, asset.id)
        if isolation.isolation_state != "isolated" or isolation.current_action is None:
            _reject("asset_not_confirmed_isolated", "Target asset must have a current confirmed isolation")

    return asset, incident, backup, verification, decision