from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.common import as_utc, get_or_404, paginate
from app.database.session import get_db
from app.enums import ActionExecutionStatus, BackupLifecycleStatus, BackupProtectionStatus
from app.models import ActionRequest, Asset, Backup
from app.schemas import (
    BackupCandidateRead,
    BackupCreate,
    BackupProtectionResult,
    BackupProtectionResultRead,
    BackupRead,
    Page,
    RecoveryEligibilityRead,
)
from app.services.audit import record_phase2_audit
from app.services.backup_readiness import assess_recovery_eligibility
from app.services.internal_auth import require_backup_component

router = APIRouter(prefix="/api/backups", tags=["Backups"])
recovery_points_router = APIRouter(prefix="/api/assets", tags=["Backups"])
internal_router = APIRouter(prefix="/api/internal/backups", tags=["Internal Backup Component"])


def _candidate(db: Session, backup: Backup) -> BackupCandidateRead:
    eligibility = assess_recovery_eligibility(db, backup)
    safe_metadata = BackupRead.model_validate(backup).model_dump()
    return BackupCandidateRead(
        **safe_metadata,
        verified=eligibility.verified,
        recovery_eligible=eligibility.eligible,
        eligibility_reasons=eligibility.reasons,
    )


@internal_router.post(
    "",
    response_model=BackupRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_backup_component)],
)
def register_backup(
    payload: BackupCreate,
    response: Response,
    db: Session = Depends(get_db),
):
    correlation_id = payload.correlation_id or uuid4()
    asset = db.get(Asset, str(payload.asset_id))
    if asset is None:
        record_phase2_audit(
            db,
            action="backup.registration_rejected",
            result_status="rejected",
            resource_type="backup",
            asset_id=payload.asset_id,
            correlation_id=correlation_id,
            actor_id=payload.created_by_component,
            source_component=payload.created_by_component,
            reason="Asset not found",
        )
        db.commit()
        raise HTTPException(status_code=404, detail="Asset not found")

    existing = (
        db.query(Backup)
        .filter(
            Backup.source_component == payload.created_by_component,
            Backup.external_backup_id == payload.external_backup_id,
        )
        .first()
    )
    if existing is not None:
        record_phase2_audit(
            db,
            action="backup.registered",
            result_status="duplicate",
            resource_type="backup",
            resource_id=existing.id,
            backup_id=existing.id,
            asset_id=existing.asset_id,
            correlation_id=existing.correlation_id,
            actor_id=payload.created_by_component,
            source_component=payload.created_by_component,
            reason="Existing producer identity returned unchanged",
        )
        db.commit()
        response.status_code = status.HTTP_200_OK
        return existing

    backup = Backup(
        asset_id=asset.id,
        source_component=payload.created_by_component,
        external_backup_id=payload.external_backup_id,
        backup_created_at=as_utc(payload.created_at),
        backup_type=payload.backup_type,
        size_bytes=payload.size_bytes,
        storage_reference=payload.storage_reference,
        manifest_reference=payload.manifest_reference,
        protection_status=payload.protection_status,
        lifecycle_status=payload.lifecycle_status,
        encryption_status=payload.encryption_status,
        correlation_id=str(correlation_id),
    )
    db.add(backup)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        existing = (
            db.query(Backup)
            .filter(
                Backup.source_component == payload.created_by_component,
                Backup.external_backup_id == payload.external_backup_id,
            )
            .first()
        )
        if existing is None:
            raise HTTPException(status_code=409, detail="Backup identity conflicts with an existing record") from exc
        record_phase2_audit(
            db,
            action="backup.registered",
            result_status="duplicate",
            resource_type="backup",
            resource_id=existing.id,
            backup_id=existing.id,
            asset_id=existing.asset_id,
            correlation_id=existing.correlation_id,
            actor_id=payload.created_by_component,
            source_component=payload.created_by_component,
            reason="Concurrent duplicate producer identity returned unchanged",
        )
        db.commit()
        response.status_code = status.HTTP_200_OK
        return existing

    record_phase2_audit(
        db,
        action="backup.registered",
        result_status="success",
        resource_type="backup",
        resource_id=backup.id,
        backup_id=backup.id,
        asset_id=asset.id,
        correlation_id=correlation_id,
        actor_id=payload.created_by_component,
        source_component=payload.created_by_component,
    )
    db.commit()
    db.refresh(backup)
    return backup


@internal_router.post(
    "/{backup_id}/protection-result",
    response_model=BackupProtectionResultRead,
    dependencies=[Depends(require_backup_component)],
)
def report_protection_result(
    backup_id: UUID,
    payload: BackupProtectionResult,
    db: Session = Depends(get_db),
):
    backup = get_or_404(db, Backup, str(backup_id), "Backup")
    action_request = None
    if payload.action_request_id is not None:
        action_request = db.get(ActionRequest, str(payload.action_request_id))
        if action_request is None:
            raise HTTPException(status_code=404, detail="Action request not found")
        if action_request.action_type != "protect_backup" or action_request.backup_id != backup.id:
            raise HTTPException(status_code=409, detail="Action request does not target this backup protection operation")
        if action_request.asset_id != backup.asset_id:
            raise HTTPException(status_code=409, detail="Action request asset does not match the backup")
        if action_request.correlation_id and payload.correlation_id and action_request.correlation_id != str(payload.correlation_id):
            raise HTTPException(status_code=409, detail="Correlation ID does not match the action request")

    correlation_id = (
        payload.correlation_id
        or (UUID(action_request.correlation_id) if action_request else UUID(backup.correlation_id))
    )
    backup.protection_status = payload.protection_status
    if action_request is not None:
        action_request.execution_status = payload.execution_status
        action_request.started_at = action_request.started_at or datetime.now(timezone.utc)
        if payload.execution_status != ActionExecutionStatus.EXECUTING:
            action_request.completed_at = as_utc(payload.completed_at) if payload.completed_at else datetime.now(timezone.utc)
        action_request.failure_reason = payload.failure_reason
        action_request.component_result = {
            "component_reference": payload.component_reference,
            "protection_status": payload.protection_status,
        }
    if payload.execution_status == ActionExecutionStatus.EXECUTING:
        action = "backup.protection.started"
        result = "started"
    elif payload.execution_status == ActionExecutionStatus.SUCCEEDED:
        action = "backup.protection.succeeded"
        result = "success"
    else:
        action = "backup.protection.failed"
        result = "failed"
    record_phase2_audit(
        db,
        action=action,
        result_status=result,
        resource_type="backup",
        resource_id=backup.id,
        backup_id=backup.id,
        asset_id=backup.asset_id,
        action_request_id=action_request.id if action_request else None,
        correlation_id=correlation_id,
        actor_id="backup_component",
        source_component="backup_component",
        reason=payload.failure_reason,
        safe_metadata={"execution_status": payload.execution_status},
    )
    db.commit()
    db.refresh(backup)
    return BackupProtectionResultRead(
        backup=BackupRead.model_validate(backup),
        action_request_id=UUID(action_request.id) if action_request else None,
        execution_status=payload.execution_status,
        correlation_id=correlation_id,
    )


@router.get("", response_model=Page[BackupCandidateRead])
def list_backups(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    asset_id: UUID | None = None,
    lifecycle_status: BackupLifecycleStatus | None = None,
    protection_status: BackupProtectionStatus | None = None,
    backup_type: str | None = None,
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(Backup)
    if asset_id:
        query = query.filter(Backup.asset_id == str(asset_id))
    if lifecycle_status:
        query = query.filter(Backup.lifecycle_status == lifecycle_status.value)
    if protection_status:
        query = query.filter(Backup.protection_status == protection_status.value)
    if backup_type:
        query = query.filter(Backup.backup_type == backup_type)
    if from_:
        query = query.filter(Backup.backup_created_at >= as_utc(from_))
    if to:
        query = query.filter(Backup.backup_created_at <= as_utc(to))
    page_result = paginate(query.order_by(Backup.backup_created_at.desc()), page, page_size)
    return Page[BackupCandidateRead](
        items=[_candidate(db, backup) for backup in page_result.items],
        page=page_result.page,
        page_size=page_result.page_size,
        total=page_result.total,
    )


@router.get("/{backup_id}/recovery-eligibility", response_model=RecoveryEligibilityRead)
def get_recovery_eligibility(backup_id: UUID, db: Session = Depends(get_db)):
    backup = get_or_404(db, Backup, str(backup_id), "Backup")
    eligibility = assess_recovery_eligibility(db, backup)
    record_phase2_audit(
        db,
        action=("recovery.eligibility_check_passed" if eligibility.eligible else "recovery.eligibility_check_failed"),
        result_status=("success" if eligibility.eligible else "failed"),
        resource_type="backup",
        resource_id=backup.id,
        backup_id=backup.id,
        asset_id=backup.asset_id,
        correlation_id=backup.correlation_id,
        source_component="api",
        actor_type="system",
        reason=", ".join(eligibility.reasons) if eligibility.reasons else None,
    )
    db.commit()
    return RecoveryEligibilityRead(
        eligible=eligibility.eligible,
        backup_id=backup.id,
        reasons=eligibility.reasons,
    )


@router.post("/{backup_id}/select-for-recovery", response_model=RecoveryEligibilityRead)
def select_backup_for_recovery(backup_id: UUID, db: Session = Depends(get_db)):
    """Record a readiness-checked selection only; this does not execute recovery."""
    backup = get_or_404(db, Backup, str(backup_id), "Backup")
    eligibility = assess_recovery_eligibility(db, backup)
    if not eligibility.eligible:
        record_phase2_audit(
            db,
            action="backup.selected_for_recovery",
            result_status="rejected",
            resource_type="backup",
            resource_id=backup.id,
            backup_id=backup.id,
            asset_id=backup.asset_id,
            correlation_id=backup.correlation_id,
            actor_type="user",
            source_component="api",
            reason=", ".join(eligibility.reasons),
        )
        db.commit()
        raise HTTPException(status_code=409, detail={"eligible": False, "reasons": eligibility.reasons})
    record_phase2_audit(
        db,
        action="backup.selected_for_recovery",
        result_status="success",
        resource_type="backup",
        resource_id=backup.id,
        backup_id=backup.id,
        asset_id=backup.asset_id,
        correlation_id=backup.correlation_id,
        actor_type="user",
        source_component="api",
    )
    db.commit()
    return RecoveryEligibilityRead(eligible=True, backup_id=backup.id, reasons=[])


@recovery_points_router.get("/{asset_id}/recovery-points", response_model=Page[BackupCandidateRead])
def list_asset_recovery_points(
    asset_id: UUID,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    if db.get(Asset, str(asset_id)) is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    query = db.query(Backup).filter(Backup.asset_id == str(asset_id))
    page_result = paginate(query.order_by(Backup.backup_created_at.desc()), page, page_size)
    return Page[BackupCandidateRead](
        items=[_candidate(db, backup) for backup in page_result.items],
        page=page_result.page,
        page_size=page_result.page_size,
        total=page_result.total,
    )


@router.get("/{backup_id}", response_model=BackupCandidateRead)
def get_backup(backup_id: UUID, db: Session = Depends(get_db)):
    return _candidate(db, get_or_404(db, Backup, str(backup_id), "Backup"))