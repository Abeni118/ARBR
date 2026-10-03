from datetime import datetime, timezone
from typing import Annotated, Any, Generic, TypeVar
from uuid import UUID

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from .enums import (
    ActionExecutionStatus,
    ActionType,
    ApprovalStatus,
    BackupLifecycleStatus,
    BackupProtectionStatus,
    CutoverStatus,
    DecisionStatus,
    EventProcessingStatus,
    EventSeverity,
    IncidentLifecycleStatus,
    IsolationExecutionStatus,
    RecoveryJobStatus,
    RiskAssessmentStatus,
    RiskLevel,
    VerificationStatus,
)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


UTCDateTime = Annotated[datetime, AfterValidator(_as_utc)]
RiskScore = Annotated[int, Field(ge=0, le=100)]
Confidence = Annotated[float, Field(ge=0, le=1)]


class APIModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)


T = TypeVar("T")


class Page(APIModel, Generic[T]):
    items: list[T]
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=100)
    total: int = Field(ge=0)


class AssetCreate(APIModel):
    external_source: str | None = Field(default=None, max_length=100)
    external_id: str | None = Field(default=None, max_length=255)
    hostname: str = Field(min_length=1, max_length=255)
    asset_type: str | None = Field(default=None, max_length=100)
    environment: str | None = Field(default=None, max_length=100)
    criticality: str | None = Field(default=None, max_length=50)
    network_segment: str | None = Field(default=None, max_length=255)

    @model_validator(mode="after")
    def validate_external_reference(self):
        if (self.external_source is None) != (self.external_id is None):
            raise ValueError("external_source and external_id must be provided together")
        return self


class AssetRead(APIModel):
    id: UUID
    external_source: str | None
    external_id: str | None
    hostname: str
    asset_type: str | None
    environment: str | None
    criticality: str | None
    network_segment: str | None
    monitoring_status: str
    created_at: UTCDateTime
    updated_at: UTCDateTime


class SecurityEventCreate(APIModel):
    source: str = Field(min_length=1, max_length=100)
    source_event_id: str = Field(min_length=1, max_length=255)
    asset_id: UUID | None = None
    incident_id: UUID | None = None
    occurred_at: UTCDateTime
    event_type: str = Field(min_length=1, max_length=100)
    event_severity: EventSeverity
    summary: str = Field(min_length=1)
    indicators: list[dict[str, Any]] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    source_component: str | None = Field(default=None, max_length=100)
    correlation_id: UUID | None = None


class SecurityEventRead(APIModel):
    id: UUID
    source: str
    source_event_id: str
    asset_id: UUID | None
    incident_id: UUID | None
    occurred_at: UTCDateTime
    received_at: UTCDateTime
    event_type: str
    event_severity: EventSeverity
    processing_status: EventProcessingStatus
    summary: str
    indicators: list[dict[str, Any]]
    evidence: dict[str, Any]
    source_component: str | None
    correlation_id: UUID


class ThreatIncidentCreate(APIModel):
    title: str = Field(min_length=1, max_length=255)
    threat_type: str = Field(min_length=1, max_length=100)
    asset_id: UUID
    description: str | None = None
    indicators: list[dict[str, Any]] = Field(default_factory=list)
    detection_source: str | None = Field(default=None, max_length=100)
    event_ids: list[UUID] = Field(default_factory=list)
    detected_at: UTCDateTime
    correlation_id: UUID | None = None


class ThreatIncidentRead(APIModel):
    id: UUID
    title: str
    threat_type: str
    asset_id: UUID
    description: str | None
    indicators: list[dict[str, Any]]
    detection_source: str | None
    detected_at: UTCDateTime
    lifecycle_status: IncidentLifecycleStatus
    current_risk_assessment_id: UUID | None
    correlation_id: UUID
    created_at: UTCDateTime
    updated_at: UTCDateTime
    resolved_at: UTCDateTime | None


class RiskAssessmentCreate(APIModel):
    incident_id: UUID
    asset_id: UUID
    score: RiskScore
    factors: list[dict[str, Any]] = Field(default_factory=list)
    confidence: Confidence | None = None
    model_version: str | None = Field(default=None, max_length=100)
    policy_version: str | None = Field(default=None, max_length=100)
    assessed_at: UTCDateTime | None = None
    correlation_id: UUID | None = None


class RiskAssessmentRead(APIModel):
    id: UUID
    incident_id: UUID
    asset_id: UUID
    score: RiskScore
    risk_level: RiskLevel
    factors: list[dict[str, Any]]
    confidence: Confidence | None
    model_version: str | None
    policy_version: str | None
    status: RiskAssessmentStatus
    assessed_at: UTCDateTime
    correlation_id: UUID


class DecisionCreate(APIModel):
    incident_id: UUID
    assessment_id: UUID
    asset_id: UUID
    recommended_actions: list[ActionType] = Field(min_length=1)
    rationale: str = Field(min_length=1)
    approval_required: bool = True
    policy_version: str | None = Field(default=None, max_length=100)
    engine_version: str | None = Field(default=None, max_length=100)
    correlation_id: UUID | None = None


class DecisionRead(APIModel):
    id: UUID
    incident_id: UUID
    assessment_id: UUID
    asset_id: UUID
    recommended_actions: list[ActionType]
    rationale: str
    approval_required: bool
    decision_status: DecisionStatus
    policy_version: str | None
    engine_version: str | None
    created_at: UTCDateTime
    correlation_id: UUID


class ActionRequestCreate(APIModel):
    action_type: ActionType
    decision_id: UUID | None = None
    incident_id: UUID | None = None
    asset_id: UUID | None = None
    backup_id: UUID | None = None
    verification_id: UUID | None = None
    requested_by_type: str = Field(min_length=1, max_length=50)
    requested_by_id: str | None = Field(default=None, max_length=255)
    request_reason: str | None = None
    correlation_id: UUID | None = None


class ActionRequestRead(APIModel):
    id: UUID
    action_type: ActionType
    decision_id: UUID | None
    incident_id: UUID | None
    asset_id: UUID | None
    backup_id: UUID | None
    verification_id: UUID | None
    requested_by_type: str
    requested_by_id: str | None
    request_reason: str | None
    approval_status: ApprovalStatus
    approved_by_id: str | None
    approved_at: UTCDateTime | None
    execution_status: ActionExecutionStatus
    started_at: UTCDateTime | None
    completed_at: UTCDateTime | None
    component_result: dict[str, Any]
    failure_reason: str | None
    correlation_id: UUID
    created_at: UTCDateTime
    updated_at: UTCDateTime


class BackupCreate(APIModel):
    asset_id: UUID
    source_component: str = Field(min_length=1, max_length=100)
    external_backup_id: str = Field(min_length=1, max_length=255)
    backup_type: str | None = Field(default=None, max_length=100)
    size_bytes: int | None = Field(default=None, ge=0)
    storage_reference: str | None = Field(default=None, max_length=1024)
    manifest_reference: str | None = Field(default=None, max_length=1024)
    backup_created_at: UTCDateTime | None = None
    correlation_id: UUID | None = None


class BackupRead(APIModel):
    id: UUID
    asset_id: UUID
    source_component: str
    external_backup_id: str
    backup_type: str | None
    size_bytes: int | None
    storage_reference: str | None
    manifest_reference: str | None
    lifecycle_status: BackupLifecycleStatus
    protection_status: BackupProtectionStatus
    encryption_status: str
    backup_created_at: UTCDateTime | None
    correlation_id: UUID
    created_at: UTCDateTime
    updated_at: UTCDateTime


class IntegrityVerificationCreate(APIModel):
    backup_id: UUID
    algorithm: str | None = Field(default=None, max_length=50)
    expected_digest: str | None = Field(default=None, max_length=512)
    trusted_manifest_reference: str | None = Field(default=None, max_length=1024)
    correlation_id: UUID | None = None


class IntegrityVerificationResult(APIModel):
    result_status: VerificationStatus
    observed_digest: str | None = Field(default=None, max_length=512)
    verifier_component: str = Field(min_length=1, max_length=100)
    verifier_version: str | None = Field(default=None, max_length=100)
    completed_at: UTCDateTime | None = None
    failure_reason: str | None = None


class IntegrityVerificationRead(APIModel):
    id: UUID
    backup_id: UUID
    algorithm: str | None
    expected_digest: str | None
    observed_digest: str | None
    trusted_manifest_reference: str | None
    result_status: VerificationStatus
    verifier_component: str | None
    verifier_version: str | None
    started_at: UTCDateTime | None
    completed_at: UTCDateTime | None
    failure_reason: str | None
    correlation_id: UUID


class IsolationActionCreate(APIModel):
    action_request_id: UUID
    asset_id: UUID
    incident_id: UUID | None = None
    isolation_mode: str | None = Field(default=None, max_length=100)
    correlation_id: UUID | None = None


class IsolationActionRead(APIModel):
    id: UUID
    action_request_id: UUID
    asset_id: UUID
    incident_id: UUID | None
    execution_status: IsolationExecutionStatus
    isolation_mode: str | None
    network_state: str | None
    requested_at: UTCDateTime
    acknowledged_at: UTCDateTime | None
    released_at: UTCDateTime | None
    component_reference: str | None
    failure_reason: str | None
    correlation_id: UUID


class RecoveryJobCreate(APIModel):
    action_request_id: UUID
    asset_id: UUID
    incident_id: UUID
    backup_id: UUID
    verification_id: UUID
    recovery_environment: str | None = Field(default=None, max_length=255)
    correlation_id: UUID | None = None


class RecoveryJobRead(APIModel):
    id: UUID
    action_request_id: UUID
    asset_id: UUID
    incident_id: UUID
    backup_id: UUID
    verification_id: UUID
    recovery_environment: str | None
    job_status: RecoveryJobStatus
    cutover_status: CutoverStatus
    malware_scan_status: str
    security_validation_status: str
    started_at: UTCDateTime | None
    completed_at: UTCDateTime | None
    outcome: str | None
    failure_reason: str | None
    component_reference: str | None
    correlation_id: UUID


class AuditEventCreate(APIModel):
    actor_type: str = Field(min_length=1, max_length=50)
    actor_id: str | None = Field(default=None, max_length=255)
    action: str = Field(min_length=1, max_length=150)
    result_status: str = Field(min_length=1, max_length=50)
    resource_type: str | None = Field(default=None, max_length=100)
    resource_id: UUID | None = None
    asset_id: UUID | None = None
    incident_id: UUID | None = None
    event_id: UUID | None = None
    assessment_id: UUID | None = None
    decision_id: UUID | None = None
    action_request_id: UUID | None = None
    backup_id: UUID | None = None
    verification_id: UUID | None = None
    recovery_job_id: UUID | None = None
    source_component: str | None = Field(default=None, max_length=100)
    reason: str | None = None
    safe_metadata: dict[str, Any] = Field(default_factory=dict)
    correlation_id: UUID | None = None
    occurred_at: UTCDateTime | None = None


class AuditEventRead(APIModel):
    id: UUID
    actor_type: str
    actor_id: str | None
    action: str
    result_status: str
    resource_type: str | None
    resource_id: UUID | None
    asset_id: UUID | None
    incident_id: UUID | None
    event_id: UUID | None
    assessment_id: UUID | None
    decision_id: UUID | None
    action_request_id: UUID | None
    backup_id: UUID | None
    verification_id: UUID | None
    recovery_job_id: UUID | None
    source_component: str | None
    reason: str | None
    safe_metadata: dict[str, Any]
    correlation_id: UUID
    occurred_at: UTCDateTime


class SystemSettingsUpdate(APIModel):
    risk_thresholds: dict[str, int] | None = None
    isolation_policy: dict[str, Any] | None = None
    backup_policy: dict[str, Any] | None = None
    recovery_policy: dict[str, Any] | None = None
    notification_policy: dict[str, Any] | None = None


class SystemSettingsRead(APIModel):
    id: UUID
    version: int
    risk_thresholds: dict[str, int]
    isolation_policy: dict[str, Any]
    backup_policy: dict[str, Any]
    recovery_policy: dict[str, Any]
    notification_policy: dict[str, Any]
    created_at: UTCDateTime
    updated_at: UTCDateTime