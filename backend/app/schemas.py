from datetime import datetime, timezone
import re
from typing import Annotated, Any, Generic, TypeVar
from uuid import UUID

from pydantic import AliasChoices, AfterValidator, BaseModel, ConfigDict, Field, model_validator

from .enums import (
    ActionExecutionStatus,
    ActionType,
    AssetIsolationState,
    ApprovalStatus,
    BackupLifecycleStatus,
    BackupProtectionStatus,
    CutoverStatus,
    DecisionStatus,
    EventProcessingStatus,
    EventSeverity,
    IncidentLifecycleStatus,
    IsolationExecutionStatus,
    IsolationMode,
    IsolationNetworkState,
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
_SECRET_KEY_MARKERS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "credential",
    "authorization",
)
_SECRET_VALUE_PATTERNS = (
    re.compile(
        r"(?:password|passwd|token|api[_-]?key|private[_-]?key|authorization)\s*[:=]\s*\S+",
        re.IGNORECASE,
    ),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]+=*", re.IGNORECASE),
    re.compile(r"[a-z][a-z0-9+.-]*://[^/@:\s]+:[^/@\s]+@", re.IGNORECASE),
)


def _reject_secret_fields(value: Any, path: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized_key = str(key).lower().replace("-", "_")
            if any(marker in normalized_key for marker in _SECRET_KEY_MARKERS):
                raise ValueError(f"Secret-like field '{path}{key}' is not allowed")
            _reject_secret_fields(child, f"{path}{key}.")
    elif isinstance(value, list):
        for child in value:
            _reject_secret_fields(child, path)


def _reject_sensitive_content(value: Any) -> None:
    """Reject credential-like field names and recognizable embedded secrets."""
    _reject_secret_fields(value)
    if isinstance(value, dict):
        children = value.values()
    elif isinstance(value, list):
        children = value
    else:
        children = (value,)
    for child in children:
        if isinstance(child, str) and any(pattern.search(child) for pattern in _SECRET_VALUE_PATTERNS):
            raise ValueError("Credential-like content is not allowed")
        if isinstance(child, (dict, list)):
            _reject_sensitive_content(child)


class APIModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)


class RiskThresholds(APIModel):
    low_min: int = Field(ge=0, le=100)
    low_max: int = Field(ge=0, le=100)
    medium_min: int = Field(ge=0, le=100)
    medium_max: int = Field(ge=0, le=100)
    high_min: int = Field(ge=0, le=100)
    high_max: int = Field(ge=0, le=100)
    critical_min: int = Field(ge=0, le=100)
    critical_max: int = Field(ge=0, le=100)

    @model_validator(mode="after")
    def validate_contiguous_bands(self):
        if self.low_min != 0 or self.critical_max != 100:
            raise ValueError("Risk thresholds must cover the full 0–100 score range")
        if not (
            self.low_min <= self.low_max < self.medium_min <= self.medium_max
            < self.high_min <= self.high_max < self.critical_min <= self.critical_max
        ):
            raise ValueError("Risk threshold bands must be ordered and non-overlapping")
        if not (
            self.low_max + 1 == self.medium_min
            and self.medium_max + 1 == self.high_min
            and self.high_max + 1 == self.critical_min
        ):
            raise ValueError("Risk threshold bands must be contiguous with no gaps")
        return self


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


class AssetExternalReference(APIModel):
    external_source: str = Field(min_length=1, max_length=100)
    external_id: str = Field(min_length=1, max_length=255)


class SecurityEventCreate(APIModel):
    source: str = Field(min_length=1, max_length=100)
    source_event_id: str = Field(min_length=1, max_length=255)
    asset_id: UUID | None = None
    asset_external_ref: AssetExternalReference | None = None
    incident_id: UUID | None = None
    occurred_at: UTCDateTime
    event_type: str = Field(min_length=1, max_length=100)
    event_severity: EventSeverity
    summary: str = Field(min_length=1)
    indicators: list[dict[str, Any]] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    source_component: str | None = Field(default=None, max_length=100)
    correlation_id: UUID | None = None

    @model_validator(mode="after")
    def validate_asset_reference_and_safe_content(self):
        if (self.asset_id is None) == (self.asset_external_ref is None):
            raise ValueError("Provide exactly one of asset_id or asset_external_ref")
        _reject_sensitive_content(self.summary)
        _reject_sensitive_content(self.indicators)
        _reject_sensitive_content(self.evidence)
        return self


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


class SecurityEventIngestResponse(APIModel):
    event: SecurityEventRead
    duplicate: bool
    correlation_id: UUID


class DashboardSummary(APIModel):
    total_security_events: int
    active_threats: int
    high_risk_incidents: int
    critical_risk_incidents: int
    risk_distribution: dict[str, int]
    recent_events: list[SecurityEventRead]


class ThreatIncidentCreate(APIModel):
    title: str = Field(min_length=1, max_length=255)
    threat_type: str = Field(min_length=1, max_length=100)
    asset_id: UUID | None = None
    asset_ids: list[UUID] = Field(default_factory=list)
    asset_external_refs: list[AssetExternalReference] = Field(default_factory=list)
    description: str | None = None
    indicators: list[dict[str, Any]] = Field(default_factory=list)
    detection_source: str | None = Field(default=None, max_length=100)
    event_ids: list[UUID] = Field(default_factory=list)
    detected_at: UTCDateTime
    correlation_id: UUID | None = None

    @model_validator(mode="after")
    def validate_assets_and_safe_content(self):
        if not (self.asset_id or self.asset_ids or self.asset_external_refs):
            raise ValueError("Provide at least one asset reference")
        _reject_sensitive_content(self.description)
        _reject_sensitive_content(self.indicators)
        return self


class ThreatIncidentRead(APIModel):
    id: UUID
    title: str
    threat_type: str
    asset_id: UUID
    affected_asset_ids: list[UUID]
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

    @model_validator(mode="after")
    def validate_safe_factors(self):
        _reject_sensitive_content(self.factors)
        return self


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
    recommended_actions: list[ActionType] = Field(
        min_length=1,
        description="Proposed actions only; creating a decision does not request, approve, or execute them.",
    )
    rationale: str = Field(min_length=1)
    approval_required: bool = True
    policy_version: str | None = Field(default=None, max_length=100)
    decision_engine_version: str | None = Field(
        default=None,
        max_length=100,
        validation_alias=AliasChoices("decision_engine_version", "engine_version"),
    )
    correlation_id: UUID | None = None

    @model_validator(mode="after")
    def validate_rationale(self):
        _reject_sensitive_content(self.rationale)
        return self


class DecisionRead(APIModel):
    id: UUID
    incident_id: UUID
    assessment_id: UUID
    asset_id: UUID
    recommended_actions: list[ActionType] = Field(
        description="Recommendation only. It is distinct from action requests and their approval/execution status."
    )
    rationale: str
    approval_required: bool
    decision_status: DecisionStatus = Field(description="Decision recommendation status; not an action execution status.")
    policy_version: str | None
    decision_engine_version: str | None = Field(validation_alias="engine_version")
    created_at: UTCDateTime
    correlation_id: UUID


class ActionRequestCreate(APIModel):
    action_type: ActionType
    decision_id: UUID | None = None
    incident_id: UUID | None = None
    asset_id: UUID | None = None
    backup_id: UUID | None = None
    verification_id: UUID | None = None
    isolation_mode: IsolationMode | None = None
    requested_by_type: str = Field(min_length=1, max_length=50)
    requested_by_id: str | None = Field(default=None, max_length=255)
    request_reason: str | None = None
    correlation_id: UUID | None = None

    @model_validator(mode="after")
    def validate_safe_reason(self):
        if self.action_type == ActionType.ISOLATE:
            if self.asset_id is None or self.isolation_mode is None:
                raise ValueError("isolate requests require asset_id and isolation_mode")
        elif self.isolation_mode is not None:
            raise ValueError("isolation_mode is only valid for isolate requests")
        if self.action_type == ActionType.RELEASE_ISOLATION:
            raise ValueError("Use the isolation release endpoint for release_isolation requests")
        _reject_sensitive_content(self.request_reason)
        return self


class ActionRequestApproval(APIModel):
    approved_by_id: str = Field(min_length=1, max_length=255)


class ActionRequestRejection(APIModel):
    rejected_by_id: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_reason(self):
        _reject_sensitive_content(self.reason)
        return self


class ActionRequestRead(APIModel):
    id: UUID
    action_type: ActionType = Field(description="Action explicitly requested, distinct from a decision recommendation.")
    decision_id: UUID | None
    incident_id: UUID | None
    asset_id: UUID | None
    backup_id: UUID | None
    verification_id: UUID | None
    isolation_mode: IsolationMode | None
    requested_by_type: str
    requested_by_id: str | None
    request_reason: str | None
    approval_status: ApprovalStatus = Field(description="Approval lifecycle for this request; independent of recommendation status.")
    approved_by_id: str | None
    approved_at: UTCDateTime | None
    execution_status: ActionExecutionStatus = Field(description="Execution lifecycle for this request; no execution is implied by a decision.")
    started_at: UTCDateTime | None
    completed_at: UTCDateTime | None
    component_result: dict[str, Any]
    failure_reason: str | None
    correlation_id: UUID
    created_at: UTCDateTime
    updated_at: UTCDateTime


class BackupCreate(APIModel):
    asset_id: UUID
    created_by_component: str = Field(min_length=1, max_length=100)
    external_backup_id: str = Field(min_length=1, max_length=255)
    created_at: UTCDateTime
    backup_type: str | None = Field(default=None, max_length=100)
    size_bytes: int | None = Field(default=None, ge=0)
    storage_reference: str | None = Field(default=None, max_length=1024)
    manifest_reference: str | None = Field(default=None, max_length=1024)
    protection_status: BackupProtectionStatus
    lifecycle_status: BackupLifecycleStatus
    encryption_status: str = Field(min_length=1, max_length=50)
    correlation_id: UUID | None = None

    @model_validator(mode="after")
    def validate_safe_references(self):
        _reject_sensitive_content(self.storage_reference)
        _reject_sensitive_content(self.manifest_reference)
        _reject_sensitive_content(self.encryption_status)
        return self


class BackupRead(APIModel):
    backup_id: UUID = Field(validation_alias=AliasChoices("backup_id", "id"))
    asset_id: UUID
    created_by_component: str = Field(validation_alias=AliasChoices("created_by_component", "source_component"))
    external_backup_id: str
    backup_type: str | None
    size_bytes: int | None
    storage_reference: str | None
    manifest_reference: str | None
    lifecycle_status: BackupLifecycleStatus
    protection_status: BackupProtectionStatus
    encryption_status: str
    created_at: UTCDateTime | None = Field(validation_alias=AliasChoices("backup_created_at", "created_at"))
    correlation_id: UUID
    updated_at: UTCDateTime


class BackupCandidateRead(BackupRead):
    verified: bool
    recovery_eligible: bool
    eligibility_reasons: list[str]


class RecoveryEligibilityRead(APIModel):
    eligible: bool
    backup_id: UUID
    reasons: list[str]


class IntegrityVerificationCreate(APIModel):
    reason: str | None = None
    requested_by: str | None = Field(default=None, max_length=255)
    correlation_id: UUID | None = None

    @model_validator(mode="after")
    def validate_safe_request(self):
        _reject_sensitive_content(self.reason)
        _reject_sensitive_content(self.requested_by)
        return self


class IntegrityVerificationResult(APIModel):
    result_status: VerificationStatus
    algorithm: str | None = Field(default=None, max_length=50)
    expected_digest: str | None = Field(default=None, max_length=512)
    trusted_manifest_reference: str | None = Field(default=None, max_length=1024)
    observed_digest: str | None = Field(default=None, max_length=512)
    verification_evidence_reference: str | None = Field(default=None, max_length=1024)
    verifier_component: str = Field(min_length=1, max_length=100)
    verifier_version: str | None = Field(default=None, max_length=100)
    started_at: UTCDateTime | None = None
    completed_at: UTCDateTime | None = None
    failure_reason: str | None = None
    correlation_id: UUID | None = None

    @model_validator(mode="after")
    def validate_component_result(self):
        if self.result_status == VerificationStatus.QUEUED:
            raise ValueError("Component results cannot set verification status to queued")
        if self.result_status == VerificationStatus.PASSED:
            if not (self.observed_digest or self.verification_evidence_reference):
                raise ValueError("A passed result requires observed digest or verification evidence")
        _reject_sensitive_content(self.trusted_manifest_reference)
        _reject_sensitive_content(self.verification_evidence_reference)
        _reject_sensitive_content(self.failure_reason)
        return self


class BackupProtectionResult(APIModel):
    protection_status: BackupProtectionStatus
    execution_status: ActionExecutionStatus
    component_reference: str | None = Field(default=None, max_length=255)
    completed_at: UTCDateTime | None = None
    failure_reason: str | None = None
    correlation_id: UUID | None = None
    action_request_id: UUID | None = None

    @model_validator(mode="after")
    def validate_reported_outcome(self):
        expected = {
            ActionExecutionStatus.EXECUTING: BackupProtectionStatus.PENDING,
            ActionExecutionStatus.SUCCEEDED: BackupProtectionStatus.PROTECTED,
            ActionExecutionStatus.FAILED: BackupProtectionStatus.FAILED,
        }
        if self.execution_status not in expected:
            raise ValueError("Protection result execution_status must be executing, succeeded, or failed")
        if self.protection_status != expected[self.execution_status]:
            raise ValueError("Protection and execution statuses must describe the same outcome")
        if self.execution_status == ActionExecutionStatus.FAILED and not self.failure_reason:
            raise ValueError("A failed protection report requires failure_reason")
        _reject_sensitive_content(self.component_reference)
        _reject_sensitive_content(self.failure_reason)
        return self


class BackupProtectionResultRead(APIModel):
    backup: BackupRead
    action_request_id: UUID | None
    execution_status: ActionExecutionStatus
    correlation_id: UUID


class IntegrityVerificationRead(APIModel):
    verification_id: UUID = Field(validation_alias=AliasChoices("verification_id", "id"))
    backup_id: UUID
    asset_id: UUID
    algorithm: str | None
    expected_digest: str | None
    observed_digest: str | None
    verification_evidence_reference: str | None
    trusted_manifest_reference: str | None
    result_status: VerificationStatus
    verifier_component: str | None
    verifier_version: str | None
    started_at: UTCDateTime | None
    completed_at: UTCDateTime | None
    failure_reason: str | None
    correlation_id: UUID


class IntegrityVerificationRequested(APIModel):
    verification_id: UUID
    backup_id: UUID
    result_status: VerificationStatus
    requested_at: UTCDateTime
    correlation_id: UUID


class IsolationActionCreate(APIModel):
    action_request_id: UUID
    asset_id: UUID
    incident_id: UUID | None = None
    decision_id: UUID | None = None
    isolation_mode: IsolationMode
    reason: str | None = None
    correlation_id: UUID | None = None

    @model_validator(mode="after")
    def validate_reason(self):
        _reject_sensitive_content(self.reason)
        return self


class IsolationReleaseCreate(APIModel):
    requested_by_type: str = Field(min_length=1, max_length=50)
    requested_by_id: str | None = Field(default=None, max_length=255)
    reason: str | None = None
    correlation_id: UUID | None = None

    @model_validator(mode="after")
    def validate_reason(self):
        _reject_sensitive_content(self.reason)
        return self


class IsolationComponentResult(APIModel):
    execution_status: IsolationExecutionStatus
    network_state: IsolationNetworkState
    acknowledged_at: UTCDateTime | None = None
    completed_at: UTCDateTime | None = None
    component_reference: str = Field(min_length=1, max_length=255)
    failure_reason: str | None = None
    correlation_id: UUID

    @model_validator(mode="after")
    def validate_component_result(self):
        if self.execution_status not in {
            IsolationExecutionStatus.EXECUTING,
            IsolationExecutionStatus.ISOLATED,
            IsolationExecutionStatus.RELEASED,
            IsolationExecutionStatus.FAILED,
            IsolationExecutionStatus.CANCELLED,
        }:
            raise ValueError("Component result status must be executing, isolated, released, failed, or cancelled")
        if self.execution_status == IsolationExecutionStatus.ISOLATED and self.network_state != IsolationNetworkState.ISOLATED:
            raise ValueError("Confirmed isolation requires network_state=isolated")
        if self.execution_status == IsolationExecutionStatus.FAILED and not self.failure_reason:
            raise ValueError("Failed isolation results require failure_reason")
        _reject_sensitive_content(self.component_reference)
        _reject_sensitive_content(self.failure_reason)
        return self


class IsolationActionRead(APIModel):
    isolation_action_id: UUID = Field(validation_alias=AliasChoices("isolation_action_id", "id"))
    action_request_id: UUID
    asset_id: UUID
    incident_id: UUID | None
    decision_id: UUID | None
    operation: ActionType
    execution_status: IsolationExecutionStatus
    isolation_mode: IsolationMode | None
    network_state: IsolationNetworkState | None
    requested_at: UTCDateTime
    acknowledged_at: UTCDateTime | None
    completed_at: UTCDateTime | None
    released_at: UTCDateTime | None
    component_reference: str | None
    failure_reason: str | None
    correlation_id: UUID


class AssetIsolationRead(APIModel):
    asset_id: UUID
    isolation_state: AssetIsolationState
    active_isolation_action_id: UUID | None
    execution_status: IsolationExecutionStatus | None
    network_state: IsolationNetworkState | None
    isolation_mode: IsolationMode | None
    requested_at: UTCDateTime | None
    acknowledged_at: UTCDateTime | None
    component_reference: str | None


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
    isolation_action_id: UUID | None = None
    recovery_job_id: UUID | None = None
    source_component: str | None = Field(default=None, max_length=100)
    reason: str | None = None
    safe_metadata: dict[str, Any] = Field(default_factory=dict)
    correlation_id: UUID | None = None
    occurred_at: UTCDateTime | None = None

    @model_validator(mode="after")
    def validate_safe_metadata(self):
        _reject_secret_fields(self.safe_metadata)
        return self


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
    isolation_action_id: UUID | None
    recovery_job_id: UUID | None
    source_component: str | None
    reason: str | None
    safe_metadata: dict[str, Any]
    correlation_id: UUID
    occurred_at: UTCDateTime


class SystemSettingsUpdate(APIModel):
    risk_thresholds: RiskThresholds | None = None
    isolation_policy: dict[str, Any] | None = None
    backup_policy: dict[str, Any] | None = None
    recovery_policy: dict[str, Any] | None = None
    notification_policy: dict[str, Any] | None = None

    @model_validator(mode="after")
    def validate_no_secret_fields(self):
        for policy in (
            self.isolation_policy,
            self.backup_policy,
            self.recovery_policy,
            self.notification_policy,
        ):
            if policy is not None:
                _reject_secret_fields(policy)
        return self


class SystemSettingsRead(APIModel):
    id: UUID
    version: int
    risk_thresholds: RiskThresholds
    isolation_policy: dict[str, Any]
    backup_policy: dict[str, Any]
    recovery_policy: dict[str, Any]
    notification_policy: dict[str, Any]
    created_at: UTCDateTime
    updated_at: UTCDateTime

    @model_validator(mode="after")
    def validate_no_secret_fields(self):
        for policy in (
            self.isolation_policy,
            self.backup_policy,
            self.recovery_policy,
            self.notification_policy,
        ):
            _reject_secret_fields(policy)
        return self