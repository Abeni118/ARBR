from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    event,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def new_id() -> str:
    return str(uuid4())


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class UUIDPrimaryKey:
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )


class Asset(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("external_source", "external_id", name="uq_asset_external_ref"),
        Index("ix_assets_hostname", "hostname"),
    )

    external_source: Mapped[str | None] = mapped_column(String(100))
    external_id: Mapped[str | None] = mapped_column(String(255))
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    asset_type: Mapped[str | None] = mapped_column(String(100))
    environment: Mapped[str | None] = mapped_column(String(100))
    criticality: Mapped[str | None] = mapped_column(String(50))
    network_segment: Mapped[str | None] = mapped_column(String(255))
    monitoring_status: Mapped[str] = mapped_column(String(50), default="unknown", nullable=False)

    security_events: Mapped[list["SecurityEvent"]] = relationship(back_populates="asset")
    threat_incidents: Mapped[list["ThreatIncident"]] = relationship(back_populates="asset")
    backups: Mapped[list["Backup"]] = relationship(back_populates="asset")


class SecurityEvent(UUIDPrimaryKey, Base):
    __tablename__ = "security_events"
    __table_args__ = (
        CheckConstraint(
            "processing_status IN ('received', 'normalized', 'processed', 'rejected')",
            name="ck_security_event_processing_status",
        ),
        CheckConstraint(
            "event_severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name="ck_security_event_severity",
        ),
        UniqueConstraint("source", "source_event_id", name="uq_security_event_source_id"),
        Index("ix_security_events_occurred_at", "occurred_at"),
    )

    source: Mapped[str] = mapped_column(String(100), nullable=False)
    source_event_id: Mapped[str] = mapped_column(String(255), nullable=False)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), index=True)
    incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("threat_incidents.id", ondelete="SET NULL"), index=True
    )
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    event_severity: Mapped[str] = mapped_column(String(20), nullable=False)
    processing_status: Mapped[str] = mapped_column(String(20), default="received", nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    indicators: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    source_component: Mapped[str | None] = mapped_column(String(100))
    correlation_id: Mapped[str] = mapped_column(String(36), default=new_id, nullable=False, index=True)

    asset: Mapped[Asset | None] = relationship(back_populates="security_events")
    incident: Mapped["ThreatIncident | None"] = relationship(back_populates="security_events")


class ThreatIncident(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "threat_incidents"
    __table_args__ = (
        CheckConstraint(
            "lifecycle_status IN ('new', 'triaged', 'investigating', 'contained', "
            "'recovery_in_progress', 'recovered', 'resolved', 'false_positive', 'closed')",
            name="ck_threat_incident_lifecycle_status",
        ),
        Index("ix_threat_incidents_detected_at", "detected_at"),
    )

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    threat_type: Mapped[str] = mapped_column(String(100), nullable=False)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="RESTRICT"), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    indicators: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    detection_source: Mapped[str | None] = mapped_column(String(100))
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    lifecycle_status: Mapped[str] = mapped_column(String(32), default="new", nullable=False)
    current_risk_assessment_id: Mapped[str | None] = mapped_column(
        ForeignKey("risk_assessments.id", use_alter=True, name="fk_incident_current_risk"), nullable=True
    )
    correlation_id: Mapped[str] = mapped_column(String(36), default=new_id, nullable=False, index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    asset: Mapped[Asset] = relationship(back_populates="threat_incidents", foreign_keys=[asset_id])
    security_events: Mapped[list[SecurityEvent]] = relationship(back_populates="incident", foreign_keys="SecurityEvent.incident_id")
    risk_assessments: Mapped[list["RiskAssessment"]] = relationship(
        back_populates="incident", foreign_keys="RiskAssessment.incident_id"
    )
    decisions: Mapped[list["Decision"]] = relationship(back_populates="incident")
    action_requests: Mapped[list["ActionRequest"]] = relationship(back_populates="incident")
    recovery_jobs: Mapped[list["RecoveryJob"]] = relationship(back_populates="incident")


class RiskAssessment(UUIDPrimaryKey, Base):
    __tablename__ = "risk_assessments"
    __table_args__ = (
        CheckConstraint("score >= 0 AND score <= 100", name="ck_risk_assessment_score_range"),
        CheckConstraint("status IN ('completed', 'failed')", name="ck_risk_assessment_status"),
        CheckConstraint("risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')", name="ck_risk_assessment_level"),
        Index("ix_risk_assessments_assessed_at", "assessed_at"),
    )

    incident_id: Mapped[str] = mapped_column(ForeignKey("threat_incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="RESTRICT"), nullable=False, index=True)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)
    factors: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    confidence: Mapped[float | None] = mapped_column()
    model_version: Mapped[str | None] = mapped_column(String(100))
    policy_version: Mapped[str | None] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(20), default="completed", nullable=False)
    assessed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(36), default=new_id, nullable=False, index=True)

    incident: Mapped[ThreatIncident] = relationship(back_populates="risk_assessments", foreign_keys=[incident_id])
    decisions: Mapped[list["Decision"]] = relationship(back_populates="risk_assessment")


class Decision(UUIDPrimaryKey, Base):
    __tablename__ = "decisions"
    __table_args__ = (
        CheckConstraint(
            "decision_status IN ('proposed', 'accepted', 'rejected', 'superseded')",
            name="ck_decision_status",
        ),
    )

    incident_id: Mapped[str] = mapped_column(ForeignKey("threat_incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("risk_assessments.id", ondelete="RESTRICT"), nullable=False, index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="RESTRICT"), nullable=False, index=True)
    recommended_actions: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    approval_required: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    decision_status: Mapped[str] = mapped_column(String(20), default="proposed", nullable=False)
    policy_version: Mapped[str | None] = mapped_column(String(100))
    engine_version: Mapped[str | None] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(36), default=new_id, nullable=False, index=True)

    incident: Mapped[ThreatIncident] = relationship(back_populates="decisions")
    risk_assessment: Mapped[RiskAssessment] = relationship(back_populates="decisions")
    action_requests: Mapped[list["ActionRequest"]] = relationship(back_populates="decision")


class ActionRequest(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "action_requests"
    __table_args__ = (
        CheckConstraint(
            "approval_status IN ('not_required', 'pending', 'approved', 'rejected', 'revoked')",
            name="ck_action_request_approval_status",
        ),
        CheckConstraint(
            "execution_status IN ('not_started', 'queued', 'executing', 'succeeded', 'failed', 'cancelled')",
            name="ck_action_request_execution_status",
        ),
    )

    action_type: Mapped[str] = mapped_column(String(50), nullable=False)
    decision_id: Mapped[str | None] = mapped_column(ForeignKey("decisions.id", ondelete="SET NULL"), index=True)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("threat_incidents.id", ondelete="SET NULL"), index=True)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), index=True)
    backup_id: Mapped[str | None] = mapped_column(ForeignKey("backups.id", ondelete="SET NULL"), index=True)
    verification_id: Mapped[str | None] = mapped_column(
        ForeignKey("integrity_verifications.id", ondelete="SET NULL"), index=True
    )
    requested_by_type: Mapped[str] = mapped_column(String(50), nullable=False)
    requested_by_id: Mapped[str | None] = mapped_column(String(255))
    request_reason: Mapped[str | None] = mapped_column(Text)
    approval_status: Mapped[str] = mapped_column(String(30), default="pending", nullable=False)
    approved_by_id: Mapped[str | None] = mapped_column(String(255))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    execution_status: Mapped[str] = mapped_column(String(20), default="not_started", nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    component_result: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    failure_reason: Mapped[str | None] = mapped_column(Text)
    correlation_id: Mapped[str] = mapped_column(String(36), default=new_id, nullable=False, index=True)

    decision: Mapped[Decision | None] = relationship(back_populates="action_requests")
    incident: Mapped[ThreatIncident | None] = relationship(back_populates="action_requests")
    isolation_action: Mapped["IsolationAction | None"] = relationship(back_populates="action_request", uselist=False)
    recovery_job: Mapped["RecoveryJob | None"] = relationship(back_populates="action_request", uselist=False)


class Backup(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "backups"
    __table_args__ = (
        CheckConstraint(
            "lifecycle_status IN ('available', 'quarantined', 'expired', 'unavailable')",
            name="ck_backup_lifecycle_status",
        ),
        CheckConstraint(
            "protection_status IN ('protected', 'pending', 'failed', 'not_protected', 'unknown')",
            name="ck_backup_protection_status",
        ),
        UniqueConstraint("source_component", "external_backup_id", name="uq_backup_external_id"),
    )

    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="RESTRICT"), nullable=False, index=True)
    source_component: Mapped[str] = mapped_column(String(100), nullable=False)
    external_backup_id: Mapped[str] = mapped_column(String(255), nullable=False)
    backup_type: Mapped[str | None] = mapped_column(String(100))
    size_bytes: Mapped[int | None] = mapped_column(Integer)
    storage_reference: Mapped[str | None] = mapped_column(String(1024))
    manifest_reference: Mapped[str | None] = mapped_column(String(1024))
    lifecycle_status: Mapped[str] = mapped_column(String(20), default="available", nullable=False)
    protection_status: Mapped[str] = mapped_column(String(20), default="unknown", nullable=False)
    encryption_status: Mapped[str] = mapped_column(String(50), default="unknown", nullable=False)
    backup_created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    correlation_id: Mapped[str] = mapped_column(String(36), default=new_id, nullable=False, index=True)

    asset: Mapped[Asset] = relationship(back_populates="backups")
    verifications: Mapped[list["IntegrityVerification"]] = relationship(back_populates="backup")
    recovery_jobs: Mapped[list["RecoveryJob"]] = relationship(back_populates="backup")


class IntegrityVerification(UUIDPrimaryKey, Base):
    __tablename__ = "integrity_verifications"
    __table_args__ = (
        CheckConstraint(
            "result_status IN ('queued', 'running', 'passed', 'failed', 'inconclusive', 'cancelled', 'error')",
            name="ck_integrity_verification_status",
        ),
    )

    backup_id: Mapped[str] = mapped_column(ForeignKey("backups.id", ondelete="RESTRICT"), nullable=False, index=True)
    algorithm: Mapped[str | None] = mapped_column(String(50))
    expected_digest: Mapped[str | None] = mapped_column(String(512))
    observed_digest: Mapped[str | None] = mapped_column(String(512))
    trusted_manifest_reference: Mapped[str | None] = mapped_column(String(1024))
    result_status: Mapped[str] = mapped_column(String(20), default="queued", nullable=False)
    verifier_component: Mapped[str | None] = mapped_column(String(100))
    verifier_version: Mapped[str | None] = mapped_column(String(100))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failure_reason: Mapped[str | None] = mapped_column(Text)
    correlation_id: Mapped[str] = mapped_column(String(36), default=new_id, nullable=False, index=True)

    backup: Mapped[Backup] = relationship(back_populates="verifications")
    recovery_jobs: Mapped[list["RecoveryJob"]] = relationship(back_populates="verification")


class IsolationAction(UUIDPrimaryKey, Base):
    __tablename__ = "isolation_actions"
    __table_args__ = (
        CheckConstraint(
            "execution_status IN ('requested', 'awaiting_approval', 'approved', 'executing', "
            "'isolated', 'failed', 'release_requested', 'released', 'cancelled')",
            name="ck_isolation_action_status",
        ),
    )

    action_request_id: Mapped[str] = mapped_column(
        ForeignKey("action_requests.id", ondelete="RESTRICT"), nullable=False, unique=True
    )
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="RESTRICT"), nullable=False, index=True)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("threat_incidents.id", ondelete="SET NULL"), index=True)
    execution_status: Mapped[str] = mapped_column(String(30), default="requested", nullable=False)
    isolation_mode: Mapped[str | None] = mapped_column(String(100))
    network_state: Mapped[str | None] = mapped_column(String(100))
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    component_reference: Mapped[str | None] = mapped_column(String(255))
    failure_reason: Mapped[str | None] = mapped_column(Text)
    correlation_id: Mapped[str] = mapped_column(String(36), default=new_id, nullable=False, index=True)

    action_request: Mapped[ActionRequest] = relationship(back_populates="isolation_action")


class RecoveryJob(UUIDPrimaryKey, Base):
    __tablename__ = "recovery_jobs"
    __table_args__ = (
        CheckConstraint(
            "job_status IN ('requested', 'awaiting_approval', 'approved', 'queued', 'restoring', "
            "'scanning', 'validation_failed', 'ready_for_cutover', 'cutover_in_progress', "
            "'completed', 'failed', 'cancelled')",
            name="ck_recovery_job_status",
        ),
        CheckConstraint(
            "cutover_status IN ('not_requested', 'pending_approval', 'approved', 'in_progress', "
            "'completed', 'failed', 'cancelled')",
            name="ck_recovery_cutover_status",
        ),
    )

    action_request_id: Mapped[str] = mapped_column(
        ForeignKey("action_requests.id", ondelete="RESTRICT"), nullable=False, unique=True
    )
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="RESTRICT"), nullable=False, index=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("threat_incidents.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    backup_id: Mapped[str] = mapped_column(ForeignKey("backups.id", ondelete="RESTRICT"), nullable=False, index=True)
    verification_id: Mapped[str] = mapped_column(
        ForeignKey("integrity_verifications.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    recovery_environment: Mapped[str | None] = mapped_column(String(255))
    job_status: Mapped[str] = mapped_column(String(32), default="requested", nullable=False)
    cutover_status: Mapped[str] = mapped_column(String(32), default="not_requested", nullable=False)
    malware_scan_status: Mapped[str] = mapped_column(String(50), default="not_started", nullable=False)
    security_validation_status: Mapped[str] = mapped_column(String(50), default="not_started", nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    outcome: Mapped[str | None] = mapped_column(Text)
    failure_reason: Mapped[str | None] = mapped_column(Text)
    component_reference: Mapped[str | None] = mapped_column(String(255))
    correlation_id: Mapped[str] = mapped_column(String(36), default=new_id, nullable=False, index=True)

    action_request: Mapped[ActionRequest] = relationship(back_populates="recovery_job")
    incident: Mapped[ThreatIncident] = relationship(back_populates="recovery_jobs")
    backup: Mapped[Backup] = relationship(back_populates="recovery_jobs")
    verification: Mapped[IntegrityVerification] = relationship(back_populates="recovery_jobs")


class AuditEvent(UUIDPrimaryKey, Base):
    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_events_occurred_at", "occurred_at"),)

    actor_type: Mapped[str] = mapped_column(String(50), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(150), nullable=False)
    result_status: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String(100))
    resource_id: Mapped[str | None] = mapped_column(String(36), index=True)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), index=True)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("threat_incidents.id", ondelete="SET NULL"), index=True)
    event_id: Mapped[str | None] = mapped_column(ForeignKey("security_events.id", ondelete="SET NULL"), index=True)
    assessment_id: Mapped[str | None] = mapped_column(
        ForeignKey("risk_assessments.id", ondelete="SET NULL"), index=True
    )
    decision_id: Mapped[str | None] = mapped_column(ForeignKey("decisions.id", ondelete="SET NULL"), index=True)
    action_request_id: Mapped[str | None] = mapped_column(
        ForeignKey("action_requests.id", ondelete="SET NULL"), index=True
    )
    backup_id: Mapped[str | None] = mapped_column(ForeignKey("backups.id", ondelete="SET NULL"), index=True)
    verification_id: Mapped[str | None] = mapped_column(
        ForeignKey("integrity_verifications.id", ondelete="SET NULL"), index=True
    )
    recovery_job_id: Mapped[str | None] = mapped_column(
        ForeignKey("recovery_jobs.id", ondelete="SET NULL"), index=True
    )
    source_component: Mapped[str | None] = mapped_column(String(100))
    reason: Mapped[str | None] = mapped_column(Text)
    safe_metadata: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(36), default=new_id, nullable=False, index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)


class SystemSettings(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "system_settings"
    __table_args__ = (UniqueConstraint("is_singleton", name="uq_system_settings_singleton"),)

    is_singleton: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    risk_thresholds: Mapped[dict] = mapped_column(
        JSON,
        default=lambda: {"low_max": 29, "medium_max": 59, "high_max": 79, "critical_min": 80},
        nullable=False,
    )
    isolation_policy: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    backup_policy: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    recovery_policy: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    notification_policy: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


def _reject_audit_mutation(mapper, connection, target) -> None:
    raise ValueError("Audit events are append-only and cannot be updated or deleted")


event.listen(AuditEvent, "before_update", _reject_audit_mutation)
event.listen(AuditEvent, "before_delete", _reject_audit_mutation)