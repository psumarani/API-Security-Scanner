"""Scans, discovered endpoints, findings and evidence."""

import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.enums import (
    Confidence,
    DiscoverySource,
    FindingStatus,
    OwaspCategory,
    ScanStatus,
    Severity,
)
from app.models.mixins import CreatedAt, UUIDPrimaryKey, utcnow
from app.models.target import ScanTarget
from app.models.types import enum_column
from app.models.user import User


class Scan(UUIDPrimaryKey, CreatedAt, Base):
    __tablename__ = "scans"
    __table_args__ = (Index("ix_scans_user_id_created_at", "user_id", "created_at"),)

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("scan_targets.id", ondelete="CASCADE"), index=True, nullable=False
    )
    status: Mapped[ScanStatus] = mapped_column(
        enum_column(ScanStatus, "scan_status"),
        default=ScanStatus.QUEUED,
        index=True,
        nullable=False,
    )
    # Modules, limits and scope used for this run (reproducibility).
    configuration: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    scanner_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Live progress (stage, per-module status) and request usage, updated while running.
    progress: Mapped[dict] = mapped_column(
        JSON, default=dict, server_default=text("'{}'"), nullable=False
    )
    requests_made: Mapped[int] = mapped_column(
        Integer, default=0, server_default=text("0"), nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_summary: Mapped[str | None] = mapped_column(Text, nullable=True)

    user: Mapped[User] = relationship(back_populates="scans")
    target: Mapped[ScanTarget] = relationship(back_populates="scans")
    endpoints: Mapped[list["Endpoint"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )
    findings: Mapped[list["VulnerabilityFinding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )


class Endpoint(UUIDPrimaryKey, CreatedAt, Base):
    __tablename__ = "endpoints"
    __table_args__ = (
        UniqueConstraint("scan_id", "http_method", "path", name="uq_endpoints_scan_method_path"),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False
    )
    path: Mapped[str] = mapped_column(String(1024), nullable=False)
    http_method: Mapped[str] = mapped_column(String(10), nullable=False)
    parameters: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    # NULL means "unknown": the specification did not say.
    authentication_required: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    discovery_source: Mapped[DiscoverySource] = mapped_column(
        enum_column(DiscoverySource, "discovery_source"), nullable=False
    )

    scan: Mapped[Scan] = relationship(back_populates="endpoints")
    findings: Mapped[list["VulnerabilityFinding"]] = relationship(back_populates="endpoint")


class VulnerabilityFinding(UUIDPrimaryKey, CreatedAt, Base):
    __tablename__ = "vulnerability_findings"
    __table_args__ = (
        UniqueConstraint("scan_id", "fingerprint", name="uq_vulnerability_findings_scan_fp"),
        Index("ix_vulnerability_findings_scan_id_severity", "scan_id", "severity"),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    endpoint_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("endpoints.id", ondelete="SET NULL"), index=True, nullable=True
    )
    check_id: Mapped[str] = mapped_column(String(64), nullable=False)
    category: Mapped[OwaspCategory] = mapped_column(
        enum_column(OwaspCategory, "owasp_category"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[Severity] = mapped_column(enum_column(Severity, "severity"), nullable=False)
    confidence: Mapped[Confidence] = mapped_column(
        enum_column(Confidence, "confidence"), nullable=False
    )
    status: Mapped[FindingStatus] = mapped_column(
        enum_column(FindingStatus, "finding_status"), nullable=False
    )
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    # Stable hash of (check, endpoint, discriminator) used for de-duplication within a scan.
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)

    scan: Mapped[Scan] = relationship(back_populates="findings")
    endpoint: Mapped[Endpoint | None] = relationship(back_populates="findings")
    evidence: Mapped[list["FindingEvidence"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", passive_deletes=True
    )


class FindingEvidence(UUIDPrimaryKey, Base):
    """Sanitized request/response summaries. Never raw secrets or full bodies."""

    __tablename__ = "finding_evidence"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("vulnerability_findings.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    request_summary: Mapped[str] = mapped_column(Text, nullable=False)
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_summary: Mapped[str] = mapped_column(Text, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), default=utcnow, nullable=False
    )

    finding: Mapped[VulnerabilityFinding] = relationship(back_populates="evidence")
