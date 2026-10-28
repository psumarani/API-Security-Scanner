"""Schemas for scans, findings, endpoints and the dashboard."""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import (
    Confidence,
    DiscoverySource,
    FindingStatus,
    OwaspCategory,
    ScanStatus,
    Severity,
)
from app.scanner.settings import ScanSettings


class ScanCreate(BaseModel):
    target_id: uuid.UUID
    modules: list[str] = Field(min_length=1, max_length=20)
    auth_profile_ids: list[uuid.UUID] | None = Field(
        default=None, description="Profiles to use; default is every profile of the target"
    )
    authorization_confirmed: bool = Field(
        description="Must be true: confirms the scope shown is authorized for testing."
    )
    settings: ScanSettings = ScanSettings()


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target_id: uuid.UUID
    target_name: str
    status: ScanStatus
    configuration: dict[str, Any]
    progress: dict[str, Any]
    requests_made: int
    scanner_version: str | None
    started_at: datetime | None
    completed_at: datetime | None
    error_summary: str | None
    created_at: datetime
    finding_counts: dict[str, int] = Field(default_factory=dict)
    endpoint_count: int = 0


class EndpointRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    path: str
    http_method: str
    parameters: list[Any]
    authentication_required: bool | None
    discovery_source: DiscoverySource
    finding_count: int = 0


class EndpointRef(BaseModel):
    id: uuid.UUID
    path: str
    http_method: str


class FindingRead(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    target_name: str | None = None
    endpoint: EndpointRef | None
    check_id: str
    category: OwaspCategory
    title: str
    severity: Severity
    confidence: Confidence
    status: FindingStatus
    created_at: datetime


class EvidenceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    request_summary: str
    response_status: int | None
    response_summary: str
    observed_at: datetime


class FindingDetail(FindingRead):
    description: str
    remediation: str
    evidence: list[EvidenceRead]
    scan_status: ScanStatus
    scan_created_at: datetime


class ModuleInfo(BaseModel):
    id: str
    name: str
    description: str
    categories: list[str]
    automated: bool
    prerequisites: list[str]
    validation: str
    limitations: str
    default_enabled: bool


class CategoryCoverageRead(BaseModel):
    category: str
    title: str
    support: str
    automation: str
    modules: list[str]
    prerequisites: str
    validation: str
    limitations: str
    evidence: str


class ScannerCatalog(BaseModel):
    scanner_version: str
    modules: list[ModuleInfo]
    owasp_coverage: list[CategoryCoverageRead]
    limits: dict[str, Any]


class SpecPreviewEndpoint(BaseModel):
    method: str
    path: str
    authentication_required: bool | None
    deprecated: bool
    parameters: int


class SpecPreview(BaseModel):
    spec_version: str
    title: str | None
    endpoint_count: int
    security_schemes: dict[str, str]
    base_path_hint: str
    warnings: list[str]
    endpoints: list[SpecPreviewEndpoint]


class FailureInfo(BaseModel):
    scan_id: uuid.UUID
    target_name: str
    error_summary: str | None
    completed_at: datetime | None


class DashboardSummary(BaseModel):
    total_scans: int
    completed_scans: int
    running_scans: int
    failed_scans: int
    total_findings: int
    findings_by_severity: dict[str, int]
    findings_by_status: dict[str, int]
    recent_scans: list[ScanRead]
    recent_findings: list[FindingRead]
    recent_failures: list[FailureInfo]
