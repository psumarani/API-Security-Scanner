"""Plain data types shared by the scanner engine and its modules (no web or DB imports)."""

import hashlib
from dataclasses import dataclass, field
from typing import Any

from app.models.enums import (
    AuthType,
    Confidence,
    DiscoverySource,
    FindingStatus,
    OwaspCategory,
    Severity,
)


@dataclass
class EvidenceDraft:
    """Sanitized evidence. Never contains credentials or full response bodies."""

    request_summary: str
    response_status: int | None
    response_summary: str


@dataclass
class FindingDraft:
    check_id: str
    category: OwaspCategory
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    status: FindingStatus
    remediation: str
    endpoint_key: tuple[str, str] | None = None  # (METHOD, path)
    discriminator: str = ""  # distinguishes several findings of one check on one endpoint
    evidence: list[EvidenceDraft] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        method, path = self.endpoint_key or ("", "")
        raw = "|".join([self.check_id, method, path, self.discriminator])
        return hashlib.sha256(raw.encode()).hexdigest()


@dataclass
class EndpointInfo:
    path: str
    method: str
    parameters: list[dict[str, Any]] = field(default_factory=list)
    request_body: dict[str, Any] | None = None
    authentication_required: bool | None = None  # None = unknown
    deprecated: bool = False
    summary: str | None = None
    source: DiscoverySource = DiscoverySource.OPENAPI

    @property
    def key(self) -> tuple[str, str]:
        return (self.method.upper(), self.path)


@dataclass
class ProfileAuth:
    """Ready-to-use credentials for one auth profile (held in memory only)."""

    id: str
    name: str
    role_label: str | None
    auth_type: AuthType
    headers: dict[str, str] = field(default_factory=dict)
    query: dict[str, str] = field(default_factory=dict)
    usable: bool = True
    note: str | None = None

    @property
    def label(self) -> str:
        return self.role_label or self.name


@dataclass
class ModuleResult:
    module_id: str
    status: str  # completed | skipped | failed | cancelled
    findings: int = 0
    requests: int = 0
    notes: list[str] = field(default_factory=list)
    inconclusive: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "findings": self.findings,
            "requests": self.requests,
            "notes": self.notes,
            "inconclusive": self.inconclusive,
        }


SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
STATUS_LABELS = {
    FindingStatus.CONFIRMED: "Confirmed",
    FindingStatus.POTENTIAL: "Potential",
    FindingStatus.INFORMATIONAL: "Informational",
    FindingStatus.INCONCLUSIVE: "Inconclusive",
}
__all__ = [
    "Confidence",
    "EndpointInfo",
    "EvidenceDraft",
    "FindingDraft",
    "FindingStatus",
    "ModuleResult",
    "OwaspCategory",
    "ProfileAuth",
    "Severity",
]
