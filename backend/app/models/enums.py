"""Enumerations shared by models, schemas and the scanner."""

from enum import StrEnum


class UserRole(StrEnum):
    USER = "user"
    ADMIN = "admin"


class AuthType(StrEnum):
    NONE = "none"
    BEARER = "bearer"
    API_KEY = "api_key"
    TEST_ACCOUNT = "test_account"


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class DiscoverySource(StrEnum):
    OPENAPI = "openapi"
    MANUAL = "manual"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingStatus(StrEnum):
    """Validation status. Confirmed means the evidence demonstrates the weakness."""

    CONFIRMED = "confirmed"
    POTENTIAL = "potential"
    INFORMATIONAL = "informational"
    INCONCLUSIVE = "inconclusive"


class OwaspCategory(StrEnum):
    """OWASP API Security Top 10 (2023) plus a bucket for non-mapped observations."""

    API1_BOLA = "API1:2023"
    API2_BROKEN_AUTH = "API2:2023"
    API3_BOPLA = "API3:2023"
    API4_RESOURCE_CONSUMPTION = "API4:2023"
    API5_BFLA = "API5:2023"
    API6_BUSINESS_FLOWS = "API6:2023"
    API7_SSRF = "API7:2023"
    API8_MISCONFIGURATION = "API8:2023"
    API9_INVENTORY = "API9:2023"
    API10_UNSAFE_CONSUMPTION = "API10:2023"
    OTHER = "other"
