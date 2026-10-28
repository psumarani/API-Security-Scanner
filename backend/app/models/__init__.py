"""Import every model so Base.metadata is complete (used by Alembic and tests)."""

from app.models.scan import Endpoint, FindingEvidence, Scan, VulnerabilityFinding
from app.models.target import AuthProfile, ScanTarget
from app.models.user import User, UserSession

__all__ = [
    "AuthProfile",
    "Endpoint",
    "FindingEvidence",
    "Scan",
    "ScanTarget",
    "User",
    "UserSession",
    "VulnerabilityFinding",
]
