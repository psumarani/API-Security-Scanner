import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, StatementError

from app.models.enums import (
    AuthType,
    Confidence,
    DiscoverySource,
    FindingStatus,
    OwaspCategory,
    ScanStatus,
    Severity,
)
from app.models.mixins import utcnow
from app.models.scan import Endpoint, Scan, VulnerabilityFinding
from app.models.target import AuthProfile, ScanTarget
from app.models.user import User


def _seed(db):
    user = User(username="u", email="u@example.com", password_hash="x")
    db.add(user)
    db.flush()
    target = ScanTarget(
        user_id=user.id,
        name="t",
        base_url="https://api.example.com",
        authorization_confirmed_at=utcnow(),
    )
    db.add(target)
    db.flush()
    scan = Scan(user_id=user.id, target_id=target.id)
    db.add(scan)
    db.flush()
    return user, target, scan


def _finding(scan, endpoint=None, fp="fp") -> VulnerabilityFinding:
    return VulnerabilityFinding(
        scan_id=scan.id,
        endpoint_id=endpoint.id if endpoint else None,
        check_id="c",
        category=OwaspCategory.API2_BROKEN_AUTH,
        title="t",
        description="d",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        status=FindingStatus.POTENTIAL,
        remediation="r",
        fingerprint=fp,
    )


def test_defaults(db_session) -> None:
    user, _, scan = _seed(db_session)
    db_session.commit()
    assert scan.status == ScanStatus.QUEUED and scan.configuration == {}
    assert user.is_active is True and user.role == "user" and user.created_at is not None


def test_finding_fingerprint_is_unique_per_scan(db_session) -> None:
    _, _, scan = _seed(db_session)
    db_session.add(_finding(scan))
    db_session.commit()
    db_session.add(_finding(scan))  # same fingerprint -> duplicate finding
    with pytest.raises(IntegrityError):
        db_session.commit()


def test_endpoint_is_unique_per_scan_method_and_path(db_session) -> None:
    _, _, scan = _seed(db_session)
    for _ in range(2):
        db_session.add(
            Endpoint(
                scan_id=scan.id,
                path="/a",
                http_method="GET",
                discovery_source=DiscoverySource.OPENAPI,
            )
        )
    with pytest.raises(IntegrityError):
        db_session.commit()


def test_invalid_enum_values_are_rejected(db_session) -> None:
    _, target, _ = _seed(db_session)
    db_session.add(AuthProfile(target_id=target.id, name="p", auth_type="telepathy"))
    with pytest.raises((StatementError, LookupError, ValueError)):
        db_session.commit()


def test_deleting_endpoint_keeps_finding(db_session) -> None:
    _, _, scan = _seed(db_session)
    ep = Endpoint(
        scan_id=scan.id, path="/a", http_method="GET", discovery_source=DiscoverySource.MANUAL
    )
    db_session.add(ep)
    db_session.flush()
    db_session.add(_finding(scan, ep))
    db_session.commit()
    db_session.delete(ep)
    db_session.commit()
    kept = db_session.scalar(select(VulnerabilityFinding))
    assert kept is not None and kept.endpoint_id is None


def test_auth_type_values_are_stored_as_strings(db_session) -> None:
    _, target, _ = _seed(db_session)
    db_session.add(AuthProfile(target_id=target.id, name="p", auth_type=AuthType.API_KEY))
    db_session.commit()
    raw = db_session.connection().exec_driver_sql("select auth_type from auth_profiles").scalar()
    assert raw == "api_key"
