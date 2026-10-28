"""Scan creation, queries, cancellation and dashboard aggregation (all owner-scoped)."""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session, joinedload

from app.core.errors import ConflictError, NotFoundError, ValidationFailed
from app.models.enums import FindingStatus, OwaspCategory, ScanStatus, Severity
from app.models.scan import Endpoint, FindingEvidence, Scan, VulnerabilityFinding
from app.models.target import AuthProfile, ScanTarget
from app.models.user import User
from app.scanner import registry
from app.scanner.engine import SCANNER_VERSION
from app.scanner.scope_validator import Scope
from app.schemas.scan import (
    DashboardSummary,
    EndpointRead,
    EndpointRef,
    EvidenceRead,
    FailureInfo,
    FindingDetail,
    FindingRead,
    ScanCreate,
    ScanRead,
)
from app.services import target_service

TERMINAL = {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED}
_SEVERITY_ORDER = case(
    {
        s.value: i
        for i, s in enumerate(
            [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        )
    },
    value=VulnerabilityFinding.severity,
)


# ---- creation ---------------------------------------------------------------------------


def create_scan(db: Session, user: User, data: ScanCreate) -> Scan:
    if not data.authorization_confirmed:
        raise ValidationFailed("You must confirm that this scope is authorized for testing")
    target = target_service.get_target(db, user, data.target_id)

    unknown = [m for m in data.modules if m not in registry.module_ids()]
    if unknown:
        raise ValidationFailed(f"Unknown scanner module(s): {', '.join(unknown)}")
    modules = list(dict.fromkeys(data.modules))

    profiles = target_service.list_auth_profiles(db, user, target.id)
    by_id = {p.id: p for p in profiles}
    if data.auth_profile_ids is None:
        selected = profiles
    else:
        missing = [str(i) for i in data.auth_profile_ids if i not in by_id]
        if missing:
            raise ValidationFailed("Auth profile(s) do not belong to this target")
        selected = [by_id[i] for i in dict.fromkeys(data.auth_profile_ids)]
    selected_ids = {p.id for p in selected}

    # Every profile referenced by BOLA/BFLA settings must be part of the selection.
    referenced: set[uuid.UUID] = {o.owner for o in data.settings.bola_objects}
    for rule in data.settings.bfla_rules:
        referenced |= set(rule.allowed) | set(rule.forbidden)
    if not referenced <= selected_ids:
        raise ValidationFailed("BOLA/BFLA settings reference auth profiles that are not selected")

    scope = Scope.from_base_url(target.base_url, allow_local_lab=target.allow_local_lab)
    scan = Scan(
        user_id=user.id,
        target_id=target.id,
        status=ScanStatus.QUEUED,
        scanner_version=SCANNER_VERSION,
        progress={
            "stage": "queued",
            "percent": 0,
            "modules": {m: {"status": "pending", "findings": 0, "requests": 0} for m in modules},
        },
        configuration={
            "modules": modules,
            "auth_profiles": [
                {
                    "id": str(p.id),
                    "name": p.name,
                    "role_label": p.role_label,
                    "auth_type": p.auth_type.value,
                }
                for p in selected
            ],
            "settings": data.settings.model_dump(mode="json"),
            "scope": {
                "origin": scope.origin,
                "base_url": scope.base_url,
                "spec_url": target.api_spec_url,
                "allow_local_lab": scope.allow_local_lab,
                "authorization_confirmed_at": datetime.now(UTC).isoformat(),
                "target_authorization_confirmed_at": target.authorization_confirmed_at.isoformat(),
            },
        },
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


# ---- queries ----------------------------------------------------------------------------


def _owned_scan(db: Session, user: User, scan_id: uuid.UUID) -> Scan:
    scan = db.scalar(
        select(Scan)
        .options(joinedload(Scan.target))
        .where(Scan.id == scan_id, Scan.user_id == user.id)
    )
    if scan is None:
        raise NotFoundError("Scan not found")
    return scan


def get_scan(db: Session, user: User, scan_id: uuid.UUID) -> Scan:
    return _owned_scan(db, user, scan_id)


def _severity_counts(db: Session, scan_ids: list[uuid.UUID]) -> dict[uuid.UUID, dict[str, int]]:
    out: dict[uuid.UUID, dict[str, int]] = {sid: {} for sid in scan_ids}
    if not scan_ids:
        return out
    rows = db.execute(
        select(VulnerabilityFinding.scan_id, VulnerabilityFinding.severity, func.count())
        .where(VulnerabilityFinding.scan_id.in_(scan_ids))
        .group_by(VulnerabilityFinding.scan_id, VulnerabilityFinding.severity)
    )
    for scan_id, sev, n in rows:
        out[scan_id][sev.value] = n
    return out


def _endpoint_counts(db: Session, scan_ids: list[uuid.UUID]) -> dict[uuid.UUID, int]:
    if not scan_ids:
        return {}
    rows = db.execute(
        select(Endpoint.scan_id, func.count())
        .where(Endpoint.scan_id.in_(scan_ids))
        .group_by(Endpoint.scan_id)
    )
    return {sid: n for sid, n in rows}


def to_scan_reads(db: Session, scans: list[Scan]) -> list[ScanRead]:
    ids = [s.id for s in scans]
    sev, eps = _severity_counts(db, ids), _endpoint_counts(db, ids)
    return [
        ScanRead(
            id=s.id,
            target_id=s.target_id,
            target_name=s.target.name,
            status=s.status,
            configuration=s.configuration,
            progress=s.progress,
            requests_made=s.requests_made,
            scanner_version=s.scanner_version,
            started_at=s.started_at,
            completed_at=s.completed_at,
            error_summary=s.error_summary,
            created_at=s.created_at,
            finding_counts=sev.get(s.id, {}),
            endpoint_count=eps.get(s.id, 0),
        )
        for s in scans
    ]


def list_scans(
    db: Session,
    user: User,
    *,
    limit: int,
    offset: int,
    status: ScanStatus | None = None,
    target_id: uuid.UUID | None = None,
) -> tuple[list[Scan], int]:
    conds = [Scan.user_id == user.id]
    if status:
        conds.append(Scan.status == status)
    if target_id:
        conds.append(Scan.target_id == target_id)
    total = db.scalar(select(func.count()).select_from(Scan).where(*conds)) or 0
    items = db.scalars(
        select(Scan)
        .options(joinedload(Scan.target))
        .where(*conds)
        .order_by(Scan.created_at.desc(), Scan.id)
        .limit(limit)
        .offset(offset)
    ).all()
    return list(items), total


def cancel_scan(db: Session, user: User, scan_id: uuid.UUID) -> Scan:
    scan = _owned_scan(db, user, scan_id)
    if scan.status in TERMINAL:
        raise ConflictError(f"Scan already {scan.status.value}")
    scan.status = ScanStatus.CANCELLED
    scan.completed_at = datetime.now(UTC)
    scan.error_summary = "Cancelled by user"
    db.commit()
    db.refresh(scan)
    return scan


def list_endpoints(db: Session, user: User, scan_id: uuid.UUID) -> list[EndpointRead]:
    scan = _owned_scan(db, user, scan_id)
    counts = dict(
        db.execute(
            select(VulnerabilityFinding.endpoint_id, func.count())
            .where(
                VulnerabilityFinding.scan_id == scan.id,
                VulnerabilityFinding.endpoint_id.is_not(None),
            )
            .group_by(VulnerabilityFinding.endpoint_id)
        ).all()
    )
    eps = db.scalars(
        select(Endpoint)
        .where(Endpoint.scan_id == scan.id)
        .order_by(Endpoint.path, Endpoint.http_method)
    ).all()
    return [
        EndpointRead(
            id=e.id,
            path=e.path,
            http_method=e.http_method,
            parameters=e.parameters,
            authentication_required=e.authentication_required,
            discovery_source=e.discovery_source,
            finding_count=counts.get(e.id, 0),
        )
        for e in eps
    ]


def _finding_read(f: VulnerabilityFinding) -> FindingRead:
    return FindingRead(
        id=f.id,
        scan_id=f.scan_id,
        target_name=f.scan.target.name if f.scan and f.scan.target else None,
        endpoint=EndpointRef(
            id=f.endpoint.id, path=f.endpoint.path, http_method=f.endpoint.http_method
        )
        if f.endpoint
        else None,
        check_id=f.check_id,
        category=f.category,
        title=f.title,
        severity=f.severity,
        confidence=f.confidence,
        status=f.status,
        created_at=f.created_at,
    )


def list_findings(
    db: Session,
    user: User,
    *,
    limit: int,
    offset: int,
    scan_id: uuid.UUID | None = None,
    severities: list[Severity] | None = None,
    statuses: list[FindingStatus] | None = None,
    category: OwaspCategory | None = None,
    search: str | None = None,
) -> tuple[list[FindingRead], int]:
    if scan_id:
        _owned_scan(db, user, scan_id)
    conds: list[Any] = [Scan.user_id == user.id]
    if scan_id:
        conds.append(VulnerabilityFinding.scan_id == scan_id)
    if severities:
        conds.append(VulnerabilityFinding.severity.in_(severities))
    if statuses:
        conds.append(VulnerabilityFinding.status.in_(statuses))
    if category:
        conds.append(VulnerabilityFinding.category == category)
    if search:
        needle = search.strip()[:100].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        like = f"%{needle}%"
        conds.append(
            or_(
                VulnerabilityFinding.title.ilike(like, escape="\\"),
                VulnerabilityFinding.description.ilike(like, escape="\\"),
            )
        )
    base = (
        select(VulnerabilityFinding)
        .join(Scan, Scan.id == VulnerabilityFinding.scan_id)
        .where(*conds)
    )
    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    rows = (
        db.scalars(
            base.options(
                joinedload(VulnerabilityFinding.endpoint),
                joinedload(VulnerabilityFinding.scan).joinedload(Scan.target),
            )
            .order_by(
                _SEVERITY_ORDER.desc(),
                VulnerabilityFinding.created_at.desc(),
                VulnerabilityFinding.id,
            )
            .limit(limit)
            .offset(offset)
        )
        .unique()
        .all()
    )
    return [_finding_read(f) for f in rows], total


def get_finding(db: Session, user: User, finding_id: uuid.UUID) -> FindingDetail:
    f = db.scalar(
        select(VulnerabilityFinding)
        .join(Scan, Scan.id == VulnerabilityFinding.scan_id)
        .options(
            joinedload(VulnerabilityFinding.endpoint),
            joinedload(VulnerabilityFinding.scan).joinedload(Scan.target),
        )
        .where(VulnerabilityFinding.id == finding_id, Scan.user_id == user.id)
    )
    if f is None:
        raise NotFoundError("Finding not found")
    evidence = db.scalars(
        select(FindingEvidence)
        .where(FindingEvidence.finding_id == f.id)
        .order_by(FindingEvidence.observed_at, FindingEvidence.id)
    ).all()
    return FindingDetail(
        **_finding_read(f).model_dump(),
        description=f.description,
        remediation=f.remediation,
        evidence=[EvidenceRead.model_validate(e) for e in evidence],
        scan_status=f.scan.status,
        scan_created_at=f.scan.created_at,
    )


def dashboard(db: Session, user: User) -> DashboardSummary:
    by_status = dict(
        db.execute(
            select(Scan.status, func.count()).where(Scan.user_id == user.id).group_by(Scan.status)
        ).all()
    )
    sev = dict(
        db.execute(
            select(VulnerabilityFinding.severity, func.count())
            .join(Scan, Scan.id == VulnerabilityFinding.scan_id)
            .where(Scan.user_id == user.id)
            .group_by(VulnerabilityFinding.severity)
        ).all()
    )
    fstat = dict(
        db.execute(
            select(VulnerabilityFinding.status, func.count())
            .join(Scan, Scan.id == VulnerabilityFinding.scan_id)
            .where(Scan.user_id == user.id)
            .group_by(VulnerabilityFinding.status)
        ).all()
    )
    recent, _ = list_scans(db, user, limit=5, offset=0)
    findings, _ = list_findings(
        db, user, limit=8, offset=0, statuses=[FindingStatus.CONFIRMED, FindingStatus.POTENTIAL]
    )
    failures = db.scalars(
        select(Scan)
        .options(joinedload(Scan.target))
        .where(Scan.user_id == user.id, Scan.status == ScanStatus.FAILED)
        .order_by(Scan.created_at.desc())
        .limit(5)
    ).all()
    return DashboardSummary(
        total_scans=sum(by_status.values()),
        completed_scans=by_status.get(ScanStatus.COMPLETED, 0),
        running_scans=by_status.get(ScanStatus.RUNNING, 0) + by_status.get(ScanStatus.QUEUED, 0),
        failed_scans=by_status.get(ScanStatus.FAILED, 0),
        total_findings=sum(sev.values()),
        findings_by_severity={s.value: sev.get(s, 0) for s in Severity},
        findings_by_status={s.value: fstat.get(s, 0) for s in FindingStatus},
        recent_scans=to_scan_reads(db, recent),
        recent_findings=findings,
        recent_failures=[
            FailureInfo(
                scan_id=s.id,
                target_name=s.target.name,
                error_summary=s.error_summary,
                completed_at=s.completed_at,
            )
            for s in failures
        ],
    )


def auth_profiles_for(db: Session, scan: Scan) -> list[AuthProfile]:
    ids = [uuid.UUID(p["id"]) for p in scan.configuration.get("auth_profiles", [])]
    if not ids:
        return []
    return list(
        db.scalars(
            select(AuthProfile).where(
                AuthProfile.id.in_(ids), AuthProfile.target_id == scan.target_id
            )
        ).all()
    )


def target_of(db: Session, scan: Scan) -> ScanTarget | None:
    return db.get(ScanTarget, scan.target_id)
