"""Scan lifecycle, endpoints, findings and report export."""

import json
import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Response, status

from app.api.deps import CurrentUser, DbSession
from app.core.errors import ConflictError
from app.models.enums import FindingStatus, OwaspCategory, ScanStatus, Severity
from app.reports.builder import build_report
from app.reports.html import render_html
from app.schemas.common import Page
from app.schemas.scan import EndpointRead, FindingRead, ScanCreate, ScanRead
from app.services import scan_service
from app.services.scan_runner import ScanDispatcher, get_dispatcher

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
def create_scan(
    data: ScanCreate,
    user: CurrentUser,
    db: DbSession,
    dispatcher: Annotated[ScanDispatcher, Depends(get_dispatcher)],
) -> ScanRead:
    scan = scan_service.create_scan(db, user, data)
    dispatcher.dispatch(scan.id)
    db.expire_all()
    return scan_service.to_scan_reads(db, [scan_service.get_scan(db, user, scan.id)])[0]


@router.get("", response_model=Page[ScanRead])
def list_scans(
    user: CurrentUser,
    db: DbSession,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
    status_filter: Annotated[ScanStatus | None, Query(alias="status")] = None,
    target_id: uuid.UUID | None = None,
) -> Page[ScanRead]:
    items, total = scan_service.list_scans(
        db, user, limit=limit, offset=offset, status=status_filter, target_id=target_id
    )
    return Page[ScanRead](
        items=scan_service.to_scan_reads(db, items), total=total, limit=limit, offset=offset
    )


@router.get("/{scan_id}", response_model=ScanRead)
def get_scan(scan_id: uuid.UUID, user: CurrentUser, db: DbSession) -> ScanRead:
    return scan_service.to_scan_reads(db, [scan_service.get_scan(db, user, scan_id)])[0]


@router.post("/{scan_id}/cancel", response_model=ScanRead)
def cancel_scan(scan_id: uuid.UUID, user: CurrentUser, db: DbSession) -> ScanRead:
    return scan_service.to_scan_reads(db, [scan_service.cancel_scan(db, user, scan_id)])[0]


@router.get("/{scan_id}/endpoints", response_model=list[EndpointRead])
def list_endpoints(scan_id: uuid.UUID, user: CurrentUser, db: DbSession) -> list[EndpointRead]:
    return scan_service.list_endpoints(db, user, scan_id)


@router.get("/{scan_id}/findings", response_model=Page[FindingRead])
def list_scan_findings(
    scan_id: uuid.UUID,
    user: CurrentUser,
    db: DbSession,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
    severity: Annotated[list[Severity] | None, Query()] = None,
    finding_status: Annotated[list[FindingStatus] | None, Query(alias="status")] = None,
    category: OwaspCategory | None = None,
    search: Annotated[str | None, Query(max_length=100)] = None,
) -> Page[FindingRead]:
    items, total = scan_service.list_findings(
        db,
        user,
        limit=limit,
        offset=offset,
        scan_id=scan_id,
        severities=severity,
        statuses=finding_status,
        category=category,
        search=search,
    )
    return Page[FindingRead](items=items, total=total, limit=limit, offset=offset)


@router.get("/{scan_id}/report")
def download_report(
    scan_id: uuid.UUID,
    user: CurrentUser,
    db: DbSession,
    format: Annotated[Literal["json", "html"], Query()] = "json",  # noqa: A002
) -> Response:
    scan = scan_service.get_scan(db, user, scan_id)
    if scan.status not in scan_service.TERMINAL:
        raise ConflictError("The report is available once the scan has finished")
    report = build_report(db, scan)
    filename = f"scan-{scan.id}-report.{format}"
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'",
    }
    if format == "html":
        return Response(render_html(report), media_type="text/html; charset=utf-8", headers=headers)
    return Response(json.dumps(report, indent=2), media_type="application/json", headers=headers)
