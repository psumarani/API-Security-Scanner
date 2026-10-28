"""Cross-scan finding queries."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Query

from app.api.deps import CurrentUser, DbSession
from app.models.enums import FindingStatus, OwaspCategory, Severity
from app.schemas.common import Page
from app.schemas.scan import FindingDetail, FindingRead
from app.services import scan_service

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=Page[FindingRead])
def list_findings(
    user: CurrentUser,
    db: DbSession,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
    scan_id: uuid.UUID | None = None,
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


@router.get("/{finding_id}", response_model=FindingDetail)
def get_finding(finding_id: uuid.UUID, user: CurrentUser, db: DbSession) -> FindingDetail:
    return scan_service.get_finding(db, user, finding_id)
