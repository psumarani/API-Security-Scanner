"""Target management endpoints."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import CurrentUser, DbSession, get_resolver
from app.scanner.scope_validator import Resolver
from app.schemas.common import Page
from app.schemas.scan import SpecPreview
from app.schemas.target import AuthProfileCreate, AuthProfileRead, TargetCreate, TargetRead
from app.services import discovery_service, target_service

router = APIRouter(prefix="/targets", tags=["targets"])


@router.post("", response_model=TargetRead, status_code=status.HTTP_201_CREATED)
def create_target(
    data: TargetCreate,
    user: CurrentUser,
    db: DbSession,
    resolver: Annotated[Resolver, Depends(get_resolver)],
) -> TargetRead:
    return TargetRead.model_validate(target_service.create_target(db, user, data, resolver))


@router.get("", response_model=Page[TargetRead])
def list_targets(
    user: CurrentUser,
    db: DbSession,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[TargetRead]:
    items, total = target_service.list_targets(db, user, limit, offset)
    return Page[TargetRead](
        items=[TargetRead.model_validate(t) for t in items], total=total, limit=limit, offset=offset
    )


@router.get("/{target_id}", response_model=TargetRead)
def get_target(target_id: uuid.UUID, user: CurrentUser, db: DbSession) -> TargetRead:
    return TargetRead.model_validate(target_service.get_target(db, user, target_id))


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_target(target_id: uuid.UUID, user: CurrentUser, db: DbSession) -> None:
    target_service.delete_target(db, user, target_id)


@router.post(
    "/{target_id}/auth-profiles",
    response_model=AuthProfileRead,
    status_code=status.HTTP_201_CREATED,
)
def create_auth_profile(
    target_id: uuid.UUID, data: AuthProfileCreate, user: CurrentUser, db: DbSession
) -> AuthProfileRead:
    profile = target_service.create_auth_profile(db, user, target_id, data)
    return AuthProfileRead.model_validate(profile)


@router.get("/{target_id}/auth-profiles", response_model=list[AuthProfileRead])
def list_auth_profiles(
    target_id: uuid.UUID, user: CurrentUser, db: DbSession
) -> list[AuthProfileRead]:
    return [
        AuthProfileRead.model_validate(p)
        for p in target_service.list_auth_profiles(db, user, target_id)
    ]


@router.delete("/{target_id}/auth-profiles/{profile_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_auth_profile(
    target_id: uuid.UUID, profile_id: uuid.UUID, user: CurrentUser, db: DbSession
) -> None:
    target_service.delete_auth_profile(db, user, target_id, profile_id)


@router.post("/{target_id}/spec-preview", response_model=SpecPreview)
def preview_spec(
    target_id: uuid.UUID,
    user: CurrentUser,
    db: DbSession,
    resolver: Annotated[Resolver, Depends(get_resolver)],
) -> SpecPreview:
    """Fetch and parse the target's OpenAPI/Swagger specification (no scan is started)."""
    return discovery_service.preview_spec(db, user, target_id, resolver)
