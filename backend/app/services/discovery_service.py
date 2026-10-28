"""On-demand specification preview for a saved target (used by the 'new scan' screen)."""

import asyncio
import uuid

import httpx
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError, ScopeViolationError, ValidationFailed
from app.models.user import User
from app.scanner.http_client import HttpClientError, SafeHttpClient
from app.scanner.openapi import SpecError, discover
from app.scanner.scope_validator import Resolver, Scope, ScopeViolation, system_resolver
from app.schemas.scan import SpecPreview, SpecPreviewEndpoint
from app.services import target_service


async def _preview(scope: Scope, spec_url: str, resolver: Resolver, transport) -> SpecPreview:
    async with SafeHttpClient(
        scope,
        resolver=resolver,
        timeout=10,
        max_requests=3,
        max_response_bytes=2_000_000,
        transport=transport,
    ) as client:
        result = await discover(client, spec_url, max_endpoints=500)
    return SpecPreview(
        spec_version=result.spec_version,
        title=result.title,
        endpoint_count=len(result.endpoints),
        security_schemes=result.security_schemes,
        base_path_hint=result.base_path_hint,
        warnings=result.warnings,
        endpoints=[
            SpecPreviewEndpoint(
                method=e.method,
                path=e.path,
                authentication_required=e.authentication_required,
                deprecated=e.deprecated,
                parameters=len(e.parameters),
            )
            for e in result.endpoints
        ],
    )


def preview_spec(
    db: Session,
    user: User,
    target_id: uuid.UUID,
    resolver: Resolver = system_resolver,
    transport: httpx.AsyncBaseTransport | None = None,
) -> SpecPreview:
    target = target_service.get_target(db, user, target_id)
    if not target.api_spec_url:
        raise ValidationFailed("This target has no specification URL")
    scope = Scope.from_base_url(target.base_url, allow_local_lab=target.allow_local_lab)
    try:
        return asyncio.run(_preview(scope, target.api_spec_url, resolver, transport))
    except ScopeViolation as exc:
        raise ScopeViolationError(f"Specification rejected: {exc}") from exc
    except (SpecError, HttpClientError) as exc:
        raise ValidationFailed(f"Could not import the specification: {exc}") from exc


__all__ = ["NotFoundError", "preview_spec"]
