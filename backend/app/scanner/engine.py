"""Scan orchestration. Independent of FastAPI and the database.

The engine discovers endpoints, prepares credentials, runs the selected modules one by one and
reports progress through callbacks, so the caller decides how to persist results.
"""

import asyncio
import functools
import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from app import __version__
from app.models.enums import AuthType
from app.scanner import registry
from app.scanner.base import ScanCancelled, ScanContext, ScanTimeLimit
from app.scanner.http_client import (
    ALL_METHODS,
    SAFE_METHODS,
    HttpClientError,
    RequestBudgetExceeded,
    SafeHttpClient,
)
from app.scanner.openapi import DiscoveryResult, SpecError, discover
from app.scanner.scope_validator import (
    Resolver,
    Scope,
    ScopeViolation,
    check_in_scope,
    system_resolver,
)
from app.scanner.settings import ScanSettings
from app.scanner.types import EndpointInfo, FindingDraft, ModuleResult, ProfileAuth

SCANNER_VERSION = __version__


def _match_endpoint(
    key: tuple[str, str], endpoints: list[EndpointInfo], prefix: str
) -> EndpointInfo | None:
    """Find the spec endpoint whose path template matches a concrete request path."""
    method, path = key
    if prefix and path.startswith(prefix):
        path = path[len(prefix) :]
    for ep in endpoints:
        if ep.method != method:
            continue
        pattern = "^" + re.sub(r"\\\{[^/]+?\\\}", "[^/]+", re.escape(ep.path)) + "$"
        if re.match(pattern, path):
            return ep
    return None


ProgressCallback = Callable[[dict[str, Any]], None]
EndpointsCallback = Callable[[list[EndpointInfo]], None]
ModuleCallback = Callable[[ModuleResult, list[FindingDraft]], None]


@dataclass
class ProfileSpec:
    """A target-API credential set as loaded from the database (secrets in memory only)."""

    id: str
    name: str
    role_label: str | None
    auth_type: AuthType
    credentials: dict[str, Any]


@dataclass
class ScanOutcome:
    status: str  # completed | failed | cancelled
    error: str | None = None
    requests_made: int = 0
    module_results: dict[str, ModuleResult] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    endpoint_count: int = 0


def _build_profile(spec: ProfileSpec) -> ProfileAuth:
    auth = ProfileAuth(spec.id, spec.name, spec.role_label, spec.auth_type)
    creds = spec.credentials
    if spec.auth_type is AuthType.BEARER:
        auth.headers["Authorization"] = f"Bearer {creds['token']}"
    elif spec.auth_type is AuthType.API_KEY:
        if creds.get("location", "header") == "query":
            auth.query[creds["name"]] = creds["value"]
        else:
            auth.headers[creds["name"]] = creds["value"]
    elif spec.auth_type is AuthType.TEST_ACCOUNT:
        auth.usable = False  # resolved by login below
    else:
        auth.usable = False
        auth.note = "profile has no credentials"
    return auth


def _extract(data: Any, dotted: str) -> str | None:
    for part in dotted.split("."):
        if not isinstance(data, dict) or part not in data:
            return None
        data = data[part]
    return data if isinstance(data, str) and data else None


async def _login_profiles(
    scope: Scope,
    resolver: Resolver,
    settings: ScanSettings,
    specs: list[ProfileSpec],
    profiles: dict[str, ProfileAuth],
    transport: httpx.AsyncBaseTransport | None,
    prefix: str,
) -> int:
    """Obtain bearer tokens for test-account profiles that define a login path."""
    pending = [s for s in specs if s.auth_type is AuthType.TEST_ACCOUNT]
    if not pending:
        return 0
    used = 0
    async with SafeHttpClient(
        scope,
        resolver=resolver,
        timeout=settings.timeout_seconds,
        max_requests=len(pending) * 2,
        allowed_methods=SAFE_METHODS | {"POST"},
        verify_tls=settings.verify_tls,
        transport=transport,
    ) as login_client:
        for spec in pending:
            auth = profiles[spec.id]
            creds = spec.credentials
            login_path = creds.get("login_path")
            if not login_path:
                auth.note = "test account has no login_path configured; skipped"
                continue
            token = None
            try:
                resp = await login_client.request(
                    "POST",
                    f"{prefix}{login_path}",
                    json={
                        creds.get("username_field", "username"): creds["username"],
                        creds.get("password_field", "password"): creds["password"],
                    },
                )
                used += 1
                if 200 <= resp.status_code < 300:
                    token = _extract(
                        json.loads(resp.text()), creds.get("token_field", "access_token")
                    )
            except (HttpClientError, ScopeViolation, ValueError):
                token = None
            if token:
                auth.headers["Authorization"] = f"Bearer {token}"
                auth.usable = True
            else:
                auth.note = "login failed or token not found in the response"
    return used


async def run_scan(
    *,
    scope: Scope,
    settings: ScanSettings,
    module_ids: list[str],
    spec_url: str | None,
    profiles: list[ProfileSpec],
    is_cancelled: Callable[[], bool],
    on_progress: ProgressCallback | None = None,
    on_endpoints: EndpointsCallback | None = None,
    on_module: ModuleCallback | None = None,
    resolver: Resolver = system_resolver,
    transport: httpx.AsyncBaseTransport | None = None,
) -> ScanOutcome:
    outcome = ScanOutcome(status="completed")
    deadline = time.monotonic() + settings.max_duration_seconds
    progress: dict[str, Any] = {
        "stage": "starting",
        "current_module": None,
        "percent": 0,
        "modules": {m: {"status": "pending", "findings": 0, "requests": 0} for m in module_ids},
    }

    def report(**changes: Any) -> None:
        progress.update(changes)
        if on_progress:
            on_progress(progress)

    try:
        # Scope pre-flight: refuse to start if the target no longer resolves to allowed addresses.
        await asyncio.to_thread(
            functools.partial(check_in_scope, scope.base_url, scope, resolver=resolver)
        )
    except ScopeViolation as exc:
        return ScanOutcome(status="failed", error=f"Target is out of scope: {exc}")

    seen: set[str] = set()
    async with SafeHttpClient(
        scope,
        resolver=resolver,
        timeout=settings.timeout_seconds,
        max_requests=settings.max_requests,
        max_concurrency=settings.max_concurrency,
        max_response_bytes=2_000_000,
        allowed_methods=ALL_METHODS if settings.allow_unsafe_methods else SAFE_METHODS,
        verify_tls=settings.verify_tls,
        transport=transport,
    ) as client:
        ctx = ScanContext(
            client=client,
            endpoints=[],
            profiles={},
            settings=settings,
            deadline=deadline,
            is_cancelled=is_cancelled,
        )
        try:
            report(stage="discovery", percent=2)
            discovery: DiscoveryResult | None = None
            if spec_url:
                try:
                    ctx.check_running()
                    discovery = await discover(
                        client, spec_url, max_endpoints=settings.max_endpoints
                    )
                except (SpecError, HttpClientError, ScopeViolation) as exc:
                    outcome.notes.append(f"Discovery failed: {exc}")
            if discovery:
                ctx.endpoints = discovery.endpoints
                outcome.notes += discovery.warnings
                if not scope.base_path and discovery.base_path_hint:
                    ctx.path_prefix = discovery.base_path_hint
                    outcome.notes.append(
                        f"Specification base path '{discovery.base_path_hint}' was prepended to endpoint paths."
                    )
            else:
                outcome.notes.append(
                    "No endpoints discovered; modules that need endpoints will do little."
                )
            outcome.endpoint_count = len(ctx.endpoints)
            if on_endpoints:
                on_endpoints(ctx.endpoints)

            for spec in profiles:
                ctx.profiles[spec.id] = _build_profile(spec)
            await _login_profiles(
                scope, resolver, settings, profiles, ctx.profiles, transport, ctx.path_prefix
            )

            total = len(module_ids)
            for index, module_id in enumerate(module_ids):
                ctx.check_running()
                module = registry.get_module(module_id)
                report(
                    stage="modules", current_module=module_id, percent=5 + int(90 * index / total)
                )
                progress["modules"][module_id]["status"] = "running"
                before = client.requests_made
                ctx.inconclusive, ctx.notes = [], []
                result = ModuleResult(module_id, "completed")
                drafts: list[FindingDraft] = []
                try:
                    drafts = await module.run(ctx)
                except (ScanCancelled, ScanTimeLimit):
                    raise
                except RequestBudgetExceeded:
                    result.notes.append("Request budget exhausted; results are partial.")
                    result.status = "completed"
                except ScopeViolation as exc:
                    result.status, result.notes = "failed", [f"Scope violation: {exc}"]
                except Exception as exc:  # noqa: BLE001 - a module bug must not kill the scan
                    result.status, result.notes = "failed", [f"Module error: {type(exc).__name__}"]
                known = {e.key for e in ctx.endpoints}
                for d in drafts:
                    if d.endpoint_key and d.endpoint_key not in known:
                        match = _match_endpoint(d.endpoint_key, ctx.endpoints, ctx.path_prefix)
                        if match:
                            d.discriminator = f"{d.discriminator}|{d.endpoint_key[1]}"
                            d.endpoint_key = match.key
                fresh = [d for d in drafts if d.fingerprint not in seen]
                seen.update(d.fingerprint for d in fresh)
                result.findings = len(fresh)
                result.requests = client.requests_made - before
                result.notes += ctx.notes
                result.inconclusive += ctx.inconclusive
                outcome.module_results[module_id] = result
                progress["modules"][module_id] = {
                    "status": result.status,
                    "findings": result.findings,
                    "requests": result.requests,
                }
                if on_module:
                    on_module(result, fresh)
                report(percent=5 + int(90 * (index + 1) / total))
            if outcome.module_results and all(
                r.status == "failed" for r in outcome.module_results.values()
            ):
                outcome.status, outcome.error = "failed", "All selected modules failed."
        except ScanCancelled:
            outcome.status = "cancelled"
            for st in progress["modules"].values():
                if st["status"] in {"pending", "running"}:
                    st["status"] = "cancelled"
        except ScanTimeLimit:
            outcome.status = "failed"
            outcome.error = f"Time limit of {settings.max_duration_seconds} seconds reached; results are partial."
        outcome.requests_made = client.requests_made
    report(
        stage="done",
        current_module=None,
        percent=100 if outcome.status == "completed" else progress["percent"],
    )
    return outcome


__all__ = ["SCANNER_VERSION", "ProfileSpec", "ScanOutcome", "run_scan"]
