"""Executes queued scans in background threads and persists their progress and results."""

import asyncio
import logging
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Protocol

import httpx
from sqlalchemy import select, update
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.core.crypto import DecryptionError
from app.models.enums import AuthType, ScanStatus
from app.models.scan import Endpoint, FindingEvidence, Scan, VulnerabilityFinding
from app.models.target import AuthProfile, ScanTarget
from app.scanner.engine import ProfileSpec, ScanOutcome, run_scan
from app.scanner.scope_validator import Resolver, Scope, system_resolver
from app.scanner.settings import ScanSettings
from app.scanner.types import EndpointInfo, FindingDraft, ModuleResult
from app.services import target_service
from app.utils.redaction import redact_text

logger = logging.getLogger(__name__)


class ScanDispatcher(Protocol):
    def dispatch(self, scan_id: uuid.UUID) -> None: ...


def _finish(
    db: Session, scan_id: uuid.UUID, status: ScanStatus, error: str | None, requests: int
) -> None:
    """Set the terminal state unless the scan was already cancelled/finished elsewhere."""
    db.execute(
        update(Scan)
        .where(Scan.id == scan_id, Scan.status.in_([ScanStatus.RUNNING, ScanStatus.QUEUED]))
        .values(
            status=status,
            completed_at=datetime.now(UTC),
            error_summary=error,
            requests_made=requests,
        )
    )
    db.commit()


def execute_scan(
    factory: sessionmaker[Session],
    scan_id: uuid.UUID,
    *,
    resolver: Resolver = system_resolver,
    transport: httpx.AsyncBaseTransport | None = None,
) -> None:
    """Run one scan to completion. Never raises: any failure is recorded on the scan."""
    with factory() as db:
        try:
            _execute(db, scan_id, resolver, transport)
        except Exception as exc:  # noqa: BLE001
            logger.exception("scan %s crashed", scan_id)
            db.rollback()
            _finish(db, scan_id, ScanStatus.FAILED, f"Internal error: {type(exc).__name__}", 0)


def _execute(db: Session, scan_id: uuid.UUID, resolver: Resolver, transport) -> None:
    scan = db.get(Scan, scan_id)
    if scan is None or scan.status != ScanStatus.QUEUED:
        return  # cancelled before it started, or unknown
    target = db.get(ScanTarget, scan.target_id)
    cfg = scan.configuration
    settings = ScanSettings.model_validate(cfg["settings"])
    scan.status, scan.started_at = ScanStatus.RUNNING, datetime.now(UTC)
    db.commit()

    specs: list[ProfileSpec] = []
    wanted = {p["id"] for p in cfg.get("auth_profiles", [])}
    for profile in db.scalars(select(AuthProfile).where(AuthProfile.target_id == target.id)):
        if str(profile.id) not in wanted:
            continue
        try:
            creds = target_service.load_profile_credentials(profile)
        except DecryptionError:
            _finish(
                db,
                scan_id,
                ScanStatus.FAILED,
                "Stored credentials could not be decrypted (ENCRYPTION_KEY changed?)",
                0,
            )
            return
        specs.append(
            ProfileSpec(
                str(profile.id),
                profile.name,
                profile.role_label,
                AuthType(profile.auth_type),
                creds,
            )
        )

    scope = Scope.from_base_url(target.base_url, allow_local_lab=target.allow_local_lab)
    endpoint_ids: dict[tuple[str, str], uuid.UUID] = {}
    last_poll = [0.0]
    cancelled = [False]

    def is_cancelled() -> bool:
        now = time.monotonic()
        if cancelled[0]:
            return True
        if now - last_poll[0] >= 0.5:
            last_poll[0] = now
            db.expire(scan)
            status = db.scalar(select(Scan.status).where(Scan.id == scan_id))
            cancelled[0] = status == ScanStatus.CANCELLED
        return cancelled[0]

    def on_progress(progress: dict) -> None:
        db.execute(update(Scan).where(Scan.id == scan_id).values(progress=dict(progress)))
        db.commit()

    def on_endpoints(endpoints: list[EndpointInfo]) -> None:
        for ep in endpoints:
            row = Endpoint(
                scan_id=scan_id,
                path=ep.path,
                http_method=ep.method,
                parameters=ep.parameters,
                authentication_required=ep.authentication_required,
                discovery_source=ep.source,
            )
            db.add(row)
            db.flush()
            endpoint_ids[ep.key] = row.id
        db.commit()

    def on_module(result: ModuleResult, drafts: list[FindingDraft]) -> None:
        for d in drafts:
            endpoint_id = endpoint_ids.get(d.endpoint_key) if d.endpoint_key else None
            finding = VulnerabilityFinding(
                scan_id=scan_id,
                endpoint_id=endpoint_id,
                check_id=d.check_id,
                category=d.category,
                title=d.title[:200],
                description=redact_text(d.description),
                severity=d.severity,
                confidence=d.confidence,
                status=d.status,
                remediation=d.remediation,
                fingerprint=d.fingerprint,
            )
            db.add(finding)
            db.flush()
            for ev in d.evidence:
                db.add(
                    FindingEvidence(
                        finding_id=finding.id,
                        request_summary=redact_text(ev.request_summary),
                        response_status=ev.response_status,
                        response_summary=redact_text(ev.response_summary),
                    )
                )
        db.commit()

    outcome: ScanOutcome = asyncio.run(
        run_scan(
            scope=scope,
            settings=settings,
            module_ids=cfg["modules"],
            spec_url=cfg["scope"].get("spec_url"),
            profiles=specs,
            is_cancelled=is_cancelled,
            on_progress=on_progress,
            on_endpoints=on_endpoints,
            on_module=on_module,
            resolver=resolver,
            transport=transport,
        )
    )

    # Persist per-module outcomes (notes, inconclusive tests) for the report.
    progress = dict(db.scalar(select(Scan.progress).where(Scan.id == scan_id)) or {})
    progress["modules"] = {
        mid: {**progress.get("modules", {}).get(mid, {}), **res.as_dict()}
        for mid, res in outcome.module_results.items()
    } | {m: v for m, v in progress.get("modules", {}).items() if m not in outcome.module_results}
    progress["notes"] = outcome.notes
    progress["endpoint_count"] = outcome.endpoint_count
    db.execute(update(Scan).where(Scan.id == scan_id).values(progress=progress))
    db.commit()

    status = {
        "completed": ScanStatus.COMPLETED,
        "failed": ScanStatus.FAILED,
        "cancelled": ScanStatus.CANCELLED,
    }[outcome.status]
    if status is ScanStatus.CANCELLED:
        db.execute(
            update(Scan).where(Scan.id == scan_id).values(requests_made=outcome.requests_made)
        )
        db.commit()
    else:
        _finish(db, scan_id, status, outcome.error, outcome.requests_made)


def recover_interrupted_scans(factory: sessionmaker[Session]) -> int:
    """Mark scans left queued/running by a previous process as failed."""
    with factory() as db:
        result = db.execute(
            update(Scan)
            .where(Scan.status.in_([ScanStatus.QUEUED, ScanStatus.RUNNING]))
            .values(
                status=ScanStatus.FAILED,
                completed_at=datetime.now(UTC),
                error_summary="Interrupted by a server restart",
            )
        )
        db.commit()
        return result.rowcount or 0


class ThreadScanDispatcher:
    """Production dispatcher: bounded thread pool, one event loop per scan."""

    def __init__(
        self, factory: sessionmaker[Session] | None = None, resolver: Resolver = system_resolver
    ) -> None:
        self._factory = factory
        self._resolver = resolver
        self._pool: ThreadPoolExecutor | None = None
        self._lock = threading.Lock()

    def _get_pool(self) -> ThreadPoolExecutor:
        with self._lock:
            if self._pool is None:
                self._pool = ThreadPoolExecutor(
                    max_workers=get_settings().max_concurrent_scans, thread_name_prefix="scan"
                )
            return self._pool

    def dispatch(self, scan_id: uuid.UUID) -> None:
        from app.db.session import get_sessionmaker

        factory = self._factory or get_sessionmaker()
        self._get_pool().submit(execute_scan, factory, scan_id, resolver=self._resolver)


class InlineScanDispatcher:
    """Runs the scan synchronously (used by tests)."""

    def __init__(
        self, factory: sessionmaker[Session], resolver: Resolver = system_resolver, transport=None
    ) -> None:
        self._factory, self._resolver, self._transport = factory, resolver, transport

    def dispatch(self, scan_id: uuid.UUID) -> None:
        execute_scan(self._factory, scan_id, resolver=self._resolver, transport=self._transport)


_default_dispatcher = ThreadScanDispatcher()


def get_dispatcher() -> ScanDispatcher:
    """FastAPI dependency (overridable in tests)."""
    return _default_dispatcher
