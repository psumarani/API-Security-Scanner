"""Builds the sanitized report document used by both the JSON and HTML exporters."""

import uuid
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.models.enums import FindingStatus, Severity
from app.models.scan import Endpoint, FindingEvidence, Scan, VulnerabilityFinding
from app.scanner import registry
from app.scanner.engine import SCANNER_VERSION
from app.scanner.severity import rank
from app.utils.redaction import redact_data, redact_text

REPORT_VERSION = "1.0"
MAX_TEXT = 1200

LIMITATIONS = [
    "Automated results are indicators, not proof of exploitability; 'potential' findings need manual verification.",
    "Only the modules listed under coverage were run; OWASP categories marked unsupported were not tested.",
    "Tests are bounded by the configured request budget, concurrency and time limit and are non-destructive.",
    "Only GET operations are exercised by default; state-changing operations were not tested unless enabled.",
    "Rate-limit testing uses a small burst and cannot establish that limits do not exist at higher volumes.",
    "Absence of findings does not imply absence of vulnerabilities.",
]


def _clean(text: str | None, limit: int = MAX_TEXT) -> str:
    out = redact_text(text or "")
    return out if len(out) <= limit else out[:limit] + "… [truncated]"


def build_report(db: Session, scan: Scan) -> dict[str, Any]:
    target = scan.target
    endpoints = db.scalars(
        select(Endpoint)
        .where(Endpoint.scan_id == scan.id)
        .order_by(Endpoint.path, Endpoint.http_method)
    ).all()
    findings = (
        db.scalars(
            select(VulnerabilityFinding)
            .options(joinedload(VulnerabilityFinding.endpoint))
            .where(VulnerabilityFinding.scan_id == scan.id)
        )
        .unique()
        .all()
    )
    findings = sorted(findings, key=lambda f: (-rank(f.severity), f.title, str(f.id)))
    evidence_rows = db.scalars(
        select(FindingEvidence)
        .where(FindingEvidence.finding_id.in_([f.id for f in findings] or [uuid.uuid4()]))
        .order_by(FindingEvidence.observed_at, FindingEvidence.id)
    ).all()
    evidence_by: dict[uuid.UUID, list[FindingEvidence]] = {}
    for ev in evidence_rows:
        evidence_by.setdefault(ev.finding_id, []).append(ev)

    per_endpoint = Counter(f.endpoint_id for f in findings if f.endpoint_id)
    cfg = redact_data(scan.configuration)
    progress = scan.progress or {}
    module_progress = progress.get("modules", {})
    coverage_modules = []
    for module_id in cfg.get("modules", []):
        meta = next((m for m in registry.list_modules() if m.id == module_id), None)
        info = module_progress.get(module_id, {})
        coverage_modules.append(
            {
                "id": module_id,
                "name": meta.name if meta else module_id,
                "status": info.get("status", "not run"),
                "findings": info.get("findings", 0),
                "requests": info.get("requests", 0),
                "notes": [_clean(n, 300) for n in info.get("notes", [])],
            }
        )
    inconclusive = [
        _clean(item, 300)
        for module_id in cfg.get("modules", [])
        for item in module_progress.get(module_id, {}).get("inconclusive", [])
    ]

    by_sev = Counter(f.severity for f in findings)
    by_status = Counter(f.status for f in findings)
    duration = (
        (scan.completed_at - scan.started_at).total_seconds()
        if scan.started_at and scan.completed_at
        else None
    )
    return {
        "report_version": REPORT_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "scanner": {
            "name": "API Security Scanner",
            "version": scan.scanner_version or SCANNER_VERSION,
        },
        "scan": {
            "id": str(scan.id),
            "status": scan.status.value,
            "created_at": scan.created_at.isoformat(),
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "duration_seconds": duration,
            "requests_made": scan.requests_made,
            "error_summary": _clean(scan.error_summary, 400) or None,
        },
        "target": {
            "id": str(target.id),
            "name": _clean(target.name, 200),
            "base_url": target.base_url,
            "api_spec_url": target.api_spec_url,
            "authorization_confirmed_at": target.authorization_confirmed_at.isoformat(),
            "authorization_note": _clean(target.authorization_note, 500) or None,
            "authorized_scope": cfg.get("scope", {}),
        },
        "configuration": {
            "modules": cfg.get("modules", []),
            "auth_profiles": [
                {k: p.get(k) for k in ("name", "role_label", "auth_type")}
                for p in cfg.get("auth_profiles", [])
            ],
            "settings": cfg.get("settings", {}),
        },
        "summary": {
            "total_findings": len(findings),
            "by_severity": {
                s.value: by_sev.get(s, 0) for s in sorted(Severity, key=rank, reverse=True)
            },
            "by_status": {s.value: by_status.get(s, 0) for s in FindingStatus},
            "endpoints_discovered": len(endpoints),
        },
        "coverage": {
            "modules": coverage_modules,
            "owasp": [c.__dict__ for c in registry.OWASP_COVERAGE],
        },
        "endpoints": [
            {
                "method": e.http_method,
                "path": e.path,
                "authentication_required": e.authentication_required,
                "findings": per_endpoint.get(e.id, 0),
            }
            for e in endpoints
        ],
        "findings": [
            {
                "id": str(f.id),
                "title": _clean(f.title, 200),
                "category": f.category.value,
                "check_id": f.check_id,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "status": f.status.value,
                "endpoint": {"method": f.endpoint.http_method, "path": f.endpoint.path}
                if f.endpoint
                else None,
                "description": _clean(f.description),
                "remediation": _clean(f.remediation),
                "evidence": [
                    {
                        "request": _clean(ev.request_summary, 700),
                        "response_status": ev.response_status,
                        "response": _clean(ev.response_summary, 700),
                        "observed_at": ev.observed_at.isoformat(),
                    }
                    for ev in evidence_by.get(f.id, [])
                ],
            }
            for f in findings
        ],
        "inconclusive_tests": inconclusive,
        "notes": [_clean(n, 300) for n in progress.get("notes", [])],
        "limitations": LIMITATIONS,
    }
