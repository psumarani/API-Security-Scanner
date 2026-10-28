"""Helpers that turn requests/responses into sanitized, size-limited evidence."""

import difflib
import hashlib
import json
from typing import Any
from urllib.parse import urlencode

from app.scanner.http_client import ScopedResponse
from app.scanner.types import EvidenceDraft, ProfileAuth
from app.utils.redaction import redact_headers, redact_text, summarize_body


def body_digest(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()[:12]


def request_summary(
    method: str,
    path: str,
    *,
    profile: ProfileAuth | None = None,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    note: str | None = None,
) -> str:
    target = path
    if params:
        target += ("&" if "?" in path else "?") + urlencode(
            {k: str(v) for k, v in params.items()}, safe="'\"=()- "
        )
    parts = [f"{method.upper()} {redact_text(target)}"]
    if profile is not None:
        parts.append(f"as profile '{profile.label}'")
    elif headers is None or "Authorization" not in headers:
        parts.append("without credentials")
    if headers:
        parts.append("headers: " + json.dumps(redact_headers(headers), sort_keys=True))
    if note:
        parts.append(note)
    return "; ".join(parts)[:600]


def response_summary(
    resp: ScopedResponse, *, include_body: bool = True, interesting: tuple[str, ...] = ()
) -> str:
    parts = [f"HTTP {resp.status_code}", f"{len(resp.body)} bytes"]
    ctype = resp.content_type.split(";")[0].strip()
    if ctype:
        parts.append(ctype)
    for name in interesting:
        if name in resp.headers:
            parts.append(f"{name}: {redact_text(resp.headers[name])[:120]}")
    if include_body and resp.body:
        parts.append("body: " + summarize_body(resp.body[:2000], resp.content_type, max_chars=240))
    elif resp.body:
        parts.append(f"body omitted ({body_digest(resp.body)})")
    return "; ".join(parts)


def make_evidence(
    method: str,
    path: str,
    resp: ScopedResponse | None,
    *,
    profile: ProfileAuth | None = None,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    note: str | None = None,
    include_body: bool = True,
    interesting: tuple[str, ...] = (),
) -> EvidenceDraft:
    return EvidenceDraft(
        request_summary=request_summary(
            method, path, profile=profile, params=params, headers=headers, note=note
        ),
        response_status=resp.status_code if resp else None,
        response_summary=(
            response_summary(resp, include_body=include_body, interesting=interesting)
            if resp
            else "no response"
        ),
    )


def bodies_similar(a: bytes, b: bytes, threshold: float = 0.9) -> bool:
    """True if two response bodies are equal (JSON-normalized) or very close in content."""
    if a == b:
        return True
    try:
        if json.dumps(json.loads(a), sort_keys=True) == json.dumps(json.loads(b), sort_keys=True):
            return True
    except ValueError:
        pass
    if not a and not b:
        return True
    if not a or not b:
        return False
    return difflib.SequenceMatcher(None, a[:3000], b[:3000], autojunk=False).ratio() >= threshold
