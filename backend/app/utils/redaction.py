"""Redaction of secrets from anything that may be logged, stored as evidence or reported."""

import json
import re
from collections.abc import Mapping
from typing import Any

REDACTED = "[REDACTED]"

SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "x-access-token",
        "x-csrf-token",
    }
)

_SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "api-key",
    "authorization",
    "credential",
    "private_key",
    "session",
    "cookie",
)

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
_BEARER_RE = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_KV_RE = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|access[_-]?token|refresh[_-]?token)"
    r"(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s&,;]+)"
)


def is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return lowered in SENSITIVE_HEADERS or any(part in lowered for part in _SENSITIVE_KEY_PARTS)


def redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {k: (REDACTED if k.lower() in SENSITIVE_HEADERS else v) for k, v in headers.items()}


def redact_text(text: str) -> str:
    """Mask JWTs, bearer/basic credentials and key=value style secrets inside free text."""
    text = _JWT_RE.sub(REDACTED, text)
    text = _BEARER_RE.sub(lambda m: f"{m.group(1)} {REDACTED}", text)
    return _KV_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)


def redact_data(value: Any) -> Any:
    """Recursively mask values under sensitive keys and secret-looking strings."""
    if isinstance(value, Mapping):
        return {
            k: (REDACTED if isinstance(k, str) and is_sensitive_key(k) else redact_data(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact_data(v) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def summarize_body(body: bytes | str, content_type: str = "", max_chars: int = 500) -> str:
    """Sanitized, truncated body summary suitable for evidence storage."""
    text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
    if "json" in content_type.lower():
        try:
            text = json.dumps(redact_data(json.loads(text)), ensure_ascii=False)
        except ValueError:
            text = redact_text(text)
    else:
        text = redact_text(text)
    if len(text) > max_chars:
        text = text[:max_chars] + f"... [truncated, {len(text) - max_chars} more characters]"
    return text
