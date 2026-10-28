"""Shared building blocks for injection-style checks.

New safe injection checks (for example reflected markers or template probes) can reuse
``injection_points`` and ``inject`` and add their own payloads and detectors. Only add a check
when there is a reliable, non-destructive way to validate it.
"""

from dataclasses import dataclass
from typing import Any

from app.scanner.base import ScanContext
from app.scanner.types import EndpointInfo


@dataclass(frozen=True)
class InjectionPoint:
    endpoint: EndpointInfo
    name: str
    location: str  # "query" | "path"
    param: dict[str, Any]


def injection_points(endpoint: EndpointInfo, limit: int) -> list[InjectionPoint]:
    points = [
        InjectionPoint(endpoint, p["name"], p["in"], p)
        for p in endpoint.parameters
        if p["in"] in {"query", "path"}
    ]
    return points[:limit]


def is_numeric(point: InjectionPoint) -> bool:
    return point.param.get("type") in {"integer", "number"}


def build_request(
    ctx: ScanContext, point: InjectionPoint, value: str | None
) -> tuple[str, dict[str, str]]:
    """Return (path, query) with *value* injected into the given point (None = baseline)."""
    from app.scanner.openapi import sample_value

    overrides: dict[str, str] = {}
    query = ctx.sample_query(point.endpoint)
    if point.location == "path" and value is not None:
        overrides[point.name] = value
    if point.location == "query":
        query[point.name] = value if value is not None else sample_value(point.param)
    return ctx.fill_path(point.endpoint, overrides), query
