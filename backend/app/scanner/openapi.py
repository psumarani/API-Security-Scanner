"""OpenAPI 3.x / Swagger 2.0 discovery.

Parsing is defensive: only local ``$ref`` pointers are resolved (depth- and cycle-limited), the
document size is bounded by the HTTP client, and nothing in the specification is trusted to be
safe to scan - scope enforcement happens later, in the HTTP client.
"""

import json
from dataclasses import dataclass, field
from typing import Any

import yaml

from app.models.enums import DiscoverySource
from app.scanner.http_client import SafeHttpClient
from app.scanner.types import EndpointInfo

HTTP_METHODS = ("get", "put", "post", "delete", "patch", "head", "options")
MAX_REF_DEPTH = 20


class SpecError(Exception):
    """The specification could not be fetched or parsed."""


@dataclass
class DiscoveryResult:
    spec_version: str
    title: str | None
    endpoints: list[EndpointInfo]
    security_schemes: dict[str, str] = field(default_factory=dict)
    base_path_hint: str = ""
    warnings: list[str] = field(default_factory=list)


def _resolve(doc: dict[str, Any], node: Any, depth: int = 0, seen: frozenset[str] = frozenset()):
    """Resolve a local $ref chain (returns the referenced object, or {} if unresolvable)."""
    while isinstance(node, dict) and "$ref" in node:
        ref = node["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/") or depth > MAX_REF_DEPTH:
            return {}
        if ref in seen:
            return {}
        seen = seen | {ref}
        depth += 1
        target: Any = doc
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(target, dict) or part not in target:
                return {}
            target = target[part]
        node = target
    return node


def _schema_info(doc: dict[str, Any], schema: Any) -> dict[str, Any]:
    schema = _resolve(doc, schema)
    if not isinstance(schema, dict):
        return {}
    info: dict[str, Any] = {"type": schema.get("type"), "format": schema.get("format")}
    if "enum" in schema and isinstance(schema["enum"], list) and schema["enum"]:
        info["enum"] = schema["enum"][:5]
    for key in ("example", "default"):
        if key in schema and isinstance(schema[key], str | int | float | bool):
            info[key] = schema[key]
    return info


def _normalize_param(doc: dict[str, Any], raw: Any) -> dict[str, Any] | None:
    raw = _resolve(doc, raw)
    if not isinstance(raw, dict) or "name" not in raw or "in" not in raw:
        return None
    schema = raw.get("schema") if "schema" in raw else raw  # Swagger 2.0 inlines the type
    info = _schema_info(doc, schema)
    param: dict[str, Any] = {
        "name": str(raw["name"])[:128],
        "in": str(raw["in"]),
        "required": bool(raw.get("required", raw["in"] == "path")),
        "type": info.get("type"),
        "format": info.get("format"),
    }
    for key in ("enum", "example", "default"):
        if key in info:
            param[key] = info[key]
    if "example" in raw and isinstance(raw["example"], str | int | float | bool):
        param["example"] = raw["example"]
    return param


def _security_names(requirements: Any) -> list[str]:
    names: list[str] = []
    if isinstance(requirements, list):
        for req in requirements:
            if isinstance(req, dict):
                names.extend(str(k) for k in req)
    return names


def parse_spec(content: bytes | str, *, max_endpoints: int = 500) -> DiscoveryResult:
    text = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else content
    try:
        doc = json.loads(text)
    except ValueError:
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise SpecError("specification is neither valid JSON nor YAML") from exc
    if not isinstance(doc, dict):
        raise SpecError("specification root must be an object")

    if str(doc.get("openapi", "")).startswith("3."):
        version, schemes_raw = (
            f"OpenAPI {doc['openapi']}",
            (doc.get("components") or {}).get("securitySchemes"),
        )
    elif str(doc.get("swagger", "")) == "2.0":
        version, schemes_raw = "Swagger 2.0", doc.get("securityDefinitions")
    else:
        raise SpecError("unsupported specification: expected OpenAPI 3.x or Swagger 2.0")

    paths = doc.get("paths")
    if not isinstance(paths, dict) or not paths:
        raise SpecError("specification declares no paths")

    schemes: dict[str, str] = {}
    if isinstance(schemes_raw, dict):
        for name, scheme in schemes_raw.items():
            scheme = _resolve(doc, scheme)
            if isinstance(scheme, dict):
                schemes[str(name)] = str(scheme.get("type", "unknown"))

    global_security = doc.get("security")
    warnings: list[str] = []
    endpoints: list[EndpointInfo] = []

    base_hint = ""
    if version == "Swagger 2.0":
        base_hint = str(doc.get("basePath", "") or "").rstrip("/")
    else:
        servers = doc.get("servers")
        if isinstance(servers, list) and servers and isinstance(servers[0], dict):
            url = str(servers[0].get("url", ""))
            if url.startswith("/"):
                base_hint = url.rstrip("/")
            elif "://" in url:
                base_hint = "/" + url.split("://", 1)[1].partition("/")[2].strip("/")
                base_hint = "" if base_hint == "/" else base_hint

    for raw_path, path_item in paths.items():
        path_item = _resolve(doc, path_item)
        if not isinstance(path_item, dict) or not isinstance(raw_path, str):
            continue
        if not raw_path.startswith("/"):
            warnings.append(f"ignored path {raw_path[:60]!r}: must start with '/'")
            continue
        path_params = [
            p for p in (_normalize_param(doc, x) for x in path_item.get("parameters", [])) if p
        ]
        for method in HTTP_METHODS:
            op = _resolve(doc, path_item.get(method))
            if not isinstance(op, dict):
                continue
            if len(endpoints) >= max_endpoints:
                warnings.append(f"endpoint limit of {max_endpoints} reached; remaining ignored")
                return DiscoveryResult(
                    version,
                    (doc.get("info") or {}).get("title"),
                    endpoints,
                    schemes,
                    base_hint,
                    warnings,
                )  # noqa: E501
            merged: dict[tuple[str, str], dict[str, Any]] = {
                (p["name"], p["in"]): p for p in path_params
            }
            for x in op.get("parameters", []):
                p = _normalize_param(doc, x)
                if p:
                    merged[(p["name"], p["in"])] = p
            params = [p for p in merged.values() if p["in"] != "body"]

            body: dict[str, Any] | None = None
            rb = _resolve(doc, op.get("requestBody"))
            if isinstance(rb, dict) and rb:
                content_types = list((_resolve(doc, rb.get("content")) or {}).keys())[:5]
                body = {"required": bool(rb.get("required", False)), "content_types": content_types}
            elif any(p["in"] == "body" for p in merged.values()):
                body = {"required": True, "content_types": list(doc.get("consumes", []))[:5]}

            if "security" in op:
                names = _security_names(op["security"])
                auth_required: bool | None = bool(names)
            elif global_security is not None:
                names = _security_names(global_security)
                auth_required = bool(names)
            else:
                auth_required = False if schemes else None

            endpoints.append(
                EndpointInfo(
                    path=raw_path,
                    method=method.upper(),
                    parameters=params,
                    request_body=body,
                    authentication_required=auth_required,
                    deprecated=bool(op.get("deprecated", False)),
                    summary=(str(op["summary"])[:200] if op.get("summary") else None),
                    source=DiscoverySource.OPENAPI,
                )
            )

    if not endpoints:
        raise SpecError("specification contains no operations")
    return DiscoveryResult(
        version, (doc.get("info") or {}).get("title"), endpoints, schemes, base_hint, warnings
    )


async def discover(
    client: SafeHttpClient, spec_url: str, *, max_endpoints: int = 500
) -> DiscoveryResult:
    """Fetch the specification through the scope-enforcing client and parse it."""
    resp = await client.get(spec_url, headers={"Accept": "application/json, application/yaml, */*"})
    if not 200 <= resp.status_code < 300:
        raise SpecError(f"specification URL returned HTTP {resp.status_code}")
    if resp.truncated:
        raise SpecError("specification is larger than the allowed size")
    return parse_spec(resp.body, max_endpoints=max_endpoints)


_SAMPLE_UUID = "00000000-0000-4000-8000-000000000001"


def sample_value(param: dict[str, Any]) -> str:
    """A plausible harmless value for a parameter (used for baseline requests)."""
    for key in ("example", "default"):
        if key in param:
            return str(param[key])
    if param.get("enum"):
        return str(param["enum"][0])
    ptype, fmt = param.get("type"), param.get("format")
    if ptype in {"integer", "number"}:
        return "1"
    if ptype == "boolean":
        return "true"
    if fmt == "uuid":
        return _SAMPLE_UUID
    if fmt == "date":
        return "2024-01-01"
    if fmt == "date-time":
        return "2024-01-01T00:00:00Z"
    return "sample"
