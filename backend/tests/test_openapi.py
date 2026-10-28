import json

import pytest

from app.scanner.openapi import SpecError, parse_spec, sample_value

OAS3 = {
    "openapi": "3.0.3",
    "info": {"title": "Demo"},
    "servers": [{"url": "https://api.example.com/v2"}],
    "security": [{"bearerAuth": []}],
    "components": {
        "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}},
        "parameters": {
            "Limit": {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 10}}
        },
        "schemas": {"Loop": {"$ref": "#/components/schemas/Loop"}},
    },
    "paths": {
        "/health": {"get": {"security": [], "summary": "Health"}},
        "/users/{id}": {
            "parameters": [
                {
                    "name": "id",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string", "format": "uuid"},
                }
            ],
            "get": {"parameters": [{"$ref": "#/components/parameters/Limit"}], "deprecated": True},
            "post": {
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {"schema": {"$ref": "#/components/schemas/Loop"}}
                    },
                }
            },
        },
        "/loop": {"$ref": "#/paths/~1loop"},
    },
}

SWAGGER2 = {
    "swagger": "2.0",
    "basePath": "/api/v1",
    "securityDefinitions": {"key": {"type": "apiKey", "name": "X-Key", "in": "header"}},
    "paths": {
        "/items": {
            "get": {"security": [{"key": []}]},
            "put": {"parameters": [{"name": "body", "in": "body", "required": True}]},
        },
        "/open": {"get": {}},
    },
}


def test_openapi3_endpoints_security_and_params() -> None:
    result = parse_spec(json.dumps(OAS3))
    assert result.spec_version == "OpenAPI 3.0.3"
    by = {(e.method, e.path): e for e in result.endpoints}
    assert (
        ("GET", "/health") in by and ("GET", "/users/{id}") in by and ("POST", "/users/{id}") in by
    )
    assert by[("GET", "/health")].authentication_required is False  # explicit security: []
    assert by[("GET", "/users/{id}")].authentication_required is True  # inherited global
    names = {p["name"] for p in by[("GET", "/users/{id}")].parameters}
    assert names == {"id", "limit"}  # path-level + $ref'd operation-level
    assert by[("GET", "/users/{id}")].deprecated is True
    assert by[("POST", "/users/{id}")].request_body["content_types"] == ["application/json"]
    assert result.security_schemes == {"bearerAuth": "http"}
    assert result.base_path_hint == "/v2"


def test_swagger2_and_base_path() -> None:
    result = parse_spec(json.dumps(SWAGGER2))
    by = {(e.method, e.path): e for e in result.endpoints}
    assert result.spec_version == "Swagger 2.0" and result.base_path_hint == "/api/v1"
    assert by[("GET", "/items")].authentication_required is True
    assert by[("GET", "/open")].authentication_required is False  # schemes exist, none applied
    assert by[("PUT", "/items")].request_body is not None


def test_yaml_specs_are_supported() -> None:
    text = "openapi: 3.0.0\npaths:\n  /a:\n    get: {}\n"
    assert parse_spec(text).endpoints[0].path == "/a"
    # no schemes at all -> unknown
    assert parse_spec(text).endpoints[0].authentication_required is None


@pytest.mark.parametrize(
    "content",
    [
        "not a spec at all: [",
        "[]",
        '{"openapi":"2.0"}',
        '{"openapi":"3.0.0"}',
        '{"openapi":"3.0.0","paths":{}}',
        '{"openapi":"3.0.0","paths":{"/x":{}}}',
    ],
)
def test_invalid_specs_raise(content: str) -> None:
    with pytest.raises(SpecError):
        parse_spec(content)


def test_endpoint_limit_and_bad_paths_are_reported() -> None:
    doc = {
        "openapi": "3.0.0",
        "paths": {f"/p{i}": {"get": {}} for i in range(10)} | {"bad": {"get": {}}},
    }
    result = parse_spec(json.dumps(doc), max_endpoints=4)
    assert len(result.endpoints) == 4 and any("limit" in w for w in result.warnings)


def test_external_and_cyclic_refs_do_not_hang_or_fetch() -> None:
    doc = {
        "openapi": "3.0.0",
        "paths": {
            "/x": {
                "get": {
                    "parameters": [
                        {"$ref": "http://evil.example/param.json"},
                        {"$ref": "#/components/parameters/A"},
                    ]
                }
            }
        },
        "components": {"parameters": {"A": {"$ref": "#/components/parameters/A"}}},
    }
    result = parse_spec(json.dumps(doc))
    assert result.endpoints[0].parameters == []


def test_sample_values() -> None:
    assert sample_value({"type": "integer"}) == "1"
    assert sample_value({"type": "string", "format": "uuid"}).startswith("00000000")
    assert sample_value({"type": "string", "enum": ["a", "b"]}) == "a"
    assert sample_value({"type": "string", "example": "zed"}) == "zed"
    assert sample_value({"type": "boolean"}) == "true"
