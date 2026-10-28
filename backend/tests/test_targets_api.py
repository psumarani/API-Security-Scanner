import uuid

import pytest
from sqlalchemy import func, select

from app.core.crypto import decrypt_json
from app.models.enums import Confidence, DiscoverySource, FindingStatus, OwaspCategory, Severity
from app.models.scan import Endpoint, FindingEvidence, Scan, VulnerabilityFinding
from app.models.target import AuthProfile, ScanTarget

TARGETS = "/api/v1/targets"


def payload(**overrides):
    body = {
        "name": "Lab API",
        "base_url": "https://api.example.com/v1/",
        "api_spec_url": "https://api.example.com/openapi.json",
        "authorization_confirmed": True,
        "authorization_note": "Own staging environment",
    }
    body.update(overrides)
    return body


def test_create_get_list_delete_target(client, auth_headers) -> None:
    r = client.post(TARGETS, json=payload(), headers=auth_headers)
    assert r.status_code == 201, r.text
    t = r.json()
    assert t["base_url"] == "https://api.example.com/v1"  # canonical, no trailing slash
    assert t["authorization_confirmed_at"] and t["allow_local_lab"] is False

    assert client.get(f"{TARGETS}/{t['id']}", headers=auth_headers).json()["name"] == "Lab API"
    page = client.get(TARGETS, headers=auth_headers).json()
    assert page["total"] == 1 and page["items"][0]["id"] == t["id"]

    assert client.delete(f"{TARGETS}/{t['id']}", headers=auth_headers).status_code == 204
    assert client.get(f"{TARGETS}/{t['id']}", headers=auth_headers).status_code == 404


def test_all_target_routes_require_authentication(client) -> None:
    some_id = uuid.uuid4()
    calls = [
        client.post(TARGETS, json=payload()),
        client.get(TARGETS),
        client.get(f"{TARGETS}/{some_id}"),
        client.delete(f"{TARGETS}/{some_id}"),
        client.post(f"{TARGETS}/{some_id}/auth-profiles", json={}),
        client.get(f"{TARGETS}/{some_id}/auth-profiles"),
        client.delete(f"{TARGETS}/{some_id}/auth-profiles/{some_id}"),
    ]
    assert [c.status_code for c in calls] == [401] * len(calls)


def test_explicit_authorization_is_required(client, auth_headers) -> None:
    r = client.post(TARGETS, json=payload(authorization_confirmed=False), headers=auth_headers)
    assert r.status_code == 422
    body = payload()
    del body["authorization_confirmed"]
    assert client.post(TARGETS, json=body, headers=auth_headers).status_code == 422


@pytest.mark.parametrize(
    "base_url",
    [
        "http://internal.example.com",  # resolves to 10.0.0.5
        "http://meta.example.com",  # resolves to 169.254.169.254
        "http://mixed.example.com",  # one public + one private address
        "http://127.0.0.1:8000",
        "http://localhost:8000/x",  # not in fake DNS -> unresolved
        "http://169.254.169.254/latest",
        "http://[::1]/",
        "http://2130706433/",
        "ftp://api.example.com",
        "https://user:pw@api.example.com",
        "https://api.example.com/?x=1",
        "not a url",
    ],
)
def test_prohibited_or_invalid_targets_are_rejected(client, auth_headers, base_url) -> None:
    r = client.post(
        TARGETS, json=payload(base_url=base_url, api_spec_url=None), headers=auth_headers
    )
    assert r.status_code == 422, r.text
    assert r.json()["error"]["code"] in {"scope_violation", "validation_error"}


def test_spec_url_must_share_the_origin(client, auth_headers) -> None:
    r = client.post(
        TARGETS,
        json=payload(api_spec_url="https://other.example.com/openapi.json"),
        headers=auth_headers,
    )
    assert r.status_code == 422 and r.json()["error"]["code"] == "scope_violation"


def test_local_lab_needs_server_switch_and_target_opt_in(client, auth_headers, monkeypatch) -> None:
    lab = payload(base_url="http://lab.example.test:8888", api_spec_url=None)
    # target not opted in -> blocked
    assert client.post(TARGETS, json=lab, headers=auth_headers).status_code == 422
    # opted in, but the server-wide switch is off -> blocked
    r = client.post(TARGETS, json={**lab, "allow_local_lab": True}, headers=auth_headers)
    assert r.status_code == 422 and "disabled on this server" in r.json()["error"]["message"]


def test_local_lab_when_enabled_is_narrow(client, auth_headers, enable_local_lab) -> None:
    lab = payload(base_url="http://lab.example.test:8888", api_spec_url=None, allow_local_lab=True)
    r = client.post(TARGETS, json=lab, headers=auth_headers)
    assert r.status_code == 201 and r.json()["allow_local_lab"] is True
    # still blocked: metadata/link-local, and private hosts without the flag
    assert (
        client.post(
            TARGETS,
            json=payload(
                name="m",
                base_url="http://meta.example.com",
                api_spec_url=None,
                allow_local_lab=True,
            ),
            headers=auth_headers,
        ).status_code
        == 422
    )
    assert (
        client.post(
            TARGETS,
            json=payload(name="p", base_url="http://internal.example.com", api_spec_url=None),
            headers=auth_headers,
        ).status_code
        == 422
    )


def test_duplicate_names_conflict_per_user(client, make_user) -> None:
    a, b = make_user("alice"), make_user("bob")
    assert client.post(TARGETS, json=payload(), headers=a).status_code == 201
    assert client.post(TARGETS, json=payload(), headers=a).status_code == 409
    assert client.post(TARGETS, json=payload(), headers=b).status_code == 201  # different owner


def test_pagination(client, auth_headers) -> None:
    for i in range(5):
        assert (
            client.post(TARGETS, json=payload(name=f"t{i}"), headers=auth_headers).status_code
            == 201
        )
    page = client.get(TARGETS, params={"limit": 2, "offset": 2}, headers=auth_headers).json()
    assert (page["total"], len(page["items"]), page["limit"], page["offset"]) == (5, 2, 2, 2)
    assert client.get(TARGETS, params={"limit": 0}, headers=auth_headers).status_code == 422
    assert client.get(TARGETS, params={"limit": 101}, headers=auth_headers).status_code == 422


def test_users_cannot_see_or_touch_each_others_targets(client, make_user) -> None:
    alice, bob = make_user("alice"), make_user("bob")
    t = client.post(TARGETS, json=payload(), headers=alice).json()
    pid = client.post(
        f"{TARGETS}/{t['id']}/auth-profiles",
        json={"name": "u1", "config": {"type": "bearer", "token": "secret-token-value"}},
        headers=alice,
    ).json()["id"]

    assert client.get(f"{TARGETS}/{t['id']}", headers=bob).status_code == 404
    assert client.delete(f"{TARGETS}/{t['id']}", headers=bob).status_code == 404
    assert client.get(TARGETS, headers=bob).json()["total"] == 0
    assert client.get(f"{TARGETS}/{t['id']}/auth-profiles", headers=bob).status_code == 404
    assert (
        client.post(
            f"{TARGETS}/{t['id']}/auth-profiles",
            json={"name": "evil", "config": {"type": "none"}},
            headers=bob,
        ).status_code
        == 404
    )
    assert client.delete(f"{TARGETS}/{t['id']}/auth-profiles/{pid}", headers=bob).status_code == 404
    # nothing was changed for the owner
    assert client.get(f"{TARGETS}/{t['id']}", headers=alice).status_code == 200
    assert len(client.get(f"{TARGETS}/{t['id']}/auth-profiles", headers=alice).json()) == 1


def test_deleting_a_target_removes_everything_beneath_it(client, auth_headers, db_session) -> None:
    t = client.post(TARGETS, json=payload(), headers=auth_headers).json()
    client.post(
        f"{TARGETS}/{t['id']}/auth-profiles",
        json={"name": "p", "config": {"type": "bearer", "token": "abcdefgh"}},
        headers=auth_headers,
    )
    target = db_session.get(ScanTarget, uuid.UUID(t["id"]))
    scan = Scan(user_id=target.user_id, target_id=target.id, configuration={"modules": ["auth"]})
    db_session.add(scan)
    db_session.flush()
    ep = Endpoint(
        scan_id=scan.id, path="/users", http_method="GET", discovery_source=DiscoverySource.OPENAPI
    )
    db_session.add(ep)
    db_session.flush()
    finding = VulnerabilityFinding(
        scan_id=scan.id,
        endpoint_id=ep.id,
        check_id="misconfig.headers",
        category=OwaspCategory.API8_MISCONFIGURATION,
        title="x",
        description="d",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        status=FindingStatus.POTENTIAL,
        remediation="r",
        fingerprint="fp1",
    )
    db_session.add(finding)
    db_session.flush()
    db_session.add(
        FindingEvidence(
            finding_id=finding.id,
            request_summary="GET /",
            response_status=200,
            response_summary="ok",
        )
    )
    db_session.commit()

    assert client.delete(f"{TARGETS}/{t['id']}", headers=auth_headers).status_code == 204
    db_session.expire_all()
    for model in (AuthProfile, Scan, Endpoint, VulnerabilityFinding, FindingEvidence):
        assert db_session.scalar(select(func.count()).select_from(model)) == 0, model


# ---- authentication profiles for target APIs --------------------------------------------


def _target(client, headers) -> str:
    return client.post(TARGETS, json=payload(), headers=headers).json()["id"]


def test_secrets_are_never_returned_and_are_encrypted_at_rest(
    client, auth_headers, db_session
) -> None:
    tid = _target(client, auth_headers)
    secret = "super-secret-bearer-value-123"
    r = client.post(
        f"{TARGETS}/{tid}/auth-profiles",
        json={
            "name": "user_a",
            "role_label": "user_a",
            "config": {"type": "bearer", "token": secret},
        },
        headers=auth_headers,
    )
    assert r.status_code == 201
    assert secret not in r.text
    assert r.json()["has_credentials"] is True and r.json()["auth_type"] == "bearer"
    assert secret not in client.get(f"{TARGETS}/{tid}/auth-profiles", headers=auth_headers).text

    stored = db_session.scalar(select(AuthProfile))
    assert secret not in stored.encrypted_config
    assert decrypt_json(stored.encrypted_config) == {"token": secret}


def test_api_key_and_test_account_profiles(client, auth_headers, db_session) -> None:
    tid = _target(client, auth_headers)
    url = f"{TARGETS}/{tid}/auth-profiles"
    r1 = client.post(
        url,
        json={
            "name": "key",
            "config": {"type": "api_key", "name": "X-API-Key", "value": "k-12345678"},
        },
        headers=auth_headers,
    )
    r2 = client.post(
        url,
        json={
            "name": "acct",
            "role_label": "admin",
            "config": {"type": "test_account", "username": "tester", "password": "pw-12345678"},
        },
        headers=auth_headers,
    )
    r3 = client.post(url, json={"name": "anon", "config": {"type": "none"}}, headers=auth_headers)
    assert (r1.status_code, r2.status_code, r3.status_code) == (201, 201, 201)
    assert r3.json()["has_credentials"] is False
    assert "pw-12345678" not in r2.text and "k-12345678" not in r1.text
    by_name = {p.name: p for p in db_session.scalars(select(AuthProfile))}
    assert decrypt_json(by_name["key"].encrypted_config)["location"] == "header"
    assert by_name["anon"].encrypted_config is None


@pytest.mark.parametrize(
    "config",
    [
        {"type": "bearer", "token": "abc\r\nX-Injected: 1"},
        {"type": "bearer", "token": "has space"},
        {"type": "bearer", "token": ""},
        {"type": "api_key", "name": "Bad Header", "value": "v"},
        {"type": "api_key", "name": "Host", "value": "v"},
        {"type": "api_key", "name": "X-Key", "value": "v\nInjected: 1"},
        {"type": "mystery"},
        {"type": "bearer"},
    ],
)
def test_invalid_or_injecting_credentials_are_rejected(client, auth_headers, config) -> None:
    tid = _target(client, auth_headers)
    r = client.post(
        f"{TARGETS}/{tid}/auth-profiles", json={"name": "p", "config": config}, headers=auth_headers
    )
    assert r.status_code == 422
    assert "abc" not in r.text  # submitted secrets are not echoed back


def test_auth_profile_limits_and_duplicates(client, auth_headers) -> None:
    tid = _target(client, auth_headers)
    url = f"{TARGETS}/{tid}/auth-profiles"
    cfg = {"type": "none"}
    assert (
        client.post(url, json={"name": "dup", "config": cfg}, headers=auth_headers).status_code
        == 201
    )
    assert (
        client.post(url, json={"name": "dup", "config": cfg}, headers=auth_headers).status_code
        == 409
    )
    for i in range(9):
        assert (
            client.post(
                url, json={"name": f"p{i}", "config": cfg}, headers=auth_headers
            ).status_code
            == 201
        )
    assert (
        client.post(
            url, json={"name": "one-too-many", "config": cfg}, headers=auth_headers
        ).status_code
        == 422
    )
    pid = client.get(url, headers=auth_headers).json()[0]["id"]
    assert client.delete(f"{url}/{pid}", headers=auth_headers).status_code == 204
    assert client.delete(f"{url}/{pid}", headers=auth_headers).status_code == 404
