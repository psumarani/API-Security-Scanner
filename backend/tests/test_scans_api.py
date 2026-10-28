"""Full-stack tests: API -> database -> background runner -> scanner -> lab app -> reports."""

import json
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.models.enums import ScanStatus
from app.models.scan import Scan
from app.services.scan_runner import InlineScanDispatcher, get_dispatcher, recover_interrupted_scans
from tests.conftest import LAB_HOST, lab_resolver

TOKENS = {"alice": "lab-token-alice", "bob": "lab-token-bob", "admin": "lab-token-admin"}
ALL_MODULES = ["misconfig", "auth", "sqli", "bola", "bfla", "rate_limit", "inventory"]


class NoopDispatcher:
    def dispatch(self, scan_id) -> None:  # leaves the scan queued
        return


@pytest.fixture
def api(client, engine, enable_local_lab):
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    app.dependency_overrides[get_dispatcher] = lambda: InlineScanDispatcher(
        factory, resolver=lab_resolver
    )
    return client


def make_target(client, headers, port, name="Lab", spec=True):
    body = {
        "name": name,
        "base_url": f"http://{LAB_HOST}:{port}",
        "authorization_confirmed": True,
        "allow_local_lab": True,
        "api_spec_url": f"http://{LAB_HOST}:{port}/openapi.json" if spec else None,
    }
    r = client.post("/api/v1/targets", json=body, headers=headers)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def add_profiles(client, headers, target_id):
    ids = {}
    for name, token in TOKENS.items():
        r = client.post(
            f"/api/v1/targets/{target_id}/auth-profiles",
            headers=headers,
            json={"name": name, "role_label": name, "config": {"type": "bearer", "token": token}},
        )
        assert r.status_code == 201, r.text
        ids[name] = r.json()["id"]
    return ids


def scan_body(target_id, ids, modules=None, **settings):
    return {
        "target_id": target_id,
        "modules": modules or ALL_MODULES,
        "authorization_confirmed": True,
        "settings": {
            "bola_objects": [{"path": "/api/orders/1", "owner": ids["alice"]}],
            "bfla_rules": [
                {"path": "/api/admin/users", "allowed": [ids["admin"]], "forbidden": [ids["alice"]]}
            ],
            "rate_limit": {"path": "/api/ping", "requests": 15},
            **settings,
        },
    }


def test_full_scan_flow(api, make_user, lab) -> None:
    alice = make_user("alice")
    tid = make_target(api, alice, lab)
    ids = add_profiles(api, alice, tid)

    preview = api.post(f"/api/v1/targets/{tid}/spec-preview", headers=alice)
    assert preview.status_code == 200 and preview.json()["endpoint_count"] == 12
    assert preview.json()["security_schemes"] == {"bearerAuth": "http"}

    r = api.post("/api/v1/scans", json=scan_body(tid, ids), headers=alice)
    assert r.status_code == 201, r.text
    scan_id = r.json()["id"]

    scan = api.get(f"/api/v1/scans/{scan_id}", headers=alice).json()
    assert scan["status"] == "completed" and scan["requests_made"] > 20
    assert scan["started_at"] and scan["completed_at"] and scan["scanner_version"]
    assert scan["endpoint_count"] == 12 and scan["target_name"] == "Lab"
    assert scan["finding_counts"].get("high", 0) + scan["finding_counts"].get("critical", 0) >= 3
    assert {m: v["status"] for m, v in scan["progress"]["modules"].items()} == {
        m: "completed" for m in ALL_MODULES
    }
    assert "lab-token" not in json.dumps(scan)  # no secret ever reaches the stored configuration

    findings = api.get(
        f"/api/v1/scans/{scan_id}/findings", params={"limit": 100}, headers=alice
    ).json()
    titles = {f["title"] for f in findings["items"]}
    assert "Object accessible to another account (BOLA)" in titles
    assert "Protected endpoint accessible without authentication" in titles
    assert any(t.startswith("Possible SQL injection") for t in titles)
    severities = [f["severity"] for f in findings["items"]]
    order = ["critical", "high", "medium", "low", "info"]
    assert severities == sorted(severities, key=order.index)  # most severe first

    confirmed = api.get(
        f"/api/v1/scans/{scan_id}/findings",
        params={"status": "confirmed", "severity": ["high", "critical"]},
        headers=alice,
    ).json()
    assert 0 < confirmed["total"] < findings["total"]
    assert (
        api.get(
            f"/api/v1/scans/{scan_id}/findings", params={"search": "sql"}, headers=alice
        ).json()["total"]
        >= 1
    )
    assert (
        api.get(
            "/api/v1/findings", params={"scan_id": scan_id, "category": "API1:2023"}, headers=alice
        ).json()["total"]
        >= 1
    )

    sqli = next(f for f in findings["items"] if f["title"].startswith("Possible SQL injection"))
    assert sqli["endpoint"]["path"] == "/search"
    detail = api.get(f"/api/v1/findings/{sqli['id']}", headers=alice).json()
    assert detail["evidence"] and detail["remediation"] and detail["scan_status"] == "completed"
    blob = json.dumps(detail)
    assert "lab-token" not in blob and "Authorization" not in blob.replace(
        "without credentials", ""
    )

    eps = api.get(f"/api/v1/scans/{scan_id}/endpoints", headers=alice).json()
    assert len(eps) == 12 and sum(e["finding_count"] for e in eps) > 0

    # --- reports ---
    rj = api.get(f"/api/v1/scans/{scan_id}/report", params={"format": "json"}, headers=alice)
    rh = api.get(f"/api/v1/scans/{scan_id}/report", params={"format": "html"}, headers=alice)
    assert rj.status_code == rh.status_code == 200
    assert (
        "attachment" in rj.headers["content-disposition"]
        and "default-src 'none'" in rh.headers["content-security-policy"]
    )
    report = rj.json()
    assert report["scan"]["id"] == scan_id and report["target"]["authorized_scope"][
        "origin"
    ].startswith("http://lab.example.test")
    assert report["summary"]["total_findings"] == findings["total"]
    assert {c["category"] for c in report["coverage"]["owasp"]} >= {"API1:2023", "API10:2023"}
    assert report["limitations"] and "inconclusive_tests" in report
    assert all(
        f["evidence"] for f in report["findings"] if f["status"] in {"confirmed", "potential"}
    )
    for text in (rj.text, rh.text):
        assert "lab-token" not in text
    assert "Security report" in rh.text and "BOLA" in rh.text

    # --- dashboard reflects real data ---
    dash = api.get("/api/v1/dashboard/summary", headers=alice).json()
    assert dash["total_scans"] == dash["completed_scans"] == 1
    assert dash["total_findings"] == findings["total"] and dash["recent_scans"][0]["id"] == scan_id
    assert sum(dash["findings_by_severity"].values()) == findings["total"]
    assert dash["recent_findings"] and all(
        f["status"] in {"confirmed", "potential"} for f in dash["recent_findings"]
    )


def test_ownership_isolation_for_scans_findings_and_reports(api, make_user, lab) -> None:
    alice, bob = make_user("alice"), make_user("bob")
    tid = make_target(api, alice, lab)
    ids = add_profiles(api, alice, tid)
    scan_id = api.post(
        "/api/v1/scans", json=scan_body(tid, ids, ["misconfig"]), headers=alice
    ).json()["id"]
    finding_id = api.get(f"/api/v1/scans/{scan_id}/findings", headers=alice).json()["items"][0][
        "id"
    ]

    for url in (
        f"/api/v1/scans/{scan_id}",
        f"/api/v1/scans/{scan_id}/findings",
        f"/api/v1/scans/{scan_id}/endpoints",
        f"/api/v1/scans/{scan_id}/report",
        f"/api/v1/findings/{finding_id}",
    ):
        assert api.get(url, headers=bob).status_code == 404, url
    assert api.post(f"/api/v1/scans/{scan_id}/cancel", headers=bob).status_code == 404
    assert (
        api.post("/api/v1/scans", json=scan_body(tid, ids, ["misconfig"]), headers=bob).status_code
        == 404
    )
    assert api.get("/api/v1/scans", headers=bob).json()["total"] == 0
    assert api.get("/api/v1/findings", headers=bob).json()["total"] == 0
    assert api.get("/api/v1/dashboard/summary", headers=bob).json()["total_scans"] == 0
    assert api.get("/api/v1/scans").status_code == 401


def test_scan_validation_rules(api, make_user, lab) -> None:
    alice = make_user("alice")
    tid = make_target(api, alice, lab)
    ids = add_profiles(api, alice, tid)
    other = make_target(api, alice, lab, name="Other")
    other_ids = add_profiles(api, alice, other)

    def post(**changes):
        body = scan_body(tid, ids, ["misconfig"])
        body.update(changes)
        return api.post("/api/v1/scans", json=body, headers=alice)

    assert post(authorization_confirmed=False).status_code == 422
    assert post(modules=["nope"]).status_code == 422
    assert post(modules=[]).status_code == 422
    assert (
        post(auth_profile_ids=[other_ids["alice"]]).status_code == 422
    )  # profile of a different target
    assert (
        post(auth_profile_ids=[ids["bob"]]).status_code == 422
    )  # BOLA/BFLA reference unselected profiles
    for bad in (
        {"max_requests": 5000},
        {"max_concurrency": 99},
        {"timeout_seconds": 300},
        {"rate_limit": {"requests": 5000}},
        {"bola_objects": [{"path": "http://evil/x", "owner": ids["alice"]}]},
    ):
        assert post(settings={**scan_body(tid, ids)["settings"], **bad}).status_code == 422, bad
    assert (
        api.get("/api/v1/scanner/catalog", headers=alice).json()["limits"]["max_requests"]["max"]
        == 2000
    )


def test_cancel_and_report_state_rules(api, make_user, lab) -> None:
    alice = make_user("alice")
    tid = make_target(api, alice, lab)
    ids = add_profiles(api, alice, tid)
    app.dependency_overrides[get_dispatcher] = lambda: NoopDispatcher()
    scan = api.post("/api/v1/scans", json=scan_body(tid, ids, ["misconfig"]), headers=alice).json()
    assert scan["status"] == "queued"
    assert (
        api.get(f"/api/v1/scans/{scan['id']}/report", headers=alice).status_code == 409
    )  # not finished

    cancelled = api.post(f"/api/v1/scans/{scan['id']}/cancel", headers=alice).json()
    assert cancelled["status"] == "cancelled" and cancelled["completed_at"]
    assert api.post(f"/api/v1/scans/{scan['id']}/cancel", headers=alice).status_code == 409
    assert api.get(f"/api/v1/scans/{scan['id']}/report", headers=alice).status_code == 200
    assert (
        api.get("/api/v1/scans", params={"status": "cancelled"}, headers=alice).json()["total"] == 1
    )
    assert (
        api.get("/api/v1/scans", params={"status": "running"}, headers=alice).json()["total"] == 0
    )


def test_a_cancelled_queued_scan_is_never_started(api, make_user, lab, engine) -> None:
    alice = make_user("alice")
    tid = make_target(api, alice, lab)
    ids = add_profiles(api, alice, tid)
    app.dependency_overrides[get_dispatcher] = lambda: NoopDispatcher()
    scan_id = api.post(
        "/api/v1/scans", json=scan_body(tid, ids, ["misconfig"]), headers=alice
    ).json()["id"]
    api.post(f"/api/v1/scans/{scan_id}/cancel", headers=alice)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    from app.services.scan_runner import execute_scan

    execute_scan(factory, uuid.UUID(scan_id), resolver=lab_resolver)
    with factory() as db:
        scan = db.get(Scan, uuid.UUID(scan_id))
        assert scan.status == ScanStatus.CANCELLED and scan.requests_made == 0


def test_failed_scan_is_recorded_not_left_running(api, make_user, lab, db_session) -> None:
    alice = make_user("alice")
    tid = make_target(api, alice, lab, spec=False)
    ids = add_profiles(api, alice, tid)
    # The target's DNS later changes to a prohibited address: the scan must fail, not run.
    app.dependency_overrides[get_dispatcher] = lambda: InlineScanDispatcher(
        sessionmaker(bind=db_session.get_bind(), autoflush=False, expire_on_commit=False),
        resolver=lambda host, port: ["169.254.169.254"],
    )
    scan = api.post("/api/v1/scans", json=scan_body(tid, ids, ["misconfig"]), headers=alice).json()
    assert scan["status"] == "failed" and "out of scope" in scan["error_summary"]
    assert scan["completed_at"] is not None


def test_html_report_escapes_untrusted_content(api, make_user, lab) -> None:
    alice = make_user("alice")
    evil = "<script>alert(1)</script><img src=x onerror=alert(2)>"
    tid = make_target(api, alice, lab, name=evil)
    ids = add_profiles(api, alice, tid)
    r = api.post(
        "/api/v1/targets",
        headers=alice,
        json={
            "name": "n2",
            "base_url": f"http://{LAB_HOST}:{lab}",
            "authorization_confirmed": True,
            "allow_local_lab": True,
            "authorization_note": "</pre><script>steal()</script>",
        },
    )
    assert r.status_code == 201
    scan_id = api.post(
        "/api/v1/scans", json=scan_body(tid, ids, ["misconfig"]), headers=alice
    ).json()["id"]
    html = api.get(f"/api/v1/scans/{scan_id}/report", params={"format": "html"}, headers=alice).text
    assert (
        "<script>alert(1)</script>" not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    )
    assert "onerror=alert(2)>" not in html or "&lt;img" in html


def test_interrupted_scans_are_recovered_on_startup(api, make_user, lab, engine) -> None:
    alice = make_user("alice")
    tid = make_target(api, alice, lab)
    ids = add_profiles(api, alice, tid)
    app.dependency_overrides[get_dispatcher] = lambda: NoopDispatcher()
    queued = api.post(
        "/api/v1/scans", json=scan_body(tid, ids, ["misconfig"]), headers=alice
    ).json()["id"]
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with factory() as db:
        db.get(Scan, uuid.UUID(queued)).status = ScanStatus.RUNNING
        db.get(Scan, uuid.UUID(queued)).started_at = datetime.now(UTC)
        db.commit()
    assert recover_interrupted_scans(factory) == 1
    scan = api.get(f"/api/v1/scans/{queued}", headers=alice).json()
    assert scan["status"] == "failed" and "restart" in scan["error_summary"]
    with factory() as db:
        assert (
            db.scalar(select(Scan.status).where(Scan.id == uuid.UUID(queued))) == ScanStatus.FAILED
        )


def test_session_management(client, make_user) -> None:
    make_user("alice")
    r = client.post(
        "/api/v1/auth/login",
        json={"identifier": "alice", "password": "correct horse battery staple"},
    )
    second = {"Authorization": f"Bearer {r.json()['access_token']}"}
    sessions = client.get("/api/v1/auth/sessions", headers=second).json()
    assert len(sessions) == 2 and sum(s["current"] for s in sessions) == 1
    other = next(s for s in sessions if not s["current"])
    assert client.delete(f"/api/v1/auth/sessions/{other['id']}", headers=second).status_code == 204
    assert len(client.get("/api/v1/auth/sessions", headers=second).json()) == 1
    assert (
        client.delete(f"/api/v1/auth/sessions/{other['id']}", headers=second).status_code == 204
    )  # idempotent
    assert client.delete(f"/api/v1/auth/sessions/{uuid.uuid4()}", headers=second).status_code == 404
