"""Runs every scanner module against the deliberately vulnerable lab app over real sockets."""

import asyncio
import uuid

import pytest

from app.models.enums import AuthType, FindingStatus
from app.scanner.engine import ProfileSpec, run_scan
from app.scanner.scope_validator import Scope
from app.scanner.settings import BflaRule, BolaObject, RateLimitSettings, ScanSettings
from app.scanner.types import FindingDraft
from tests.conftest import LAB_HOST, lab_resolver

ALICE, BOB, ADMIN = (str(uuid.uuid4()) for _ in range(3))


def profiles() -> list[ProfileSpec]:
    return [
        ProfileSpec(ALICE, "alice", "user_a", AuthType.BEARER, {"token": "lab-token-alice"}),
        ProfileSpec(BOB, "bob", "user_b", AuthType.BEARER, {"token": "lab-token-bob"}),
        ProfileSpec(ADMIN, "admin", "admin", AuthType.BEARER, {"token": "lab-token-admin"}),
    ]


def scan(port: int, modules: list[str], settings: ScanSettings | None = None, specs=None):
    collected: list[FindingDraft] = []
    scope = Scope.from_base_url(f"http://{LAB_HOST}:{port}", allow_local_lab=True)
    outcome = asyncio.run(
        run_scan(
            scope=scope,
            settings=settings or ScanSettings(),
            module_ids=modules,
            spec_url=f"http://{LAB_HOST}:{port}/openapi.json",
            profiles=profiles() if specs is None else specs,
            is_cancelled=lambda: False,
            on_module=lambda _r, drafts: collected.extend(drafts),
            resolver=lab_resolver,
        )
    )
    return outcome, collected


def by_check(findings: list[FindingDraft], check_id: str) -> list[FindingDraft]:
    return [f for f in findings if f.check_id == check_id]


def paths(findings: list[FindingDraft]) -> set[str]:
    return {f.endpoint_key[1] for f in findings if f.endpoint_key}


def test_discovery_uses_spec_base_path(lab) -> None:
    outcome, _ = scan(lab, ["inventory"])
    assert outcome.endpoint_count == 12
    assert any("base path '/api'" in n for n in outcome.notes)


def test_authentication_module(lab) -> None:
    outcome, findings = scan(lab, ["auth"])
    assert outcome.status == "completed"
    missing = by_check(findings, "auth.missing_enforcement")
    assert paths(missing) == {"/account"}
    assert missing[0].status is FindingStatus.CONFIRMED  # anonymous == authenticated response
    weak = by_check(findings, "auth.invalid_token_accepted")
    assert paths(weak) == {"/weak-auth/me"} and {f.discriminator for f in weak} >= {"malformed"}
    # correctly protected endpoints produce no finding
    flagged = paths(missing) | paths(weak)
    assert not flagged & {
        "/profile",
        "/admin/secure-users",
        "/safe/orders/{order_id}",
        "/orders/{order_id}",
    }


def test_auth_without_profile_is_only_potential(lab) -> None:
    _, findings = scan(lab, ["auth"], specs=[])
    missing = by_check(findings, "auth.missing_enforcement")
    assert missing and all(f.status is FindingStatus.POTENTIAL for f in missing)


def test_sql_injection_is_confirmed_only_with_two_signals(lab) -> None:
    _, findings = scan(lab, ["sqli"])
    hits = by_check(findings, "sqli.parameter")
    assert [f.endpoint_key for f in hits] == [("GET", "/search")]
    assert hits[0].status is FindingStatus.CONFIRMED and len(hits[0].evidence) >= 3
    # evidence never contains credentials
    assert "lab-token" not in " ".join(
        e.request_summary + e.response_summary for e in hits[0].evidence
    )


def test_bola_confirms_cross_account_access_and_spares_enforced_endpoint(lab) -> None:
    settings = ScanSettings(
        bola_objects=[
            BolaObject(path="/api/orders/1", owner=ALICE),
            BolaObject(path="/api/safe/orders/1", owner=ALICE),
        ]
    )
    _, findings = scan(lab, ["bola"], settings)
    hits = by_check(findings, "bola.cross_account_read")
    assert len(hits) == 2 and all(f.status is FindingStatus.CONFIRMED for f in hits)
    assert all("/safe/" not in h.evidence[0].request_summary for h in hits)
    assert paths(hits) == {"/orders/{order_id}"}  # concrete path mapped to the spec endpoint


def test_bola_needs_two_accounts_and_known_objects(lab) -> None:
    outcome, findings = scan(
        lab,
        ["bola"],
        ScanSettings(bola_objects=[BolaObject(path="/api/orders/1", owner=ALICE)]),
        specs=profiles()[:1],
    )
    assert findings == [] and any("two usable" in n for n in outcome.module_results["bola"].notes)
    outcome, _ = scan(lab, ["bola"])
    assert any("No known objects" in n for n in outcome.module_results["bola"].notes)


def test_bfla_uses_the_stated_permission_model(lab) -> None:
    settings = ScanSettings(
        bfla_rules=[
            BflaRule(path="/api/admin/users", allowed=[ADMIN], forbidden=[ALICE]),
            BflaRule(path="/api/admin/secure-users", allowed=[ADMIN], forbidden=[ALICE]),
            BflaRule(method="DELETE", path="/api/admin/users", forbidden=[ALICE]),
        ]
    )
    outcome, findings = scan(lab, ["bfla"], settings)
    hits = by_check(findings, "bfla.forbidden_role_allowed")
    assert len(hits) == 1 and hits[0].status is FindingStatus.CONFIRMED
    assert any("state-changing" in i for i in outcome.module_results["bfla"].inconclusive)


def test_rate_limit_detects_missing_and_present_limits(lab) -> None:
    _, findings = scan(
        lab,
        ["rate_limit"],
        ScanSettings(rate_limit=RateLimitSettings(path="/api/ping", requests=20)),
    )
    missing = by_check(findings, "rate_limit.not_observed")
    assert (
        missing
        and missing[0].status is FindingStatus.POTENTIAL
        and missing[0].confidence.value == "low"
    )

    outcome, findings = scan(
        lab,
        ["rate_limit"],
        ScanSettings(rate_limit=RateLimitSettings(path="/api/limited", requests=20)),
    )
    assert by_check(findings, "rate_limit.observed") and not by_check(
        findings, "rate_limit.not_observed"
    )
    assert outcome.module_results["rate_limit"].requests <= 20  # stops early once 429 is seen


def test_misconfiguration_module(lab) -> None:
    _, findings = scan(lab, ["misconfig"])
    ids = {f.check_id: f for f in findings}
    assert ids["misconfig.cors.reflected_credentials"].status is FindingStatus.CONFIRMED
    assert ids["misconfig.verbose_errors"].status is FindingStatus.CONFIRMED
    assert ids["misconfig.risky_methods"].status is FindingStatus.POTENTIAL
    assert ids["misconfig.version_banner"].status is FindingStatus.INFORMATIONAL
    # missing headers are hardening gaps, never "confirmed" vulnerabilities
    headers = [f for f in findings if f.check_id.startswith("misconfig.header.")]
    assert headers and all(f.status is FindingStatus.INFORMATIONAL for f in headers)
    assert "misconfig.plaintext_http" not in ids  # local lab mode is exempt


def test_inventory_module(lab) -> None:
    _, findings = scan(lab, ["inventory"])
    ids = {f.check_id for f in findings}
    assert {"inventory.deprecated_active", "inventory.public_spec"} <= ids


def test_findings_are_deduplicated_and_budget_is_respected(lab) -> None:
    outcome, findings = scan(lab, ["misconfig", "auth", "sqli"], ScanSettings(max_requests=25))
    fps = [f.fingerprint for f in findings]
    assert len(fps) == len(set(fps))
    assert outcome.requests_made <= 25


def test_out_of_scope_target_fails_fast(lab) -> None:
    scope = Scope.from_base_url(f"http://{LAB_HOST}:{lab}", allow_local_lab=False)  # lab mode off
    outcome = asyncio.run(
        run_scan(
            scope=scope,
            settings=ScanSettings(),
            module_ids=["misconfig"],
            spec_url=None,
            profiles=[],
            is_cancelled=lambda: False,
            resolver=lab_resolver,
        )
    )
    assert outcome.status == "failed" and "out of scope" in outcome.error


def test_cancellation_stops_between_modules(lab) -> None:
    calls = {"n": 0}

    def cancel_after_first() -> bool:
        calls["n"] += 1
        return calls["n"] > 3

    scope = Scope.from_base_url(f"http://{LAB_HOST}:{lab}", allow_local_lab=True)
    outcome = asyncio.run(
        run_scan(
            scope=scope,
            settings=ScanSettings(),
            module_ids=["misconfig", "auth", "sqli", "inventory"],
            spec_url=f"http://{LAB_HOST}:{lab}/openapi.json",
            profiles=profiles(),
            is_cancelled=cancel_after_first,
            resolver=lab_resolver,
        )
    )
    assert outcome.status == "cancelled" and len(outcome.module_results) < 4


def test_time_limit_marks_the_scan_failed(lab) -> None:
    scope = Scope.from_base_url(f"http://{LAB_HOST}:{lab}", allow_local_lab=True)
    outcome = asyncio.run(
        run_scan(
            scope=scope,
            settings=ScanSettings(max_duration_seconds=30).model_copy(
                update={"max_duration_seconds": -1}
            ),
            module_ids=["misconfig"],
            spec_url=None,
            profiles=[],
            is_cancelled=lambda: False,
            resolver=lab_resolver,
        )
    )
    assert outcome.status == "failed" and "Time limit" in outcome.error


@pytest.mark.parametrize("bad", ["http://evil.example/x", "//evil", "api/x", "/a b"])
def test_user_supplied_paths_must_be_relative(bad: str) -> None:
    with pytest.raises(ValueError):
        BolaObject(path=bad, owner=uuid.uuid4())
