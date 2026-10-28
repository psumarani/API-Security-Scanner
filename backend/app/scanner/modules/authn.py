"""API2 - Broken Authentication (enforcement and token validation)."""

import base64
import json

from app.models.enums import Confidence, FindingStatus, OwaspCategory, Severity
from app.scanner.base import ModuleMeta, ScanContext, ScannerModule
from app.scanner.evidence import bodies_similar, make_evidence
from app.scanner.types import EndpointInfo, FindingDraft


def _b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


def _unsigned_jwt() -> str:
    return f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64({'sub': '1', 'role': 'admin'})}."


class AuthenticationModule(ScannerModule):
    meta = ModuleMeta(
        id="auth",
        name="Authentication enforcement",
        description="Requests endpoints declared as protected without credentials, and with "
        "malformed or unsigned tokens, and compares the results to an authenticated baseline.",
        categories=[OwaspCategory.API2_BROKEN_AUTH],
        automated=True,
        prerequisites=[
            "OpenAPI spec declaring security on operations",
            "At least one auth profile (recommended, for baseline comparison)",
        ],
        validation="A finding is confirmed only when the anonymous (or invalid-token) response "
        "matches the authenticated response. A bare 2xx without a baseline is 'potential'.",
        limitations="Only GET operations are exercised. Endpoints without declared security are "
        "not tested. Sample IDs are used for path parameters.",
    )

    async def run(self, ctx: ScanContext) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        profile = ctx.default_profile()
        candidates = [e for e in ctx.safe_endpoints() if e.authentication_required][
            : ctx.settings.max_endpoints_per_module
        ]
        if not candidates:
            ctx.notes.append("No GET endpoints declared as requiring authentication.")
            return findings
        for index, ep in enumerate(candidates):
            findings += await self._test_endpoint(ctx, ep, profile, test_tokens=index < 10)
        return findings

    async def _test_endpoint(self, ctx, ep: EndpointInfo, profile, *, test_tokens: bool):
        path = ctx.fill_path(ep)
        if ctx.has_unfilled_path(path):
            ctx.inconclusive.append(f"{ep.method} {ep.path}: path parameters could not be filled")
            return []
        query = ctx.sample_query(ep)
        baseline = (
            await ctx.try_send(
                "GET", path, profile=profile, params=query, why=f"baseline {ep.path}"
            )
            if profile
            else None
        )
        anon = await ctx.try_send("GET", path, params=query, why=f"anonymous {ep.path}")
        if anon is None:
            return []

        found: list[FindingDraft] = []
        key = ep.key
        base_ok = baseline is not None and 200 <= baseline.status_code < 300

        if 200 <= anon.status_code < 300:
            evidence = [make_evidence("GET", path, anon, params=query, include_body=False)]
            if base_ok:
                evidence.append(
                    make_evidence(
                        "GET", path, baseline, profile=profile, params=query, include_body=False
                    )
                )
            if base_ok and bodies_similar(anon.body, baseline.body):
                status, conf, sev = FindingStatus.CONFIRMED, Confidence.HIGH, Severity.HIGH
                detail = "The anonymous response is equivalent to the authenticated response."
            elif base_ok:
                status, conf, sev = FindingStatus.POTENTIAL, Confidence.MEDIUM, Severity.MEDIUM
                detail = (
                    "The anonymous response differs from the authenticated one, so part of the "
                    "endpoint may be intentionally public."
                )
            else:
                status, conf, sev = FindingStatus.POTENTIAL, Confidence.MEDIUM, Severity.MEDIUM
                detail = "No authenticated baseline was available to compare against."
            found.append(
                FindingDraft(
                    check_id="auth.missing_enforcement",
                    category=OwaspCategory.API2_BROKEN_AUTH,
                    title="Protected endpoint accessible without authentication",
                    description=f"{ep.method} {ep.path} is declared as requiring authentication "
                    f"but returned HTTP {anon.status_code} to an anonymous request. {detail}",
                    severity=sev,
                    confidence=conf,
                    status=status,
                    remediation="Enforce authentication on every protected route server-side "
                    "(deny by default) and add automated tests for 401 responses.",
                    endpoint_key=key,
                    evidence=evidence,
                )
            )
            return found
        if anon.status_code not in (401, 403):
            ctx.inconclusive.append(
                f"{ep.method} {ep.path}: anonymous request returned HTTP {anon.status_code}"
            )
            return found
        if not test_tokens:
            return found

        variants = [
            ("malformed", "Bearer invalid.token.value"),
            ("unsigned (alg=none)", f"Bearer {_unsigned_jwt()}"),
        ]
        for label, header in variants:
            resp = await ctx.try_send(
                "GET", path, params=query, headers={"Authorization": header}, why=f"{label} token"
            )
            if resp is None or not 200 <= resp.status_code < 300:
                continue
            same = base_ok and bodies_similar(resp.body, baseline.body)
            found.append(
                FindingDraft(
                    check_id="auth.invalid_token_accepted",
                    category=OwaspCategory.API2_BROKEN_AUTH,
                    title=f"{label.capitalize()} token accepted",
                    description=f"{ep.method} {ep.path} rejected anonymous requests but returned "
                    f"HTTP {resp.status_code} for a {label} bearer token, so token validation "
                    "appears to be missing or flawed."
                    + (" The response matches an authenticated response." if same else ""),
                    severity=Severity.CRITICAL if same else Severity.HIGH,
                    confidence=Confidence.HIGH if same else Confidence.MEDIUM,
                    status=FindingStatus.CONFIRMED if same else FindingStatus.POTENTIAL,
                    remediation="Verify token signatures, expiry, issuer and audience on every "
                    "request and reject 'none' algorithms; use a maintained JWT library.",
                    endpoint_key=key,
                    discriminator=label,
                    evidence=[
                        make_evidence(
                            "GET",
                            path,
                            resp,
                            params=query,
                            note=f"with a {label} bearer token",
                            include_body=False,
                        ),
                        make_evidence("GET", path, anon, params=query, include_body=False),
                    ],
                )
            )
        return found
