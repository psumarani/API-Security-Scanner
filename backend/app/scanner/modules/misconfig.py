"""API8 - Security Misconfiguration (headers, CORS, banners, verbose errors, plaintext HTTP)."""

import re
import secrets

from app.models.enums import Confidence, FindingStatus, OwaspCategory, Severity
from app.scanner.base import ModuleMeta, ScanContext, ScannerModule
from app.scanner.evidence import make_evidence
from app.scanner.types import FindingDraft

_STACK_TRACE = re.compile(
    r"(Traceback \(most recent call last\)|\bat [\w.$]+\([\w.]+:\d+\)|System\.\w+Exception|"
    r"SQLSTATE\[|Fatal error:|/usr/lib/|/var/www/|C:\\\\|node_modules/|\bin <module>\b)"
)
_VERSIONED_BANNER = re.compile(r"\d+\.\d+")
_UNTRUSTED_ORIGIN = "https://untrusted.example"
_BANNER_HEADERS = ("server", "x-powered-by", "x-aspnet-version")


class MisconfigurationModule(ScannerModule):
    meta = ModuleMeta(
        id="misconfig",
        name="Security misconfiguration",
        description="Security headers, CORS policy, version banners, verbose errors, "
        "plaintext HTTP and advertised OPTIONS methods.",
        categories=[OwaspCategory.API8_MISCONFIGURATION],
        automated=True,
        prerequisites=["None"],
        validation="Observed response headers/bodies. Missing headers are reported as "
        "informational hardening gaps, never as exploitable flaws.",
        limitations="Header presence is judged on sampled responses; CORS risk depends on "
        "whether credentials/cookies are used by the API.",
    )

    async def run(self, ctx: ScanContext) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        profile = ctx.default_profile()

        root = await ctx.try_send("GET", "/", profile=profile, prefixed=False, why="GET /")
        sample = None
        for ep in ctx.safe_endpoints()[:3]:
            path = ctx.fill_path(ep)
            if ctx.has_unfilled_path(path):
                continue
            sample = await ctx.try_send(
                "GET", path, profile=profile, params=ctx.sample_query(ep), why=f"GET {ep.path}"
            )
            if sample is not None:
                sample_path = path
                break
        probes = [("/", root)] + ([(sample_path, sample)] if sample is not None else [])

        findings += self._headers(ctx, probes)
        findings += self._banners(probes)
        findings += await self._cors(ctx, profile)
        findings += await self._options(ctx)
        findings += await self._verbose_error(ctx)
        findings += self._plaintext(ctx, root)
        return findings

    def _headers(self, ctx: ScanContext, probes) -> list[FindingDraft]:
        out: list[FindingDraft] = []
        reference = next(((p, r) for p, r in probes if r is not None), None)
        if reference is None:
            return out
        path, resp = reference
        checks = [
            (
                "x-content-type-options",
                lambda v: v is not None and v.lower() == "nosniff",
                "Missing X-Content-Type-Options header",
                "Without 'nosniff', browsers may MIME-sniff API responses, which can turn "
                "user-controlled content into executable content in some clients.",
                "Add 'X-Content-Type-Options: nosniff' to all responses.",
            ),
            (
                "cache-control",
                lambda v: v is not None and ("no-store" in v.lower() or "private" in v.lower()),
                "Responses are not marked as non-cacheable",
                "Responses lack 'Cache-Control: no-store' (or private). Sensitive API data "
                "could be stored by shared caches or browsers.",
                "Send 'Cache-Control: no-store' on responses that contain user-specific data.",
            ),
        ]
        if ctx.client.scope.scheme == "https":
            checks.append(
                (
                    "strict-transport-security",
                    lambda v: v is not None and "max-age" in v.lower(),
                    "Missing Strict-Transport-Security header",
                    "Without HSTS, clients are not instructed to refuse plaintext connections "
                    "to this host after the first visit.",
                    "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
                )
            )
        for header, ok, title, desc, fix in checks:
            if not ok(resp.headers.get(header)):
                out.append(
                    FindingDraft(
                        check_id=f"misconfig.header.{header}",
                        category=OwaspCategory.API8_MISCONFIGURATION,
                        title=title,
                        description=desc + " This is a hardening gap, not a demonstrated exploit.",
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        status=FindingStatus.INFORMATIONAL,
                        remediation=fix,
                        endpoint_key=None,
                        evidence=[make_evidence("GET", path, resp, include_body=False)],
                    )
                )
        return out

    def _banners(self, probes) -> list[FindingDraft]:
        for path, resp in probes:
            if resp is None:
                continue
            leaked = {
                h: resp.headers[h]
                for h in _BANNER_HEADERS
                if h in resp.headers and _VERSIONED_BANNER.search(resp.headers[h])
            }
            if leaked:
                return [
                    FindingDraft(
                        check_id="misconfig.version_banner",
                        category=OwaspCategory.API8_MISCONFIGURATION,
                        title="Technology and version disclosed in response headers",
                        description="Response headers reveal software names and versions "
                        f"({', '.join(f'{k}: {v}' for k, v in leaked.items())}), which helps "
                        "attackers match known vulnerabilities.",
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        status=FindingStatus.INFORMATIONAL,
                        remediation="Remove or genericize Server/X-Powered-By headers.",
                        evidence=[
                            make_evidence(
                                "GET", path, resp, include_body=False, interesting=tuple(leaked)
                            )
                        ],
                    )
                ]
        return []

    async def _cors(self, ctx: ScanContext, profile) -> list[FindingDraft]:
        headers = {"Origin": _UNTRUSTED_ORIGIN}
        resp = await ctx.try_send(
            "GET", "/", headers=headers, profile=profile, prefixed=False, why="CORS probe"
        )
        if resp is None:
            return []
        acao = resp.headers.get("access-control-allow-origin")
        acac = resp.headers.get("access-control-allow-credentials", "").lower() == "true"
        evidence = make_evidence(
            "GET",
            "/",
            resp,
            headers=headers,
            include_body=False,
            interesting=("access-control-allow-origin", "access-control-allow-credentials"),
        )
        if acao == _UNTRUSTED_ORIGIN and acac:
            return [
                FindingDraft(
                    check_id="misconfig.cors.reflected_credentials",
                    category=OwaspCategory.API8_MISCONFIGURATION,
                    title="CORS reflects arbitrary origins with credentials allowed",
                    description="The API echoed an untrusted Origin in Access-Control-Allow-Origin "
                    "and set Access-Control-Allow-Credentials: true. A malicious site could read "
                    "authenticated responses from a victim's browser.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    status=FindingStatus.CONFIRMED,
                    remediation="Allow only an explicit allowlist of trusted origins; never "
                    "reflect the Origin header together with credentials.",
                    evidence=[evidence],
                )
            ]
        if acao == "*" or acao == _UNTRUSTED_ORIGIN:
            return [
                FindingDraft(
                    check_id="misconfig.cors.permissive",
                    category=OwaspCategory.API8_MISCONFIGURATION,
                    title="Permissive CORS policy",
                    description="The API allows cross-origin reads from any origin. This is "
                    "acceptable for fully public data but dangerous if any endpoint returns "
                    "user-specific data.",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    status=FindingStatus.INFORMATIONAL,
                    remediation="Restrict Access-Control-Allow-Origin to trusted origins.",
                    evidence=[evidence],
                )
            ]
        return []

    async def _options(self, ctx: ScanContext) -> list[FindingDraft]:
        resp = await ctx.try_send("OPTIONS", "/", prefixed=False, why="OPTIONS /")
        if resp is None:
            return []
        allow = resp.headers.get("allow", "").upper()
        risky = [m for m in ("TRACE", "CONNECT") if re.search(rf"\b{m}\b", allow)]
        if not risky:
            return []
        return [
            FindingDraft(
                check_id="misconfig.risky_methods",
                category=OwaspCategory.API8_MISCONFIGURATION,
                title=f"Server advertises {', '.join(risky)} method",
                description="The Allow header lists methods that are rarely needed by APIs and "
                "widen the attack surface. The methods themselves were not exercised.",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                status=FindingStatus.POTENTIAL,
                remediation="Disable TRACE and CONNECT on the web server or gateway.",
                evidence=[
                    make_evidence("OPTIONS", "/", resp, include_body=False, interesting=("allow",))
                ],
            )
        ]

    async def _verbose_error(self, ctx: ScanContext) -> list[FindingDraft]:
        path = f"/__scanner_probe_{secrets.token_hex(4)}__"
        resp = await ctx.try_send(
            "GET", path, profile=ctx.default_profile(), prefixed=False, why="error probe"
        )
        if resp is None or resp.status_code < 400:
            return []
        match = _STACK_TRACE.search(resp.text()[:4000])
        if not match:
            return []
        return [
            FindingDraft(
                check_id="misconfig.verbose_errors",
                category=OwaspCategory.API8_MISCONFIGURATION,
                title="Verbose error response discloses internal details",
                description="A request for a non-existent resource returned content that looks "
                "like a stack trace or internal file path, exposing implementation details.",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                status=FindingStatus.CONFIRMED,
                remediation="Return generic error messages to clients and log details server-side; "
                "disable debug mode in production.",
                evidence=[make_evidence("GET", path, resp)],
            )
        ]

    def _plaintext(self, ctx: ScanContext, root) -> list[FindingDraft]:
        scope = ctx.client.scope
        if scope.scheme != "http" or scope.allow_local_lab or root is None:
            return []
        return [
            FindingDraft(
                check_id="misconfig.plaintext_http",
                category=OwaspCategory.API8_MISCONFIGURATION,
                title="API is served over unencrypted HTTP",
                description="The target responded over plain HTTP. Credentials and data could be "
                "intercepted in transit unless HTTPS is enforced upstream.",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                status=FindingStatus.POTENTIAL,
                remediation="Serve the API over HTTPS only and redirect or reject HTTP.",
                evidence=[make_evidence("GET", "/", root, include_body=False)],
            )
        ]
