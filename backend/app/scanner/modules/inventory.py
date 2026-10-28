"""API9 - Improper Inventory Management (limited, passive checks)."""

import re

from app.models.enums import Confidence, FindingStatus, OwaspCategory, Severity
from app.scanner.base import ModuleMeta, ScanContext, ScannerModule
from app.scanner.evidence import make_evidence
from app.scanner.types import FindingDraft

_DOC_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/api-docs",
    "/swagger/v1/swagger.json",
)
_VERSION = re.compile(r"/v(\d+)(?:/|$)")


class InventoryModule(ScannerModule):
    meta = ModuleMeta(
        id="inventory",
        name="API inventory",
        description="Checks whether deprecated operations still respond, whether several API "
        "versions are exposed, and whether API documentation is publicly reachable.",
        categories=[OwaspCategory.API9_INVENTORY],
        automated=True,
        prerequisites=["Discovered endpoints (OpenAPI spec)"],
        validation="Observed responses only. Findings are advisory ('potential' or informational).",
        limitations="Cannot discover undocumented hosts, shadow APIs or old deployments; that "
        "requires asset-inventory work outside this scanner.",
    )

    async def run(self, ctx: ScanContext) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        profile = ctx.default_profile()

        for ep in [e for e in ctx.safe_endpoints() if e.deprecated][:10]:
            path = ctx.fill_path(ep)
            if ctx.has_unfilled_path(path):
                continue
            resp = await ctx.try_send(
                "GET",
                path,
                profile=profile if ep.authentication_required else None,
                params=ctx.sample_query(ep),
                why=f"deprecated {ep.path}",
            )
            if resp is not None and 200 <= resp.status_code < 300:
                findings.append(
                    FindingDraft(
                        check_id="inventory.deprecated_active",
                        category=OwaspCategory.API9_INVENTORY,
                        title="Deprecated operation is still active",
                        description=f"GET {ep.path} is marked deprecated in the specification but "
                        f"still returned HTTP {resp.status_code}. Retired operations are often "
                        "less maintained and monitored.",
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        status=FindingStatus.POTENTIAL,
                        remediation="Retire deprecated operations on a published schedule and "
                        "block them at the gateway afterwards.",
                        endpoint_key=ep.key,
                        evidence=[make_evidence("GET", path, resp, include_body=False)],
                    )
                )

        versions = sorted({m.group(1) for e in ctx.endpoints if (m := _VERSION.search(e.path))})
        if len(versions) > 1:
            findings.append(
                FindingDraft(
                    check_id="inventory.multiple_versions",
                    category=OwaspCategory.API9_INVENTORY,
                    title="Multiple API versions are exposed",
                    description="The specification exposes versions "
                    + ", ".join(f"v{v}" for v in versions)
                    + ". Confirm that older versions are still supported and receive the same "
                    "security fixes.",
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    status=FindingStatus.INFORMATIONAL,
                    remediation="Maintain an inventory of versions with owners and retirement dates.",
                    discriminator="versions",
                )
            )

        for doc_path in _DOC_PATHS:
            resp = await ctx.try_send("GET", doc_path, prefixed=False, why=f"docs {doc_path}")
            if (
                resp
                and resp.status_code == 200
                and re.search(r'"(openapi|swagger)"\s*:', resp.text()[:2000])
            ):
                findings.append(
                    FindingDraft(
                        check_id="inventory.public_spec",
                        category=OwaspCategory.API9_INVENTORY,
                        title="API specification is publicly accessible",
                        description=f"{doc_path} returns the API specification without authentication. "
                        "This is fine for public APIs but discloses every operation of internal ones.",
                        severity=Severity.INFO,
                        confidence=Confidence.HIGH,
                        status=FindingStatus.INFORMATIONAL,
                        remediation="Restrict documentation endpoints to trusted users in production "
                        "if the API is not meant to be public.",
                        endpoint_key=("GET", doc_path),
                        evidence=[make_evidence("GET", doc_path, resp, include_body=False)],
                    )
                )
                break
        return findings
