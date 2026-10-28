"""API5 - Broken Function Level Authorization, driven by an explicit permission model."""

from app.models.enums import Confidence, FindingStatus, OwaspCategory, Severity
from app.scanner.base import ModuleMeta, ScanContext, ScannerModule
from app.scanner.evidence import make_evidence
from app.scanner.settings import SAFE_METHODS
from app.scanner.types import FindingDraft


class BflaModule(ScannerModule):
    meta = ModuleMeta(
        id="bfla",
        name="Function-level authorization (BFLA)",
        description="Calls operations as accounts that should NOT be permitted and compares with "
        "accounts that are permitted.",
        categories=[OwaspCategory.API5_BFLA],
        automated=True,
        prerequisites=[
            "Test accounts for the relevant roles",
            "Permission rules: operation, allowed accounts, forbidden accounts",
        ],
        validation="Confirmed when a forbidden account receives 2xx for an operation your rules "
        "forbid it from calling (and, if given, an allowed account is served as expected).",
        limitations="State-changing operations are skipped unless 'allow unsafe methods' is on; "
        "even then no request bodies are generated. Rules are only as good as the model you supply.",
        default_enabled=False,
    )

    async def run(self, ctx: ScanContext) -> list[FindingDraft]:
        rules = ctx.settings.bfla_rules
        if not rules:
            ctx.notes.append("No permission rules configured; BFLA checks skipped.")
            return []
        findings: list[FindingDraft] = []
        for rule in rules:
            if rule.method not in SAFE_METHODS and not ctx.settings.allow_unsafe_methods:
                ctx.inconclusive.append(
                    f"{rule.method} {rule.path}: state-changing method skipped (unsafe methods disabled)"
                )
                continue
            allowed_ok = None
            for pid in map(str, rule.allowed):
                prof = ctx.profiles.get(pid)
                if prof and prof.usable:
                    resp = await ctx.try_send(
                        rule.method, rule.path, profile=prof, prefixed=False, why="allowed role"
                    )
                    allowed_ok = bool(resp and 200 <= resp.status_code < 300)
                    break
            if rule.allowed and allowed_ok is False:
                ctx.inconclusive.append(
                    f"{rule.method} {rule.path}: the permitted account was not served; check the rule"
                )
            for pid in map(str, rule.forbidden):
                prof = ctx.profiles.get(pid)
                if prof is None or not prof.usable:
                    ctx.inconclusive.append(
                        f"{rule.method} {rule.path}: forbidden profile unusable"
                    )
                    continue
                resp = await ctx.try_send(
                    rule.method, rule.path, profile=prof, prefixed=False, why=f"{prof.label}"
                )
                if resp is None or not 200 <= resp.status_code < 300:
                    continue
                findings.append(
                    FindingDraft(
                        check_id="bfla.forbidden_role_allowed",
                        category=OwaspCategory.API5_BFLA,
                        title="Privileged function reachable by an unauthorized role",
                        description=f"{rule.method} {rule.path} is expected to be forbidden for "
                        f"'{prof.label}', but the API returned HTTP {resp.status_code}.",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH if allowed_ok else Confidence.MEDIUM,
                        status=FindingStatus.CONFIRMED,
                        remediation="Enforce role/permission checks per function on the server "
                        "(deny by default) and test every privileged route with each role.",
                        endpoint_key=(rule.method, rule.path),
                        discriminator=pid,
                        evidence=[
                            make_evidence(
                                rule.method,
                                rule.path,
                                resp,
                                profile=prof,
                                include_body=False,
                                note="expected to be forbidden",
                            )
                        ],
                    )
                )
        return findings
