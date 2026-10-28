"""API1 - Broken Object Level Authorization, using explicitly provisioned objects and accounts."""

from app.models.enums import Confidence, FindingStatus, OwaspCategory, Severity
from app.scanner.base import ModuleMeta, ScanContext, ScannerModule
from app.scanner.evidence import bodies_similar, make_evidence
from app.scanner.types import FindingDraft


class BolaModule(ScannerModule):
    meta = ModuleMeta(
        id="bola",
        name="Object-level authorization (BOLA / IDOR)",
        description="For each known object, compares the owner's access with access by every "
        "other test account.",
        categories=[OwaspCategory.API1_BOLA],
        automated=True,
        prerequisites=[
            "At least two provisioned test accounts (auth profiles)",
            "Known objects: a path and the profile that owns it",
        ],
        validation="Confirmed when a non-owner receives a 2xx response equivalent to the owner's. "
        "A 2xx with different content is 'potential'. Identifiers are never guessed.",
        limitations="Read-only (GET) checks of objects you list. Does not enumerate identifiers "
        "and cannot judge whether an equivalent response is legitimately shared data.",
        default_enabled=False,
    )

    async def run(self, ctx: ScanContext) -> list[FindingDraft]:
        objects = ctx.settings.bola_objects
        usable = {pid: p for pid, p in ctx.profiles.items() if p.usable and (p.headers or p.query)}
        if not objects:
            ctx.notes.append("No known objects configured; BOLA checks skipped.")
            return []
        if len(usable) < 2:
            ctx.notes.append("BOLA needs at least two usable test accounts; checks skipped.")
            return []

        findings: list[FindingDraft] = []
        for obj in objects:
            owner = usable.get(str(obj.owner))
            if owner is None:
                ctx.inconclusive.append(f"{obj.path}: owner profile is not usable")
                continue
            base = await ctx.try_send(
                "GET", obj.path, profile=owner, prefixed=False, why=f"owner access {obj.path}"
            )
            if base is None:
                continue
            if not 200 <= base.status_code < 300:
                ctx.inconclusive.append(
                    f"{obj.path}: owner request returned HTTP {base.status_code}; check the test data"
                )
                continue
            for pid, other in usable.items():
                if pid == str(obj.owner):
                    continue
                resp = await ctx.try_send(
                    "GET",
                    obj.path,
                    profile=other,
                    prefixed=False,
                    why=f"{other.label} -> {obj.path}",
                )
                if resp is None or not 200 <= resp.status_code < 300:
                    continue
                same = bodies_similar(resp.body, base.body)
                findings.append(
                    FindingDraft(
                        check_id="bola.cross_account_read",
                        category=OwaspCategory.API1_BOLA,
                        title="Object accessible to another account (BOLA)",
                        description=f"GET {obj.path} belongs to '{owner.label}' but account "
                        f"'{other.label}' received HTTP {resp.status_code}"
                        + (
                            " with a response equivalent to the owner's."
                            if same
                            else " with a different response; verify whether it exposes the owner's data."
                        ),
                        severity=Severity.HIGH if same else Severity.MEDIUM,
                        confidence=Confidence.HIGH if same else Confidence.MEDIUM,
                        status=FindingStatus.CONFIRMED if same else FindingStatus.POTENTIAL,
                        remediation="Authorize every object access against the authenticated "
                        "user's ownership/permissions on the server side; do not rely on "
                        "unguessable identifiers.",
                        endpoint_key=("GET", obj.path),
                        discriminator=f"{owner.id}->{other.id}",
                        evidence=[
                            make_evidence(
                                "GET",
                                obj.path,
                                base,
                                profile=owner,
                                include_body=False,
                                note="owner",
                            ),
                            make_evidence(
                                "GET",
                                obj.path,
                                resp,
                                profile=other,
                                include_body=False,
                                note="non-owner",
                            ),
                        ],
                    )
                )
        return findings
