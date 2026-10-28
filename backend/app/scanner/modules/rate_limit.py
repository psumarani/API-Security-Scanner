"""API4 - Unrestricted Resource Consumption: bounded, non-disruptive rate-limit assessment."""

import asyncio
from collections import Counter

from app.models.enums import Confidence, FindingStatus, OwaspCategory, Severity
from app.scanner.base import ModuleMeta, ScanContext, ScannerModule
from app.scanner.evidence import make_evidence
from app.scanner.types import EndpointInfo, FindingDraft

RATE_HEADERS = (
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "ratelimit",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "retry-after",
)
ERROR_STOP_RATIO = 0.2


class RateLimitModule(ScannerModule):
    meta = ModuleMeta(
        id="rate_limit",
        name="Rate limiting",
        description="Sends a small, bounded burst of GET requests to one endpoint and records "
        "status codes and rate-limit headers.",
        categories=[OwaspCategory.API4_RESOURCE_CONSUMPTION],
        automated=True,
        prerequisites=["A safe GET endpoint (chosen automatically or configured)"],
        validation="Reports 'potential' only when no throttling signal (429 or rate-limit headers) "
        "appears within the request budget. This cannot prove limits do not exist beyond the budget.",
        limitations="Never attempts denial of service: the burst is capped (default 30, max 100), "
        "concurrency is bounded and the test stops early on 429 or repeated server errors.",
    )

    def _pick(self, ctx: ScanContext) -> tuple[str, dict[str, str], EndpointInfo | None] | None:
        if ctx.settings.rate_limit.path:
            return ctx.settings.rate_limit.path, {}, None
        for ep in ctx.safe_endpoints():
            path = ctx.fill_path(ep)
            if not ctx.has_unfilled_path(path):
                return path, ctx.sample_query(ep), ep
        return None

    async def run(self, ctx: ScanContext) -> list[FindingDraft]:
        picked = self._pick(ctx)
        if picked is None:
            ctx.notes.append("No suitable GET endpoint found for the rate-limit test.")
            return []
        path, query, ep = picked
        profile = ctx.default_profile() if (ep is None or ep.authentication_required) else None
        cfg = ctx.settings.rate_limit
        budget = min(cfg.requests, ctx.client.requests_remaining)
        if budget < 5:
            ctx.inconclusive.append("rate limit: not enough request budget left")
            return []

        statuses: Counter[int] = Counter()
        seen_headers: dict[str, str] = {}
        first = last = None
        stop = asyncio.Event()
        sem = asyncio.Semaphore(cfg.concurrency)
        sent = 0

        async def one() -> None:
            nonlocal sent, first, last
            if stop.is_set():
                return
            async with sem:
                if stop.is_set():
                    return
                resp = await ctx.try_send(
                    "GET",
                    path,
                    profile=profile,
                    params=query,
                    prefixed=ep is not None,
                    why="rate limit burst",
                )
                sent += 1
                if resp is None:
                    stop.set()
                    return
                statuses[resp.status_code] += 1
                for h in RATE_HEADERS:
                    if h in resp.headers:
                        seen_headers.setdefault(h, resp.headers[h][:80])
                first = first or resp
                last = resp
                if resp.status_code == 429:
                    stop.set()
                if (
                    sent >= 10
                    and sum(v for k, v in statuses.items() if k >= 500) / sent > ERROR_STOP_RATIO
                ):
                    stop.set()

        await asyncio.gather(*(one() for _ in range(budget)))

        total = sum(statuses.values())
        if total == 0:
            return []
        summary = ", ".join(f"{k}:{v}" for k, v in sorted(statuses.items()))
        evidence = make_evidence(
            "GET",
            path,
            last,
            profile=profile,
            params=query,
            include_body=False,
            interesting=tuple(seen_headers),
            note=f"{total} requests sent; status counts {summary}",
        )
        server_errors = sum(v for k, v in statuses.items() if k >= 500)
        if server_errors / total > ERROR_STOP_RATIO:
            ctx.inconclusive.append(
                f"rate limit: test stopped early after {server_errors} server errors"
            )
            return []
        if statuses.get(429) or any(
            h.startswith(("ratelimit", "x-ratelimit")) for h in seen_headers
        ):
            ctx.notes.append(f"Rate limiting observed on {path} ({summary}).")
            return [
                FindingDraft(
                    check_id="rate_limit.observed",
                    category=OwaspCategory.API4_RESOURCE_CONSUMPTION,
                    title="Rate limiting detected",
                    description=f"Throttling signals were observed on GET {path} ({summary}).",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    status=FindingStatus.INFORMATIONAL,
                    remediation="No action required. Verify limits also cover authentication and "
                    "expensive endpoints.",
                    endpoint_key=("GET", path),
                    evidence=[evidence],
                )
            ]
        return [
            FindingDraft(
                check_id="rate_limit.not_observed",
                category=OwaspCategory.API4_RESOURCE_CONSUMPTION,
                title="No rate limiting observed",
                description=f"{total} rapid requests to GET {path} all succeeded ({summary}) with no "
                "429 response or rate-limit headers. Limits may exist at higher volumes or on "
                "other layers; this test is deliberately small.",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                status=FindingStatus.POTENTIAL,
                remediation="Apply per-client rate limits and quotas (and size/pagination limits) "
                "at the gateway or application, returning 429 with Retry-After.",
                endpoint_key=("GET", path),
                evidence=[evidence],
            )
        ]
