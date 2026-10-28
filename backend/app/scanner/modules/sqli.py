"""SQL injection detection (error-based plus boolean differential), bounded and non-destructive."""

import re

from app.models.enums import Confidence, FindingStatus, OwaspCategory, Severity
from app.scanner.base import ModuleMeta, ScanContext, ScannerModule
from app.scanner.evidence import bodies_similar, make_evidence
from app.scanner.modules.injection_base import (
    InjectionPoint,
    build_request,
    injection_points,
    is_numeric,
)
from app.scanner.openapi import sample_value
from app.scanner.types import FindingDraft

ERROR_PAYLOADS = ["'", '"', "\\"]

_DB_ERRORS: list[tuple[str, re.Pattern[str]]] = [
    (
        "MySQL/MariaDB",
        re.compile(
            r"You have an error in your SQL syntax|mysql_fetch|MariaDB server version|com\.mysql\.jdbc",
            re.I,
        ),
    ),
    (
        "PostgreSQL",
        re.compile(
            r"PostgreSQL.*ERROR|pg_query\(|syntax error at or near|unterminated quoted string|psycopg",
            re.I,
        ),
    ),
    (
        "SQLite",
        re.compile(r"SQLite3?::|sqlite3\.OperationalError|unrecognized token:|SQLITE_ERROR", re.I),
    ),
    (
        "Microsoft SQL Server",
        re.compile(
            r"Unclosed quotation mark|Microsoft OLE DB|ODBC SQL Server Driver|SqlException", re.I
        ),
    ),
    ("Oracle", re.compile(r"ORA-\d{5}|Oracle error|quoted string not properly terminated", re.I)),
    ("Generic SQL", re.compile(r"SQL syntax.*error|SQLSTATE\[|java\.sql\.SQL", re.I)),
]


def detect_db_error(text: str) -> str | None:
    for dbms, pattern in _DB_ERRORS:
        if pattern.search(text):
            return dbms
    return None


class SqlInjectionModule(ScannerModule):
    meta = ModuleMeta(
        id="sqli",
        name="SQL injection",
        description="Sends a small, fixed set of non-destructive probes (quote characters and "
        "boolean true/false conditions) to GET query and path parameters.",
        categories=[OwaspCategory.OTHER],
        automated=True,
        prerequisites=["Discovered GET endpoints with query or path parameters"],
        validation="Confirmed only when a database error signature that is absent from the "
        "baseline AND a reproducible boolean differential are both observed. A single signal "
        "is reported as 'potential'.",
        limitations="Blind/time-based injection, POST/JSON bodies, headers and cookies are not "
        "tested. No data is extracted and no state-changing queries are sent.",
    )

    async def run(self, ctx: ScanContext) -> list[FindingDraft]:
        findings: list[FindingDraft] = []
        cfg = ctx.settings.sqli
        tested = 0
        for ep in ctx.safe_endpoints():
            points = injection_points(ep, cfg.max_parameters)
            if not points:
                continue
            if tested >= min(cfg.max_endpoints, ctx.settings.max_endpoints_per_module):
                ctx.notes.append("SQL injection endpoint limit reached; remaining skipped.")
                break
            tested += 1
            profile = ctx.default_profile() if ep.authentication_required else None
            for point in points:
                found = await self._test_point(ctx, point, profile)
                if found:
                    findings.append(found)
        if tested == 0:
            ctx.notes.append("No GET endpoints with query/path parameters were found.")
        return findings

    async def _send(self, ctx, point: InjectionPoint, value, profile):
        path, query = build_request(ctx, point, value)
        resp = await ctx.try_send(
            "GET", path, profile=profile, params=query, why=f"sqli {point.name}"
        )
        return resp, path, query

    async def _test_point(self, ctx, point: InjectionPoint, profile) -> FindingDraft | None:
        ep = point.endpoint
        base, base_path, base_q = await self._send(ctx, point, None, profile)
        if base is None or base.status_code >= 500:
            ctx.inconclusive.append(f"{ep.method} {ep.path}: baseline unusable for '{point.name}'")
            return None
        sample = sample_value(point.param)

        error_hit = None
        status_flip = None
        for payload in ERROR_PAYLOADS:
            resp, path, query = await self._send(ctx, point, sample + payload, profile)
            if resp is None:
                continue
            dbms = detect_db_error(resp.text()[:4000])
            if dbms and not detect_db_error(base.text()[:4000]):
                error_hit = (payload, dbms, resp, path, query)
                break
            if resp.status_code >= 500 and base.status_code < 500 and status_flip is None:
                status_flip = (payload, resp, path, query)

        if is_numeric(point):
            true_v, false_v = f"{sample} AND 1=1", f"{sample} AND 1=2"
        else:
            true_v, false_v = f"{sample}' AND '1'='1", f"{sample}' AND '1'='2"
        t, tp, tq = await self._send(ctx, point, true_v, profile)
        f1, fp, fq = await self._send(ctx, point, false_v, profile)
        f2, _, _ = await self._send(ctx, point, false_v, profile)
        boolean_hit = bool(
            t
            and f1
            and f2
            and t.status_code < 500
            and f1.status_code < 500
            and bodies_similar(t.body, base.body)
            and not bodies_similar(f1.body, base.body)
            and bodies_similar(f1.body, f2.body)
        )

        if not (error_hit or boolean_hit or status_flip):
            return None

        evidence = [
            make_evidence("GET", base_path, base, profile=profile, params=base_q, note="baseline")
        ]
        signals: list[str] = []
        if error_hit:
            payload, dbms, resp, path, query = error_hit
            signals.append(f"a {dbms} error message appeared after sending {payload!r}")
            evidence.append(
                make_evidence("GET", path, resp, profile=profile, params=query, note="error probe")
            )
        if boolean_hit:
            signals.append(
                "a true condition matched the baseline while a false condition changed the response (reproduced twice)"
            )
            evidence += [
                make_evidence("GET", tp, t, profile=profile, params=tq, note="true condition"),
                make_evidence("GET", fp, f1, profile=profile, params=fq, note="false condition"),
            ]
        if status_flip and not error_hit:
            payload, resp, path, query = status_flip
            signals.append(f"the server returned HTTP {resp.status_code} after sending {payload!r}")
            evidence.append(
                make_evidence(
                    "GET", path, resp, profile=profile, params=query, note="status change"
                )
            )

        if error_hit and boolean_hit:
            status, conf, sev = FindingStatus.CONFIRMED, Confidence.HIGH, Severity.HIGH
        elif error_hit:
            status, conf, sev = FindingStatus.POTENTIAL, Confidence.MEDIUM, Severity.HIGH
        elif boolean_hit:
            status, conf, sev = FindingStatus.POTENTIAL, Confidence.MEDIUM, Severity.MEDIUM
        else:
            status, conf, sev = FindingStatus.POTENTIAL, Confidence.LOW, Severity.MEDIUM

        return FindingDraft(
            check_id="sqli.parameter",
            category=OwaspCategory.OTHER,
            title=f"Possible SQL injection in {point.location} parameter '{point.name}'",
            description=f"{ep.method} {ep.path}: "
            + "; ".join(signals)
            + ". "
            + (
                "Two independent signals support this finding."
                if status is FindingStatus.CONFIRMED
                else "Manual verification is required before treating this as confirmed."
            ),
            severity=sev,
            confidence=conf,
            status=status,
            remediation="Use parameterized queries / prepared statements for all database access, "
            "validate input types, and return generic errors instead of database messages.",
            endpoint_key=ep.key,
            discriminator=point.name,
            evidence=evidence,
        )
