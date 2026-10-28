"""Module registry and the OWASP API Security Top 10 coverage matrix."""

from dataclasses import dataclass

from app.scanner.base import ModuleMeta, ScannerModule
from app.scanner.modules.authn import AuthenticationModule
from app.scanner.modules.bfla import BflaModule
from app.scanner.modules.bola import BolaModule
from app.scanner.modules.inventory import InventoryModule
from app.scanner.modules.misconfig import MisconfigurationModule
from app.scanner.modules.rate_limit import RateLimitModule
from app.scanner.modules.sqli import SqlInjectionModule

_MODULES: dict[str, ScannerModule] = {}


def register(module: ScannerModule) -> None:
    if module.meta.id in _MODULES:
        raise ValueError(f"duplicate module id {module.meta.id!r}")
    _MODULES[module.meta.id] = module


def get_module(module_id: str) -> ScannerModule:
    return _MODULES[module_id]


def module_ids() -> list[str]:
    return list(_MODULES)


def list_modules() -> list[ModuleMeta]:
    return [m.meta for m in _MODULES.values()]


for _cls in (
    MisconfigurationModule,
    AuthenticationModule,
    SqlInjectionModule,
    BolaModule,
    BflaModule,
    RateLimitModule,
    InventoryModule,
):
    register(_cls())


@dataclass(frozen=True)
class CategoryCoverage:
    category: str
    title: str
    support: str  # supported | partial | unsupported
    automation: str
    modules: list[str]
    prerequisites: str
    validation: str
    limitations: str
    evidence: str


OWASP_COVERAGE: list[CategoryCoverage] = [
    CategoryCoverage(
        "API1:2023",
        "Broken Object Level Authorization",
        "supported",
        "Automated (needs your test data)",
        ["bola"],
        "Two or more test accounts and a list of known objects with their owners.",
        "Owner vs non-owner responses compared; confirmed only on equivalent 2xx content.",
        "Read-only; never guesses identifiers; cannot judge intentionally shared objects.",
        "Sanitized owner and non-owner request/response summaries (status, size, body digest).",
    ),
    CategoryCoverage(
        "API2:2023",
        "Broken Authentication",
        "partial",
        "Automated",
        ["auth"],
        "OpenAPI spec with security declarations; an auth profile is recommended.",
        "Anonymous / malformed / unsigned-token responses compared with an authenticated baseline.",
        "Does not test password policy, credential stuffing, MFA, lockout or token lifetime on the target.",
        "Anonymous and baseline request/response summaries.",
    ),
    CategoryCoverage(
        "API3:2023",
        "Broken Object Property Level Authorization",
        "unsupported",
        "Manual",
        [],
        "Needs knowledge of which properties are sensitive or writable.",
        "Not automated: mass-assignment and excessive-data-exposure checks need business context.",
        "No false positives are generated; review responses and write endpoints manually.",
        "n/a",
    ),
    CategoryCoverage(
        "API4:2023",
        "Unrestricted Resource Consumption",
        "partial",
        "Automated",
        ["rate_limit"],
        "A safe GET endpoint.",
        "Small bounded burst; throttling signals recorded. Absence is 'potential' with low confidence.",
        "Does not test payload size, pagination limits, expensive queries or quotas; never DoS.",
        "Status-code counts and rate-limit headers.",
    ),
    CategoryCoverage(
        "API5:2023",
        "Broken Function Level Authorization",
        "supported",
        "Automated (needs your permission model)",
        ["bfla"],
        "Test accounts per role and rules listing allowed and forbidden accounts per operation.",
        "Forbidden account receiving 2xx is confirmed against your stated rule.",
        "State-changing operations skipped unless enabled; no request bodies are generated.",
        "Request/response summary of the forbidden call.",
    ),
    CategoryCoverage(
        "API6:2023",
        "Unrestricted Access to Sensitive Business Flows",
        "unsupported",
        "Manual",
        [],
        "Needs a model of business flows and abuse cases.",
        "Not automated.",
        "Requires manual workflow analysis.",
        "n/a",
    ),
    CategoryCoverage(
        "API7:2023",
        "Server Side Request Forgery",
        "unsupported",
        "Manual / out-of-band",
        [],
        "Needs an out-of-band callback server and knowledge of URL-accepting parameters.",
        "Not automated: reliable validation requires out-of-band interaction.",
        "The scanner's own HTTP client is hardened against SSRF; that is separate from testing targets.",
        "n/a",
    ),
    CategoryCoverage(
        "API8:2023",
        "Security Misconfiguration",
        "supported",
        "Automated",
        ["misconfig", "sqli"],
        "None (injection checks need GET endpoints with parameters).",
        "Header/CORS/banner/error observations; missing headers are informational. SQL injection "
        "uses error + boolean signals and is mapped to 'other' as OWASP 2023 has no injection category.",
        "Blind and time-based injection, non-GET injection, TLS configuration and WAF behaviour are not tested.",
        "Response headers and sanitized response excerpts.",
    ),
    CategoryCoverage(
        "API9:2023",
        "Improper Inventory Management",
        "partial",
        "Automated (limited)",
        ["inventory"],
        "Discovered endpoints.",
        "Deprecated operations still responding, multiple versions, public API documentation.",
        "Cannot discover unknown hosts, shadow APIs or forgotten deployments.",
        "Sanitized responses for deprecated or documentation endpoints.",
    ),
    CategoryCoverage(
        "API10:2023",
        "Unsafe Consumption of APIs",
        "unsupported",
        "Manual",
        [],
        "Needs visibility into the target's outbound integrations.",
        "Not automated.",
        "Requires code/architecture review.",
        "n/a",
    ),
]
