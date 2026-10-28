"""Target scope enforcement: URL syntax, destination classification and origin matching.

This module is deliberately independent of FastAPI and the database so it can be unit-tested
and reused by the HTTP client on every request and redirect hop.

Policy
------
* Only http and https. No credentials in URLs. No ambiguous numeric hosts ("2130706433", "127.1").
* A request is in scope only if scheme, host and port equal the target's configured origin.
* Every address a hostname resolves to must be permitted. One bad address rejects the request.
* Loopback and private (RFC 1918 / ULA) ranges are blocked unless the target explicitly opted in
  to "local lab" mode (which also requires a server-side switch).
* Link-local (cloud metadata), multicast, unspecified, reserved and other special ranges are
  blocked even in local-lab mode.
"""

import ipaddress
import re
import socket
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = {"http": 80, "https": 443}

Resolver = Callable[[str, int], list[str]]

_FORBIDDEN_URL_CHARS = re.compile(r"[\s\\\x00-\x1f\x7f]")
_NUMERIC_HOST = re.compile(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+))*", re.IGNORECASE)
_HOSTNAME_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
_NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")
_THIS_NETWORK = ipaddress.ip_network("0.0.0.0/8")


class ScopeViolation(Exception):
    """A URL or destination is outside the authorized scope or otherwise prohibited."""


@dataclass(frozen=True)
class ParsedUrl:
    scheme: str
    host: str  # normalized: lowercase, IDNA (ASCII), no brackets, no trailing dot
    port: int
    path: str
    query: str

    @property
    def origin(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        default = ALLOWED_SCHEMES[self.scheme]
        return f"{self.scheme}://{host}" + ("" if self.port == default else f":{self.port}")


@dataclass(frozen=True)
class Scope:
    """The authorized origin (and base path) for a target."""

    scheme: str
    host: str
    port: int
    base_path: str = ""
    allow_local_lab: bool = False

    @property
    def origin(self) -> str:
        return ParsedUrl(self.scheme, self.host, self.port, "", "").origin

    @property
    def base_url(self) -> str:
        return self.origin + self.base_path

    @classmethod
    def from_base_url(cls, base_url: str, *, allow_local_lab: bool = False) -> "Scope":
        parsed = parse_url(base_url)
        return cls(
            scheme=parsed.scheme,
            host=parsed.host,
            port=parsed.port,
            base_path=parsed.path.rstrip("/"),
            allow_local_lab=allow_local_lab,
        )


def system_resolver(host: str, port: int) -> list[str]:
    """Resolve a hostname with the system resolver; returns de-duplicated IP strings."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ScopeViolation(f"host {host!r} could not be resolved") from exc
    seen: dict[str, None] = {}
    for info in infos:
        seen[str(info[4][0])] = None
    return list(seen)


def _parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _normalize_host(raw_host: str) -> str:
    if "%" in raw_host:  # IPv6 zone identifiers and percent-encoded hosts are never legitimate
        raise ScopeViolation("invalid host")
    host = raw_host.rstrip(".").lower()
    if not host:
        raise ScopeViolation("URL has no host")
    if _parse_ip(host) is not None:
        return host
    if "%" in host or ":" in host:
        raise ScopeViolation("invalid host")
    if _NUMERIC_HOST.fullmatch(host):
        raise ScopeViolation("ambiguous numeric host is not allowed; use a canonical IP address")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ScopeViolation("invalid host name") from exc
    if len(host) > 253 or not all(_HOSTNAME_LABEL.fullmatch(label) for label in host.split(".")):
        raise ScopeViolation("invalid host name")
    return host


def parse_url(url: str) -> ParsedUrl:
    """Strictly parse and normalize an http(s) URL. Raises ScopeViolation on anything odd."""
    if not isinstance(url, str) or not url or len(url) > MAX_URL_LENGTH:
        raise ScopeViolation("URL is empty or too long")
    if _FORBIDDEN_URL_CHARS.search(url):
        raise ScopeViolation("URL contains whitespace, backslashes or control characters")
    try:
        parts = urlsplit(url)
        port = parts.port
        raw_host = parts.hostname
    except ValueError as exc:
        raise ScopeViolation("URL is malformed") from exc
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise ScopeViolation("only http and https URLs are allowed")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise ScopeViolation("credentials in URLs are not allowed")
    if not raw_host:
        raise ScopeViolation("URL has no host")
    if port is not None and not 1 <= port <= 65535:
        raise ScopeViolation("invalid port")
    return ParsedUrl(
        scheme=scheme,
        host=_normalize_host(raw_host),
        port=port if port is not None else ALLOWED_SCHEMES[scheme],
        path=parts.path or "/",
        query=parts.query,
    )


def classify_ip(ip: str, *, allow_local_lab: bool = False) -> str | None:
    """Return a reason if the address must not be contacted, else None."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "not a valid IP address"

    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        elif addr.sixtofour is not None:
            addr = addr.sixtofour
        elif addr in _NAT64_PREFIX:
            addr = ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
        elif addr.teredo is not None:
            return "Teredo tunnel address"

    # Ranges that are never acceptable, even for local-lab targets.
    if addr.is_unspecified:
        return "unspecified address"
    if addr.is_multicast:
        return "multicast address"
    if addr.is_link_local:
        return "link-local address (includes cloud metadata endpoints)"
    if isinstance(addr, ipaddress.IPv4Address) and addr in _THIS_NETWORK:
        return '"this network" address'
    if getattr(addr, "is_site_local", False):
        return "site-local address"

    # Loopback and private ranges: only for explicitly authorized local-lab targets.
    # (Checked before is_reserved because Python files ::1 under the reserved ::/8 block.)
    if addr.is_loopback or (addr.is_private and not addr.is_reserved):
        return None if allow_local_lab else "loopback or private network address"
    if addr.is_reserved:
        return "reserved address"
    if not addr.is_global:
        return "non-global address"
    return None


def resolve_and_check(
    host: str,
    port: int,
    *,
    allow_local_lab: bool = False,
    resolver: Resolver = system_resolver,
) -> list[str]:
    """Resolve *host* and verify every resulting address is permitted. Returns the addresses."""
    literal = _parse_ip(host)
    ips = [str(literal)] if literal is not None else resolver(host, port)
    if not ips:
        raise ScopeViolation(f"host {host!r} did not resolve to any address")
    for ip in ips:
        reason = classify_ip(ip, allow_local_lab=allow_local_lab)
        if reason is not None:
            raise ScopeViolation(f"destination for {host!r} is prohibited: {reason}")
    return ips


def check_in_scope(url: str, scope: Scope, *, resolver: Resolver = system_resolver) -> list[str]:
    """Verify *url* is inside *scope* (same origin) and resolves only to permitted addresses."""
    parsed = parse_url(url)
    if (parsed.scheme, parsed.host, parsed.port) != (scope.scheme, scope.host, scope.port):
        raise ScopeViolation(f"URL is outside the authorized scope ({scope.origin})")
    return resolve_and_check(
        parsed.host, parsed.port, allow_local_lab=scope.allow_local_lab, resolver=resolver
    )


@dataclass(frozen=True)
class ValidatedTarget:
    base_url: str  # canonical form
    api_spec_url: str | None
    scope: Scope


def validate_target_urls(
    base_url: str,
    api_spec_url: str | None,
    *,
    allow_local_lab: bool = False,
    resolver: Resolver = system_resolver,
) -> ValidatedTarget:
    """Validate and canonicalize the URLs of a new target.

    The specification URL must be on the same origin as the base URL.
    """
    parsed = parse_url(base_url)
    if parsed.query or "#" in base_url:
        raise ScopeViolation("base URL must not contain a query string or fragment")
    scope = Scope.from_base_url(base_url, allow_local_lab=allow_local_lab)
    check_in_scope(scope.base_url, scope, resolver=resolver)

    spec_canonical: str | None = None
    if api_spec_url:
        check_in_scope(api_spec_url, scope, resolver=resolver)
        spec = parse_url(api_spec_url)
        if "#" in api_spec_url:
            raise ScopeViolation("specification URL must not contain a fragment")
        spec_canonical = spec.origin + spec.path + (f"?{spec.query}" if spec.query else "")
    return ValidatedTarget(
        base_url=scope.base_url or scope.origin, api_spec_url=spec_canonical, scope=scope
    )
