"""Controlled HTTP client used by every scanner module.

Safety is enforced in the request path itself:

* every request (and every redirect hop) is checked against the target scope;
* redirects are never followed automatically and are re-validated hop by hop;
* the TCP connection is made to an address that was classified at connect time and pinned,
  which defeats DNS rebinding (the name is never re-resolved after validation);
* request budget, concurrency, timeouts and response size are bounded;
* state-changing methods are refused unless explicitly allowed;
* environment proxies are ignored so traffic cannot be rerouted around the checks.
"""

import asyncio
import functools
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import anyio
import httpcore
import httpx

from app.scanner.scope_validator import (
    Resolver,
    Scope,
    ScopeViolation,
    check_in_scope,
    resolve_and_check,
    system_resolver,
)

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
ALL_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"})
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
USER_AGENT = "api-security-scanner/0.2 (authorized security assessment)"


class HttpClientError(Exception):
    """Base class for controlled-client failures."""


class RequestBudgetExceeded(HttpClientError):
    """The per-scan request budget has been used up."""


class UnsafeMethodError(HttpClientError):
    """The HTTP method is not allowed for this scan configuration."""


class TooManyRedirects(HttpClientError):
    """The redirect limit was reached."""


class RedirectBlocked(ScopeViolation):
    """A redirect pointed outside the authorized scope."""


class NetworkError(HttpClientError):
    """Timeout, connection failure or other transport problem."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind  # "timeout" | "connect" | "protocol" | "network"


@dataclass
class ScopedResponse:
    status_code: int
    headers: dict[str, str]
    body: bytes
    truncated: bool
    url: str
    elapsed_ms: float
    redirect_chain: list[str] = field(default_factory=list)

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "")

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Connects only to addresses that pass the scope policy, resolved at connect time."""

    def __init__(
        self,
        scope: Scope,
        resolver: Resolver = system_resolver,
        inner: httpcore.AsyncNetworkBackend | None = None,
    ) -> None:
        self._scope = scope
        self._resolver = resolver
        self._inner = inner or httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        if (host.lower().rstrip("."), port) != (self._scope.host, self._scope.port):
            raise ScopeViolation("connection attempt outside the authorized scope")
        ips = await anyio.to_thread.run_sync(
            functools.partial(
                resolve_and_check,
                host,
                port,
                allow_local_lab=self._scope.allow_local_lab,
                resolver=self._resolver,
            )
        )
        last_error: Exception | None = None
        for ip in ips:  # connect to the vetted literal address, never to the name
            try:
                return await self._inner.connect_tcp(
                    ip,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_error = exc
        raise last_error or httpcore.ConnectError("no usable address")

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise ScopeViolation("unix sockets are not allowed")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def build_pinned_transport(
    scope: Scope, resolver: Resolver = system_resolver, *, verify_tls: bool = True
) -> httpx.AsyncHTTPTransport:
    """An httpx transport whose connections go through PinnedNetworkBackend.

    httpx has no public hook for a custom network backend, so the transport's connection pool is
    replaced. requirements.txt pins httpx to a tested range and a test asserts this wiring.
    """
    transport = httpx.AsyncHTTPTransport(verify=verify_tls, trust_env=False)
    transport._pool = httpcore.AsyncConnectionPool(  # noqa: SLF001
        ssl_context=httpx.create_ssl_context(verify=verify_tls, trust_env=False),
        max_connections=20,
        max_keepalive_connections=10,
        keepalive_expiry=5.0,
        network_backend=PinnedNetworkBackend(scope, resolver),
    )
    return transport


async def _read_capped(response: httpx.Response, cap: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        remaining = cap - total
        if len(chunk) > remaining:
            chunks.append(chunk[:remaining])
            return b"".join(chunks), True
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks), False


class SafeHttpClient:
    """Async client bound to one target scope. Use as ``async with SafeHttpClient(...)``."""

    def __init__(
        self,
        scope: Scope,
        *,
        resolver: Resolver = system_resolver,
        timeout: float = 10.0,
        max_requests: int = 200,
        max_concurrency: int = 5,
        max_redirects: int = 3,
        max_response_bytes: int = 1_000_000,
        allowed_methods: frozenset[str] = SAFE_METHODS,
        default_headers: Mapping[str, str] | None = None,
        verify_tls: bool = True,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if max_requests < 1 or max_concurrency < 1 or timeout <= 0:
            raise ValueError("max_requests, max_concurrency and timeout must be positive")
        self.scope = scope
        self._resolver = resolver
        self._max_requests = max_requests
        self._max_redirects = max_redirects
        self._max_bytes = max_response_bytes
        self._allowed_methods = frozenset(m.upper() for m in allowed_methods)
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._requests_made = 0
        self._budget_lock = asyncio.Lock()
        headers = {"User-Agent": USER_AGENT, **(default_headers or {})}
        self._client = httpx.AsyncClient(
            transport=transport or build_pinned_transport(scope, resolver, verify_tls=verify_tls),
            timeout=httpx.Timeout(timeout, connect=min(timeout, 5.0)),
            headers=headers,
            follow_redirects=False,
            trust_env=False,
        )

    @property
    def requests_made(self) -> int:
        return self._requests_made

    @property
    def requests_remaining(self) -> int:
        return self._max_requests - self._requests_made

    async def __aenter__(self) -> "SafeHttpClient":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self._client.aclose()

    def _absolute(self, url_or_path: str) -> str:
        if "://" in url_or_path:
            return url_or_path
        return f"{self.scope.base_url}/{url_or_path.lstrip('/')}"

    async def _reserve(self) -> None:
        async with self._budget_lock:
            if self._requests_made >= self._max_requests:
                raise RequestBudgetExceeded(f"request budget of {self._max_requests} exhausted")
            self._requests_made += 1

    async def request(
        self,
        method: str,
        url_or_path: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, Any] | None = None,
        json: Any = None,
        content: bytes | str | None = None,
    ) -> ScopedResponse:
        method = method.upper()
        if method not in self._allowed_methods:
            raise UnsafeMethodError(f"{method} requests are not enabled for this scan")

        url = self._absolute(url_or_path)
        chain: list[str] = []
        send_params, send_json, send_content = params, json, content

        for hop in range(self._max_redirects + 1):
            try:
                await anyio.to_thread.run_sync(
                    functools.partial(check_in_scope, url, self.scope, resolver=self._resolver)
                )
            except ScopeViolation as exc:
                if hop == 0:
                    raise
                raise RedirectBlocked(f"redirect blocked: {exc}") from exc

            await self._reserve()
            started = time.perf_counter()
            async with self._semaphore:
                try:
                    request = self._client.build_request(
                        method,
                        url,
                        headers=headers,
                        params=send_params,
                        json=send_json,
                        content=send_content,
                    )
                    response = await self._client.send(request, stream=True)
                    try:
                        body, truncated = await _read_capped(response, self._max_bytes)
                    finally:
                        await response.aclose()
                except httpx.TimeoutException as exc:
                    raise NetworkError(
                        "timeout", f"request timed out: {type(exc).__name__}"
                    ) from exc
                except httpx.ConnectError as exc:
                    raise NetworkError("connect", "connection failed") from exc
                except httpx.ProtocolError as exc:
                    raise NetworkError("protocol", "malformed or interrupted response") from exc
                except httpx.RequestError as exc:
                    raise NetworkError("network", f"network error: {type(exc).__name__}") from exc
            elapsed_ms = (time.perf_counter() - started) * 1000

            location = response.headers.get("location")
            if response.status_code in REDIRECT_STATUSES and location:
                chain.append(url)
                url = urljoin(url, location)
                if response.status_code in {301, 302, 303} and method not in {"GET", "HEAD"}:
                    method, send_json, send_content = "GET", None, None
                send_params = None
                continue

            return ScopedResponse(
                status_code=response.status_code,
                headers={k.lower(): v for k, v in response.headers.items()},
                body=body,
                truncated=truncated,
                url=url,
                elapsed_ms=elapsed_ms,
                redirect_chain=chain,
            )
        raise TooManyRedirects(f"more than {self._max_redirects} redirects")

    async def get(self, url_or_path: str, **kwargs: Any) -> ScopedResponse:
        return await self.request("GET", url_or_path, **kwargs)
