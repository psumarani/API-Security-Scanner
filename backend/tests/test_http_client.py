import asyncio
import threading
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpcore
import httpx
import pytest

from app.scanner.http_client import (
    ALL_METHODS,
    NetworkError,
    PinnedNetworkBackend,
    RedirectBlocked,
    RequestBudgetExceeded,
    SafeHttpClient,
    TooManyRedirects,
    UnsafeMethodError,
    build_pinned_transport,
)
from app.scanner.scope_validator import Scope, ScopeViolation

DNS = {
    "api.example.com": ["93.184.216.34"],
    "other.example.com": ["93.184.216.35"],
    "internal.example.com": ["10.0.0.5"],
}


def resolver(host: str, port: int) -> list[str]:  # noqa: ARG001
    try:
        return DNS[host]
    except KeyError as exc:
        raise ScopeViolation(f"host {host!r} could not be resolved") from exc


def run(coro):
    return asyncio.run(coro)


def make_client(handler: Callable[[httpx.Request], httpx.Response], **kwargs) -> SafeHttpClient:
    scope = Scope.from_base_url("https://api.example.com/v1")
    return SafeHttpClient(
        scope, resolver=resolver, transport=httpx.MockTransport(handler), **kwargs
    )


class Recorder:
    def __init__(self, responder: Callable[[httpx.Request], httpx.Response]) -> None:
        self.requests: list[httpx.Request] = []
        self._responder = responder

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._responder(request)


def ok(_: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"ok": True})


def test_relative_paths_are_joined_to_the_base_url() -> None:
    rec = Recorder(ok)

    async def go():
        async with make_client(rec) as c:
            return await c.get("/users/1", params={"a": "b"})

    resp = run(go())
    assert resp.status_code == 200 and resp.body == b'{"ok":true}'
    assert str(rec.requests[0].url) == "https://api.example.com/v1/users/1?a=b"
    assert rec.requests[0].headers["user-agent"].startswith("api-security-scanner")


def test_out_of_scope_urls_are_refused_without_sending() -> None:
    rec = Recorder(ok)

    async def go(url):
        async with make_client(rec) as c:
            return await c.get(url)

    for url in (
        "https://other.example.com/",
        "https://internal.example.com/",
        "http://api.example.com/v1",
        "https://api.example.com:8443/v1",
        "https://user:pw@api.example.com/v1",
        "http://169.254.169.254/latest/meta-data",
        "file:///etc/passwd",
    ):
        with pytest.raises(ScopeViolation):
            run(go(url))
    assert rec.requests == []


def test_redirect_to_another_host_or_prohibited_address_is_blocked() -> None:
    for location in (
        "https://other.example.com/x",
        "http://169.254.169.254/latest/meta-data/",
        "https://internal.example.com/",
        "http://127.0.0.1:8080/",
    ):
        rec = Recorder(lambda r, loc=location: httpx.Response(302, headers={"location": loc}))

        async def go(rec=rec):
            async with make_client(rec) as c:
                return await c.get("/start")

        with pytest.raises(RedirectBlocked):
            run(go())
        assert len(rec.requests) == 1  # the redirect target was never requested


def test_same_origin_redirects_are_followed_and_recorded() -> None:
    def responder(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/a":
            return httpx.Response(302, headers={"location": "/v1/b"})
        return httpx.Response(200, text="done")

    async def go():
        async with make_client(Recorder(responder)) as c:
            return await c.get("/a")

    resp = run(go())
    assert resp.body == b"done" and resp.url.endswith("/v1/b")
    assert resp.redirect_chain == ["https://api.example.com/v1/a"]


def test_redirect_loop_hits_the_hop_limit() -> None:
    rec = Recorder(lambda r: httpx.Response(302, headers={"location": "/v1/loop"}))

    async def go():
        async with make_client(rec, max_redirects=3) as c:
            return await c.get("/loop")

    with pytest.raises(TooManyRedirects):
        run(go())
    assert len(rec.requests) == 4


def test_request_budget_counts_every_request_including_redirects() -> None:
    rec = Recorder(ok)

    async def go():
        async with make_client(rec, max_requests=3) as c:
            for _ in range(3):
                await c.get("/x")
            assert c.requests_remaining == 0
            await c.get("/x")

    with pytest.raises(RequestBudgetExceeded):
        run(go())
    assert len(rec.requests) == 3


def test_unsafe_methods_need_explicit_opt_in() -> None:
    rec = Recorder(ok)

    async def blocked():
        async with make_client(rec) as c:
            await c.request("DELETE", "/users/1")

    async def allowed():
        async with make_client(rec, allowed_methods=ALL_METHODS) as c:
            return await c.request("POST", "/users", json={"a": 1})

    with pytest.raises(UnsafeMethodError):
        run(blocked())
    assert rec.requests == []
    assert run(allowed()).status_code == 200


def test_post_redirect_on_302_downgrades_to_get() -> None:
    def responder(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(302, headers={"location": "/v1/done"})
        return httpx.Response(200, text="ok")

    rec = Recorder(responder)

    async def go():
        async with make_client(rec, allowed_methods=ALL_METHODS) as c:
            return await c.request("POST", "/submit", json={"x": 1})

    run(go())
    assert [r.method for r in rec.requests] == ["POST", "GET"]
    assert rec.requests[1].content == b""


def test_response_bodies_are_capped() -> None:
    rec = Recorder(lambda r: httpx.Response(200, content=b"A" * 5000))

    async def go():
        async with make_client(rec, max_response_bytes=1000) as c:
            return await c.get("/big")

    resp = run(go())
    assert len(resp.body) == 1000 and resp.truncated is True


def test_network_failures_are_classified() -> None:
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    def broken(request: httpx.Request) -> httpx.Response:
        raise httpx.RemoteProtocolError("garbage", request=request)

    for handler, kind in ((timeout, "timeout"), (refused, "connect"), (broken, "protocol")):

        async def go(handler=handler):
            async with make_client(handler) as c:
                await c.get("/x")

        with pytest.raises(NetworkError) as info:
            run(go())
        assert info.value.kind == kind


def test_invalid_limits_are_rejected() -> None:
    scope = Scope.from_base_url("https://api.example.com")
    for kwargs in ({"max_requests": 0}, {"max_concurrency": 0}, {"timeout": 0}):
        with pytest.raises(ValueError):
            SafeHttpClient(scope, resolver=resolver, **kwargs)


def test_concurrency_is_bounded() -> None:
    state = {"now": 0, "peak": 0}

    class SlowTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            state["now"] += 1
            state["peak"] = max(state["peak"], state["now"])
            await asyncio.sleep(0.02)
            state["now"] -= 1
            return httpx.Response(200, text="x")

    async def go():
        scope = Scope.from_base_url("https://api.example.com")
        async with SafeHttpClient(
            scope, resolver=resolver, transport=SlowTransport(), max_concurrency=2
        ) as c:
            await asyncio.gather(*(c.get("/x") for _ in range(8)))

    run(go())
    assert state["peak"] == 2


# ---- connect-time pinning ----------------------------------------------------------------


def test_transport_is_wired_to_the_pinned_backend() -> None:
    scope = Scope.from_base_url("https://api.example.com")
    transport = build_pinned_transport(scope, resolver)
    assert isinstance(transport._pool._network_backend, PinnedNetworkBackend)  # noqa: SLF001


def test_dns_rebinding_is_stopped_at_connect_time() -> None:
    """Name resolves to a public IP for the pre-flight check, then flips to loopback."""
    calls = {"n": 0}

    def rebinding(host: str, port: int) -> list[str]:  # noqa: ARG001
        calls["n"] += 1
        return ["93.184.216.34"] if calls["n"] == 1 else ["127.0.0.1"]

    async def go():
        scope = Scope.from_base_url("http://rebind.example.com:8080")
        async with SafeHttpClient(scope, resolver=rebinding, timeout=2) as c:
            await c.get("/")

    with pytest.raises(ScopeViolation):
        run(go())
    assert calls["n"] >= 2  # pre-flight AND connect-time resolution both happened


def test_backend_rejects_connections_outside_scope_and_unix_sockets() -> None:
    scope = Scope.from_base_url("http://api.example.com:8080")
    backend = PinnedNetworkBackend(scope, resolver)

    async def go():
        with pytest.raises(ScopeViolation):
            await backend.connect_tcp("other.example.com", 8080)
        with pytest.raises(ScopeViolation):
            await backend.connect_tcp("api.example.com", 9999)
        with pytest.raises(ScopeViolation):
            await backend.connect_unix_socket("/var/run/docker.sock")

    run(go())


def test_backend_connects_to_the_vetted_ip_not_the_name() -> None:
    seen: list[str] = []

    class FakeInner(httpcore.AsyncNetworkBackend):
        async def connect_tcp(
            self, host, port, timeout=None, local_address=None, socket_options=None
        ):
            seen.append(host)
            return object()

        async def connect_unix_socket(self, path, timeout=None, socket_options=None):
            raise NotImplementedError

        async def sleep(self, seconds):
            return None

    scope = Scope.from_base_url("http://api.example.com:8080")
    backend = PinnedNetworkBackend(scope, resolver, inner=FakeInner())
    run(backend.connect_tcp("api.example.com", 8080))
    assert seen == ["93.184.216.34"]


# ---- real sockets: loopback "lab" server -------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    seen_hosts: list[str] = []

    def do_GET(self) -> None:  # noqa: N802
        type(self).seen_hosts.append(self.headers.get("Host", ""))
        if self.path == "/redirect-out":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/elsewhere")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b'{"lab": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:  # silence
        return


@pytest.fixture
def lab_server() -> Iterator[int]:
    _Handler.seen_hosts = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def test_real_request_to_lab_target_uses_pinned_ip_and_original_host_header(lab_server) -> None:
    def lab_resolver(host: str, port: int) -> list[str]:  # noqa: ARG001
        return ["127.0.0.1"]

    async def go():
        scope = Scope.from_base_url(f"http://lab.example.test:{lab_server}", allow_local_lab=True)
        async with SafeHttpClient(scope, resolver=lab_resolver, timeout=3) as c:
            return await c.get("/ping")

    resp = run(go())
    assert resp.status_code == 200 and resp.body == b'{"lab": true}'
    assert _Handler.seen_hosts == [f"lab.example.test:{lab_server}"]


def test_loopback_target_is_refused_without_local_lab_opt_in(lab_server) -> None:
    def lab_resolver(host: str, port: int) -> list[str]:  # noqa: ARG001
        return ["127.0.0.1"]

    async def go():
        scope = Scope.from_base_url(f"http://lab.example.test:{lab_server}", allow_local_lab=False)
        async with SafeHttpClient(scope, resolver=lab_resolver, timeout=3) as c:
            await c.get("/ping")

    with pytest.raises(ScopeViolation):
        run(go())
    assert _Handler.seen_hosts == []


def test_real_redirect_out_of_scope_is_blocked_even_in_lab_mode(lab_server) -> None:
    def lab_resolver(host: str, port: int) -> list[str]:  # noqa: ARG001
        return ["127.0.0.1"]

    async def go():
        scope = Scope.from_base_url(f"http://lab.example.test:{lab_server}", allow_local_lab=True)
        async with SafeHttpClient(scope, resolver=lab_resolver, timeout=3) as c:
            await c.get("/redirect-out")

    with pytest.raises(RedirectBlocked):
        run(go())
