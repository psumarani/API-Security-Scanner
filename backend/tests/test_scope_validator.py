import pytest

from app.scanner.scope_validator import (
    Scope,
    ScopeViolation,
    check_in_scope,
    classify_ip,
    parse_url,
    resolve_and_check,
    validate_target_urls,
)

DNS = {
    "api.example.com": ["93.184.216.34"],
    "internal.example.com": ["10.0.0.5"],
    "mixed.example.com": ["93.184.216.34", "10.0.0.5"],
    "meta.example.com": ["169.254.169.254"],
    "lab.example.test": ["127.0.0.1"],
}


def resolver(host: str, port: int) -> list[str]:  # noqa: ARG001
    try:
        return DNS[host]
    except KeyError as exc:
        raise ScopeViolation(f"host {host!r} could not be resolved") from exc


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "127.8.8.8",
        "10.1.2.3",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.1.1",
        "169.254.169.254",
        "169.254.0.1",
        "0.0.0.0",
        "100.64.0.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "0.1.2.3",
        "::1",
        "::",
        "fe80::1",
        "fc00::1",
        "fd00:ec2::254",
        "ff02::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "::ffff:169.254.169.254",
        "2002:7f00:1::",
        "64:ff9b::7f00:1",
        "192.0.2.1",
        "198.18.0.1",
    ],
)
def test_prohibited_addresses_are_blocked_by_default(ip: str) -> None:
    assert classify_ip(ip) is not None


@pytest.mark.parametrize("ip", ["93.184.216.34", "8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_addresses_are_allowed(ip: str) -> None:
    assert classify_ip(ip) is None


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.0.10", "::1", "fd12::1"])
def test_local_lab_allows_loopback_and_private_only(ip: str) -> None:
    assert classify_ip(ip, allow_local_lab=True) is None


@pytest.mark.parametrize(
    "ip",
    [
        "169.254.169.254",
        "fe80::1",
        "0.0.0.0",
        "0.1.2.3",
        "224.0.0.1",
        "240.0.0.1",
        "100.64.0.1",
        "::ffff:169.254.169.254",
    ],
)
def test_local_lab_never_allows_metadata_multicast_or_special_ranges(ip: str) -> None:
    assert classify_ip(ip, allow_local_lab=True) is not None


def test_garbage_ip_is_blocked() -> None:
    assert classify_ip("not-an-ip") is not None


@pytest.mark.parametrize(
    "url",
    [
        "",
        "ftp://api.example.com/",
        "file:///etc/passwd",
        "gopher://api.example.com/",
        "javascript:alert(1)",
        "//api.example.com/x",
        "http://",
        "http:///path",
        "http://user:pass@api.example.com/",
        "http://user@api.example.com/",
        "http://api.example.com\\@evil.com/",
        "http://api.example.com/\npath",
        "http://api.example.com:99999/",
        "http://api.example.com:0/",
        "http://api .example.com/",
        "http://2130706433/",
        "http://127.1/",
        "http://0x7f.0.0.1/",
        "http://017700000001/",
        "http://010.0.0.1/",
        "http://[::1%25eth0]/",
        "http://-bad.example.com/",
        "http://" + "a" * 64 + ".example.com/",
        "http://api.example.com/" + "a" * 3000,
    ],
)
def test_malformed_or_ambiguous_urls_are_rejected(url: str) -> None:
    with pytest.raises(ScopeViolation):
        parse_url(url)


def test_parse_url_normalizes() -> None:
    p = parse_url("HTTPS://API.Example.COM./v1/items?x=1")
    assert (p.scheme, p.host, p.port, p.path, p.query) == (
        "https",
        "api.example.com",
        443,
        "/v1/items",
        "x=1",
    )
    assert parse_url("http://api.example.com:8080").origin == "http://api.example.com:8080"
    assert parse_url("http://[2001:db8::1]:8080/").origin == "http://[2001:db8::1]:8080"
    assert parse_url("http://münchen.example/").host == "xn--mnchen-3ya.example"


def test_resolution_rejects_any_prohibited_address() -> None:
    with pytest.raises(ScopeViolation):
        resolve_and_check("internal.example.com", 80, resolver=resolver)
    with pytest.raises(ScopeViolation):  # one public + one private is still rejected
        resolve_and_check("mixed.example.com", 80, resolver=resolver)
    with pytest.raises(ScopeViolation):
        resolve_and_check("meta.example.com", 80, resolver=resolver)
    with pytest.raises(ScopeViolation):
        resolve_and_check("nxdomain.example.com", 80, resolver=resolver)
    assert resolve_and_check("api.example.com", 80, resolver=resolver) == ["93.184.216.34"]


def test_ip_literals_are_checked_without_dns() -> None:
    def boom(host: str, port: int) -> list[str]:
        raise AssertionError("resolver must not be called for IP literals")

    with pytest.raises(ScopeViolation):
        resolve_and_check("127.0.0.1", 80, resolver=boom)
    assert resolve_and_check("93.184.216.34", 80, resolver=boom) == ["93.184.216.34"]


def test_check_in_scope_requires_same_origin() -> None:
    scope = Scope.from_base_url("https://api.example.com/v1")
    assert check_in_scope("https://api.example.com/v1/users", scope, resolver=resolver)
    for url in (
        "http://api.example.com/v1",  # scheme
        "https://api.example.com:8443/v1",  # port
        "https://other.example.com/v1",  # host
        "https://api.example.com.evil.com/",  # suffix trick
        "https://evil.com/?https://api.example.com/",
        "https://internal.example.com/",
    ):
        with pytest.raises(ScopeViolation):
            check_in_scope(url, scope, resolver=resolver)


def test_scope_from_base_url() -> None:
    scope = Scope.from_base_url("https://API.example.com/v1/")
    assert (scope.host, scope.port, scope.base_path, scope.base_url) == (
        "api.example.com",
        443,
        "/v1",
        "https://api.example.com/v1",
    )


def test_validate_target_urls_canonicalizes_and_checks_spec() -> None:
    v = validate_target_urls(
        "HTTPS://API.example.com/v1/", "https://api.example.com/openapi.json", resolver=resolver
    )
    assert v.base_url == "https://api.example.com/v1"
    assert v.api_spec_url == "https://api.example.com/openapi.json"
    with pytest.raises(ScopeViolation):  # spec on another origin
        validate_target_urls(
            "https://api.example.com", "https://evil.com/spec.json", resolver=resolver
        )
    with pytest.raises(ScopeViolation):  # query/fragment in base url
        validate_target_urls("https://api.example.com/?a=1", None, resolver=resolver)
    with pytest.raises(ScopeViolation):
        validate_target_urls("https://api.example.com/#frag", None, resolver=resolver)


def test_validate_target_urls_local_lab_gate() -> None:
    with pytest.raises(ScopeViolation):
        validate_target_urls("http://lab.example.test:8888", None, resolver=resolver)
    v = validate_target_urls(
        "http://lab.example.test:8888", None, allow_local_lab=True, resolver=resolver
    )
    assert v.scope.allow_local_lab is True
    with pytest.raises(ScopeViolation):  # metadata stays blocked in lab mode
        validate_target_urls(
            "http://meta.example.com", None, allow_local_lab=True, resolver=resolver
        )
