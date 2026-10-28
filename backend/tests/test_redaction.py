from app.utils.redaction import (
    REDACTED,
    redact_data,
    redact_headers,
    redact_text,
    summarize_body,
)

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJlLXZhbHVl"


def test_sensitive_headers_are_masked_case_insensitively() -> None:
    out = redact_headers(
        {"Authorization": "Bearer abc", "COOKIE": "sid=1", "X-Api-Key": "k", "Accept": "text/html"}
    )
    assert out == {
        "Authorization": REDACTED,
        "COOKIE": REDACTED,
        "X-Api-Key": REDACTED,
        "Accept": "text/html",
    }


def test_free_text_secrets_are_masked() -> None:
    text = f"Authorization: Bearer abcdefghijklmnop token={JWT} password=hunter2 api_key: 'k-123'"
    out = redact_text(text)
    for leaked in ("abcdefghijklmnop", JWT, "hunter2", "k-123"):
        assert leaked not in out
    assert REDACTED in out


def test_nested_data_is_masked_by_key_and_value() -> None:
    data = {
        "user": {"name": "ann", "password": "pw", "profile": {"access_token": JWT}},
        "items": [{"secret": "s"}, {"note": f"jwt {JWT}"}],
        "count": 3,
    }
    out = redact_data(data)
    assert out["user"]["password"] == REDACTED
    assert out["user"]["profile"]["access_token"] == REDACTED
    assert out["items"][0]["secret"] == REDACTED
    assert JWT not in str(out)
    assert out["user"]["name"] == "ann" and out["count"] == 3


def test_summarize_body_sanitizes_and_truncates() -> None:
    body = b'{"token": "abc123", "data": "' + b"x" * 2000 + b'"}'
    out = summarize_body(body, "application/json", max_chars=100)
    assert "abc123" not in out and "truncated" in out and len(out) < 250
    assert summarize_body("password=hunter2", "text/plain") == "password=" + REDACTED
    assert summarize_body(b"\xff\xfe not utf8", "text/plain")  # never raises
