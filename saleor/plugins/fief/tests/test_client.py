r"""Unit tests for the Fief plugin HTTP client + HMAC signer.

The HMAC algorithm here MUST match T58 (apps/fief verifier) byte-for-byte.

Algorithm (locked across language boundaries, per fief-app-plan.md T58):
    sign_string = f"{METHOD}\n{path}\n{ts}\n{body_sha256_hex}"
    signature   = hex(HMAC-SHA256(secret_utf8, sign_string_utf8))
    body_sha256 = hex(SHA256(body_bytes))   ; SHA256("") for empty body
"""

import hashlib
import hmac
import json
from unittest.mock import MagicMock, patch

import pytest

from ..client import (
    AuthenticationUrlResponse,
    FiefPluginClient,
    LogoutResponse,
    ObtainAccessTokensResponse,
    RefreshResponse,
    build_signature,
    canonical_sign_string,
    sha256_hex,
)

# ---------------------------------------------------------------------------
# Byte-lock fixture
# ---------------------------------------------------------------------------
# The test below MUST stay in lock-step with the parallel T58 verifier test
# on the apps/fief side. If you change any of these inputs or the expected
# signature, you MUST also update the T58 fixture (or you've broken the wire
# protocol). The exact byte values were chosen to be portable: ASCII-only
# JSON, small body, fixed timestamp, deterministic.
BYTE_LOCK_FIXTURE = {
    "method": "POST",
    "path": "/api/plugin/external-authentication-url",
    "timestamp": "1715212800",  # 2024-05-08T22:40:00Z, fixed for the test
    "body": b'{"saleorApiUrl":"https://shop.example.com/graphql/","channelSlug":"default","input":{"redirectUri":"https://shop.example.com/callback"}}',
    "secret": "test-shared-secret-do-not-use-in-prod",
}
# Pre-computed expected outputs. These values are the byte-lock; T58's Node
# verifier MUST produce identical bytes for the same inputs.
BYTE_LOCK_EXPECTED_BODY_SHA256 = (
    "dd8754f44b86a477b4e901628c64fbdab83db3da10462b5d6ccb50e1849248cf"
)
BYTE_LOCK_EXPECTED_SIGN_STRING = (
    "POST\n"
    "/api/plugin/external-authentication-url\n"
    "1715212800\n"
    "dd8754f44b86a477b4e901628c64fbdab83db3da10462b5d6ccb50e1849248cf"
)
BYTE_LOCK_EXPECTED_SIGNATURE = (
    "b6d9f71b30f0ba32d7db1f8a800102e20f52cca25358f9d5d34a92b63286c4bb"
)


# ---------------------------------------------------------------------------
# Pure-function HMAC tests
# ---------------------------------------------------------------------------


def test_sha256_hex_empty_body():
    # given
    body = b""

    # when
    digest = sha256_hex(body)

    # then — RFC test vector for SHA-256("")
    assert (
        digest
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_sha256_hex_known_input():
    # given
    body = b"abc"

    # when
    digest = sha256_hex(body)

    # then — RFC test vector for SHA-256("abc")
    assert (
        digest
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_canonical_sign_string_shape():
    # when
    s = canonical_sign_string(
        method="POST",
        path="/foo",
        timestamp="1715212800",
        body_sha256_hex="deadbeef",
    )

    # then
    assert s == "POST\n/foo\n1715212800\ndeadbeef"


def test_canonical_sign_string_uppercases_method():
    # given/when
    s = canonical_sign_string(
        method="post",
        path="/foo",
        timestamp="1",
        body_sha256_hex="x",
    )

    # then — methods canonicalized to upper to match T58 verifier
    assert s == "POST\n/foo\n1\nx"


def test_build_signature_matches_byte_lock():
    """The cross-language byte-lock test.

    If this test fails, either T56 or T58 has drifted from the wire spec.
    DO NOT just regenerate the expected value — coordinate with T58.
    """
    # given (frozen fixture)
    fx = BYTE_LOCK_FIXTURE
    expected_body_hash = BYTE_LOCK_EXPECTED_BODY_SHA256
    expected_sign_string = BYTE_LOCK_EXPECTED_SIGN_STRING
    expected_signature = BYTE_LOCK_EXPECTED_SIGNATURE

    # when
    actual_body_hash = sha256_hex(fx["body"])
    actual_sign_string = canonical_sign_string(
        method=fx["method"],
        path=fx["path"],
        timestamp=fx["timestamp"],
        body_sha256_hex=actual_body_hash,
    )
    actual_signature = build_signature(
        secret=fx["secret"],
        method=fx["method"],
        path=fx["path"],
        timestamp=fx["timestamp"],
        body=fx["body"],
    )

    # then — recompute via stdlib to prove the implementation matches a
    # hand-written reference, not just its own output (defense in depth).
    reference_signature = hmac.new(
        fx["secret"].encode("utf-8"),
        actual_sign_string.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    assert actual_body_hash == expected_body_hash
    assert actual_sign_string == expected_sign_string
    assert actual_signature == expected_signature
    assert actual_signature == reference_signature


def test_build_signature_empty_body():
    # given
    secret = "k"
    method = "GET"
    path = "/p"
    ts = "1"
    body = b""

    # when
    sig = build_signature(
        secret=secret, method=method, path=path, timestamp=ts, body=body
    )

    # then
    expected_sign_string = (
        "GET\n/p\n1\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    expected = hmac.new(
        secret.encode("utf-8"),
        expected_sign_string.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    assert sig == expected


# ---------------------------------------------------------------------------
# Client request shape + response parsing tests
# ---------------------------------------------------------------------------


@pytest.fixture
def client():
    return FiefPluginClient(
        base_url="https://apps.fief.example.com",
        hmac_secret="test-shared-secret-do-not-use-in-prod",
        saleor_api_url="https://shop.example.com/graphql/",
        default_connection_id="conn_abc",
    )


def _make_response(status: int = 200, payload: dict | None = None):
    resp = MagicMock()
    resp.status_code = status
    resp.text = json.dumps(payload or {})
    resp.json = MagicMock(return_value=payload or {})
    resp.raise_for_status = MagicMock()
    return resp


def test_authentication_url_request_shape(client):
    # given
    fake_resp = _make_response(
        200,
        {"authorizationUrl": "https://fief.example/authorize?x=1"},
    )

    # when
    with patch.object(client, "_session") as session:
        session.request.return_value = fake_resp
        result = client.authentication_url(
            redirect_uri="https://shop.example.com/callback",
            saleor_user_id=None,
            channel_slug="default",
        )

    # then
    assert isinstance(result, AuthenticationUrlResponse)
    assert result.authorization_url == "https://fief.example/authorize?x=1"

    call = session.request.call_args
    assert call.kwargs["method"] == "POST"
    assert call.kwargs["url"].endswith(
        "/api/plugin/external-authentication-url"
    )
    headers = call.kwargs["headers"]
    assert "X-Fief-Plugin-Timestamp" in headers
    assert "X-Fief-Plugin-Signature" in headers
    assert (
        headers["X-Fief-Plugin-Saleor-Url"]
        == "https://shop.example.com/graphql/"
    )
    assert headers["X-Fief-Plugin-Channel"] == "default"
    assert headers["X-Fief-Plugin-Connection"] == "conn_abc"
    # Body is JSON-encoded with the expected fields.
    body = json.loads(call.kwargs["data"])
    assert body["redirectUri"] == "https://shop.example.com/callback"


def test_obtain_access_tokens_request_shape(client):
    # given
    payload = {
        "claims": {
            "id": "VXNlcjox",
            "email": "user@example.com",
            "firstName": "Ada",
            "lastName": "Lovelace",
            "isActive": True,
            "metadata": {},
            "privateMetadata": {},
        },
        "fiefAccessToken": "fief-access",
        "fiefRefreshToken": "fief-refresh",
    }
    fake_resp = _make_response(200, payload)

    # when
    with patch.object(client, "_session") as session:
        session.request.return_value = fake_resp
        result = client.obtain_access_tokens(
            code="auth-code",
            state="opaque-state",
            channel_slug="default",
        )

    # then
    assert isinstance(result, ObtainAccessTokensResponse)
    assert result.fief_access_token == "fief-access"
    assert result.fief_refresh_token == "fief-refresh"
    assert result.claims["email"] == "user@example.com"
    call = session.request.call_args
    assert call.kwargs["url"].endswith(
        "/api/plugin/external-obtain-access-tokens"
    )
    body = json.loads(call.kwargs["data"])
    assert body["code"] == "auth-code"
    assert body["state"] == "opaque-state"


def test_refresh_request_shape(client):
    # given
    payload = {
        "claims": {
            "id": "VXNlcjox",
            "email": "user@example.com",
            "firstName": "Ada",
            "lastName": "Lovelace",
            "isActive": True,
            "metadata": {},
            "privateMetadata": {},
        },
        "fiefAccessToken": "new-access",
        "fiefRefreshToken": "new-refresh",
        "logoutRequired": False,
    }
    fake_resp = _make_response(200, payload)

    # when
    with patch.object(client, "_session") as session:
        session.request.return_value = fake_resp
        result = client.refresh(
            refresh_token="old-refresh",
            channel_slug="default",
        )

    # then
    assert isinstance(result, RefreshResponse)
    assert result.fief_access_token == "new-access"
    assert result.logout_required is False
    call = session.request.call_args
    assert call.kwargs["url"].endswith("/api/plugin/external-refresh")
    body = json.loads(call.kwargs["data"])
    assert body["refreshToken"] == "old-refresh"


def test_logout_request_shape(client):
    # given
    fake_resp = _make_response(200, {"ok": True})

    # when
    with patch.object(client, "_session") as session:
        session.request.return_value = fake_resp
        result = client.logout(
            refresh_token="old-refresh",
            channel_slug="default",
        )

    # then
    assert isinstance(result, LogoutResponse)
    assert result.ok is True
    call = session.request.call_args
    assert call.kwargs["url"].endswith("/api/plugin/external-logout")
    body = json.loads(call.kwargs["data"])
    assert body["refreshToken"] == "old-refresh"


def test_signature_header_changes_with_body(client):
    """Tampering with the body must yield a different signature."""
    captured = []

    def _capture(*, method, url, headers, data, timeout):
        captured.append({"headers": dict(headers), "data": data})
        return _make_response(200, {"authorizationUrl": "https://x"})

    with patch.object(client, "_session") as session:
        session.request.side_effect = _capture
        client.authentication_url(
            redirect_uri="https://shop.example.com/a",
            saleor_user_id=None,
            channel_slug="default",
        )
        client.authentication_url(
            redirect_uri="https://shop.example.com/b",
            saleor_user_id=None,
            channel_slug="default",
        )

    sig_a = captured[0]["headers"]["X-Fief-Plugin-Signature"]
    sig_b = captured[1]["headers"]["X-Fief-Plugin-Signature"]
    assert sig_a != sig_b
