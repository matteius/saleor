r"""HTTP client for the apps/fief HTTPS endpoints (T56).

Wire format
-----------
Every request is signed with HMAC-SHA256. The byte layout MUST match the
T58 verifier on the apps/fief side. See
``tests/test_client.py::test_build_signature_matches_byte_lock`` for the
cross-language byte-lock fixture — if that test fails, the protocol has
drifted and apps/fief will reject our requests.

Sign string (line-fed UTF-8)::

    {METHOD}\n{path}\n{timestamp}\n{body_sha256_hex}

- METHOD is upper-cased.
- path is the request path, no querystring (T58 verifier reads the same).
- timestamp is unix seconds as a base-10 ASCII integer string.
- body_sha256_hex is lower-case hex of SHA-256(body); for an empty body
  use SHA-256 of the empty string.
- secret is interpreted as UTF-8 bytes.
- signature is lower-case hex of HMAC-SHA256(secret, sign_string).

Headers
-------
- X-Fief-Plugin-Timestamp     : unix-seconds (matches sign string)
- X-Fief-Plugin-Signature     : hex-encoded HMAC-SHA256
- X-Fief-Plugin-Saleor-Url    : the saleorApiUrl this plugin instance speaks
- X-Fief-Plugin-Channel       : channel slug (optional but always sent)
- X-Fief-Plugin-Connection    : connection id (optional)
- X-Fief-Plugin-Nonce         : optional replay-cache nonce (T58 may guard)

The four request methods all use the same signing path. Bodies are
JSON-serialized with ``separators=(",", ":")`` so the bytes are stable
(this matters because the SHA-256 covers the exact bytes we send).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any

from requests_hardened import HTTPSession

# Saleor's hardened-HTTP config — IP filter + timeouts + UA. Imported lazily
# in the client constructor so tests that monkeypatch settings still work.
from ...core.http_client import HTTPConfig

# ---------------------------------------------------------------------------
# Endpoint paths (relative to ``apps_fief_base_url``)
# ---------------------------------------------------------------------------

PATH_AUTH_URL = "/api/plugin/external-authentication-url"
PATH_OBTAIN_TOKENS = "/api/plugin/external-obtain-access-tokens"
PATH_REFRESH = "/api/plugin/external-refresh"
PATH_LOGOUT = "/api/plugin/external-logout"

DEFAULT_REQUEST_TIMEOUT_SECONDS = 10


# ---------------------------------------------------------------------------
# Signing primitives — also imported by the test suite for the byte-lock
# ---------------------------------------------------------------------------


def sha256_hex(body: bytes) -> str:
    """Lower-case hex SHA-256 of ``body``. SHA-256("") for empty body."""
    return hashlib.sha256(body).hexdigest()


def canonical_sign_string(
    *,
    method: str,
    path: str,
    timestamp: str,
    body_sha256_hex: str,
) -> str:
    r"""Build the exact bytes the HMAC covers.

    Method is upper-cased. The line separator is ``\n`` (single byte).
    """
    return f"{method.upper()}\n{path}\n{timestamp}\n{body_sha256_hex}"


def build_signature(
    *,
    secret: str,
    method: str,
    path: str,
    timestamp: str,
    body: bytes,
) -> str:
    """Return the lower-case hex HMAC-SHA256 signature for the request.

    Splitting the signature primitives out (instead of inlining inside a
    monolithic request method) keeps the byte-lock test small and lets the
    T58 author reproduce the exact bytes by calling these helpers directly.
    """
    body_hash = sha256_hex(body)
    sign_string = canonical_sign_string(
        method=method,
        path=path,
        timestamp=timestamp,
        body_sha256_hex=body_hash,
    )
    return hmac.new(
        secret.encode("utf-8"),
        sign_string.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


# ---------------------------------------------------------------------------
# Response dataclasses (typed wrappers around the apps/fief JSON shapes)
# ---------------------------------------------------------------------------


@dataclass
class AuthenticationUrlResponse:
    authorization_url: str


@dataclass
class ObtainAccessTokensResponse:
    claims: dict[str, Any]
    fief_access_token: str
    fief_refresh_token: str | None = None


@dataclass
class RefreshResponse:
    claims: dict[str, Any]
    fief_access_token: str
    fief_refresh_token: str | None = None
    logout_required: bool = False


@dataclass
class LogoutResponse:
    ok: bool


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class FiefPluginClient:
    """Calls apps/fief over HTTPS with HMAC-signed requests.

    Method-style signatures (``authentication_url``, ``obtain_access_tokens``,
    ``refresh``, ``logout``) intentionally mirror the four `external_*`
    Saleor BasePlugin methods that T57 will delegate to. Each returns a
    typed dataclass shaped after the apps/fief response.
    """

    def __init__(
        self,
        *,
        base_url: str,
        hmac_secret: str,
        saleor_api_url: str,
        default_connection_id: str | None = None,
        session: HTTPSession | None = None,
        timeout: int = DEFAULT_REQUEST_TIMEOUT_SECONDS,
    ):
        self._base_url = base_url.rstrip("/")
        self._hmac_secret = hmac_secret
        self._saleor_api_url = saleor_api_url
        self._default_connection_id = default_connection_id
        self._timeout = timeout
        # HTTPSession from requests-hardened gives us Saleor's IP filter +
        # never-redirect + UA defaults consistent with the rest of the codebase.
        self._session = session or HTTPSession(config=HTTPConfig)

    # ------------------------------------------------------------------
    # public API — one method per apps/fief endpoint
    # ------------------------------------------------------------------

    def authentication_url(
        self,
        *,
        redirect_uri: str,
        saleor_user_id: str | None,
        channel_slug: str | None,
        connection_id: str | None = None,
    ) -> AuthenticationUrlResponse:
        body: dict[str, Any] = {"redirectUri": redirect_uri}
        if saleor_user_id is not None:
            body["saleorUserId"] = saleor_user_id
        payload = self._post(
            path=PATH_AUTH_URL,
            body=body,
            channel_slug=channel_slug,
            connection_id=connection_id,
        )
        return AuthenticationUrlResponse(
            authorization_url=payload["authorizationUrl"],
        )

    def obtain_access_tokens(
        self,
        *,
        code: str,
        state: str,
        channel_slug: str | None,
        connection_id: str | None = None,
    ) -> ObtainAccessTokensResponse:
        payload = self._post(
            path=PATH_OBTAIN_TOKENS,
            body={"code": code, "state": state},
            channel_slug=channel_slug,
            connection_id=connection_id,
        )
        return ObtainAccessTokensResponse(
            claims=payload["claims"],
            fief_access_token=payload["fiefAccessToken"],
            fief_refresh_token=payload.get("fiefRefreshToken"),
        )

    def refresh(
        self,
        *,
        refresh_token: str,
        channel_slug: str | None,
        connection_id: str | None = None,
    ) -> RefreshResponse:
        payload = self._post(
            path=PATH_REFRESH,
            body={"refreshToken": refresh_token},
            channel_slug=channel_slug,
            connection_id=connection_id,
        )
        return RefreshResponse(
            claims=payload["claims"],
            fief_access_token=payload["fiefAccessToken"],
            fief_refresh_token=payload.get("fiefRefreshToken"),
            logout_required=bool(payload.get("logoutRequired", False)),
        )

    def logout(
        self,
        *,
        refresh_token: str | None,
        channel_slug: str | None,
        connection_id: str | None = None,
    ) -> LogoutResponse:
        body: dict[str, Any] = {}
        if refresh_token is not None:
            body["refreshToken"] = refresh_token
        payload = self._post(
            path=PATH_LOGOUT,
            body=body,
            channel_slug=channel_slug,
            connection_id=connection_id,
        )
        return LogoutResponse(ok=bool(payload.get("ok", True)))

    # ------------------------------------------------------------------
    # internal: signing + transport
    # ------------------------------------------------------------------

    def _post(
        self,
        *,
        path: str,
        body: dict[str, Any],
        channel_slug: str | None,
        connection_id: str | None,
    ) -> dict[str, Any]:
        # Stable JSON serialization is mandatory: the body's SHA-256 must
        # match what apps/fief recomputes from the bytes it received.
        body_bytes = json.dumps(body, separators=(",", ":")).encode("utf-8")
        timestamp = str(int(time.time()))
        signature = build_signature(
            secret=self._hmac_secret,
            method="POST",
            path=path,
            timestamp=timestamp,
            body=body_bytes,
        )
        connection = connection_id or self._default_connection_id
        headers = {
            "Content-Type": "application/json",
            "X-Fief-Plugin-Timestamp": timestamp,
            "X-Fief-Plugin-Signature": signature,
            "X-Fief-Plugin-Saleor-Url": self._saleor_api_url,
            "X-Fief-Plugin-Nonce": uuid.uuid4().hex,
        }
        if channel_slug:
            headers["X-Fief-Plugin-Channel"] = channel_slug
        if connection:
            headers["X-Fief-Plugin-Connection"] = connection

        response = self._session.request(
            method="POST",
            url=f"{self._base_url}{path}",
            headers=headers,
            data=body_bytes,
            timeout=self._timeout,
        )
        response.raise_for_status()
        return response.json()
