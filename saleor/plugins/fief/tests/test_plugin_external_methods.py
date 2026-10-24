"""T57 — Saleor BasePlugin ``external_*`` overrides for the Fief plugin.

These tests stay pure-Python (no live Postgres) by mocking the four pieces
the override touches:

- ``FiefPlugin._get_client`` — replaced with a ``MagicMock`` that returns
  the typed dataclasses from ``client.py`` (``AuthenticationUrlResponse``,
  ``ObtainAccessTokensResponse``, ``RefreshResponse``, ``LogoutResponse``).
- ``saleor.account.models.User.objects`` — patched at the call site inside
  the plugin (``saleor.plugins.fief.plugin.User``) so we can simulate the
  "create" and "already exists" paths without touching the DB.
- ``saleor.core.jwt.create_access_token`` / ``create_refresh_token`` —
  patched at the import site inside the plugin so the tests don't need a
  configured JWT manager.
- ``saleor.core.jwt.jwt_decode`` and the OIDC plugin's
  ``is_owner_of_token_valid`` — patched for ``external_verify`` happy path.

The ``conftest.py`` in this directory neutralizes the saleor-wide DB
autouse fixtures so these run on a fresh checkout without a Postgres
credential.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from django.core.exceptions import ValidationError

from ...base_plugin import ExternalAccessTokens
from ..client import (
    AuthenticationUrlResponse,
    LogoutResponse,
    ObtainAccessTokensResponse,
    RefreshResponse,
)
from ..plugin import FiefPlugin

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_plugin(active: bool = True) -> FiefPlugin:
    """Instantiate FiefPlugin without going through the plugin manager.

    BasePlugin's ``__init__`` only needs ``configuration`` (list of
    ``{"name", "value"}``) and ``active``; everything else has defaults.
    """
    configuration = [
        {"name": "apps_fief_base_url", "value": "https://apps.fief.example.com"},
        {"name": "hmac_secret", "value": "test-shared-secret-do-not-use-in-prod"},
        {"name": "default_connection_id", "value": "conn_abc"},
    ]
    return FiefPlugin(configuration=configuration, active=active)


@pytest.fixture
def plugin():
    return _make_plugin()


@pytest.fixture
def request_factory():
    """Return a bare object that satisfies the ``request`` parameter type hint.

    The Fief plugin overrides do not read anything off the request; the
    parameter exists to match BasePlugin's signature. Tests pass
    ``SimpleNamespace()`` so they are decoupled from Django's RequestFactory.
    """
    return SimpleNamespace()


@pytest.fixture
def fief_claims():
    """Canonical T55-shaped claims payload that apps/fief returns to T57."""
    return {
        "id": "VXNlcjoxMg==",
        "email": "ada@example.com",
        "firstName": "Ada",
        "lastName": "Lovelace",
        "isActive": True,
        "metadata": {"fief_sync_origin": "fief"},
        "privateMetadata": {"fief_sub": "fief-user-uuid-1"},
    }


# ---------------------------------------------------------------------------
# external_authentication_url
# ---------------------------------------------------------------------------


def test_external_authentication_url_returns_authorization_url(
    plugin, request_factory
):
    # given
    fake_client = MagicMock()
    fake_client.authentication_url.return_value = AuthenticationUrlResponse(
        authorization_url="https://fief.example/authorize?client_id=x&state=y",
    )

    data = {
        "redirectUri": "https://shop.example.com/callback",
        "saleorApiUrl": "https://shop.example.com/graphql/",
        "channelSlug": "default",
    }

    # when
    with patch.object(plugin, "_get_client", return_value=fake_client) as mock_get:
        result = plugin.external_authentication_url(data, request_factory, None)

    # then
    assert result == {
        "authorizationUrl": "https://fief.example/authorize?client_id=x&state=y",
    }
    mock_get.assert_called_once_with(saleor_api_url="https://shop.example.com/graphql/")
    fake_client.authentication_url.assert_called_once_with(
        redirect_uri="https://shop.example.com/callback",
        saleor_user_id=None,
        channel_slug="default",
    )


def test_external_authentication_url_returns_previous_value_when_inactive(
    request_factory,
):
    # given
    inactive = _make_plugin(active=False)
    sentinel = {"authorizationUrl": "previous"}

    # when
    result = inactive.external_authentication_url(
        {"redirectUri": "https://shop.example.com/callback"},
        request_factory,
        sentinel,
    )

    # then
    assert result is sentinel


def test_external_authentication_url_raises_on_missing_redirect_uri(
    plugin, request_factory
):
    # given
    data = {"saleorApiUrl": "https://shop.example.com/graphql/"}

    # when / then
    with pytest.raises(ValidationError):
        plugin.external_authentication_url(data, request_factory, None)


# ---------------------------------------------------------------------------
# external_obtain_access_tokens
# ---------------------------------------------------------------------------


def _fake_user(*, email: str = "ada@example.com", pk: int = 12):
    """Lightweight stand-in for an account.User instance in tests."""
    return SimpleNamespace(
        pk=pk,
        id=pk,
        email=email,
        first_name="Ada",
        last_name="Lovelace",
        is_active=True,
        is_confirmed=True,
        is_staff=False,
    )


def test_external_obtain_access_tokens_creates_user_and_returns_jwt(
    plugin, request_factory, fief_claims
):
    # given
    fake_client = MagicMock()
    fake_client.obtain_access_tokens.return_value = ObtainAccessTokensResponse(
        claims=fief_claims,
        fief_access_token="fief-access-token",
        fief_refresh_token="fief-refresh-token",
    )

    new_user = _fake_user()
    fake_user_manager = MagicMock()
    fake_user_manager.get_or_create.return_value = (new_user, True)

    data = {
        "code": "auth-code-from-fief",
        "state": "opaque-state",
        "saleorApiUrl": "https://shop.example.com/graphql/",
        "channelSlug": "default",
    }

    # when
    with (
        patch.object(plugin, "_get_client", return_value=fake_client),
        patch(
            "saleor.plugins.fief.plugin.User.objects", fake_user_manager
        ),
        patch(
            "saleor.plugins.fief.plugin.create_access_token",
            return_value="saleor.access.jwt",
        ),
        patch(
            "saleor.plugins.fief.plugin.create_refresh_token",
            return_value="saleor.refresh.jwt",
        ),
    ):
        result = plugin.external_obtain_access_tokens(
            data, request_factory, None
        )

    # then
    assert isinstance(result, ExternalAccessTokens)
    assert result.user is new_user
    assert result.token == "saleor.access.jwt"
    assert result.refresh_token == "saleor.refresh.jwt"
    assert result.csrf_token is not None
    assert len(result.csrf_token) > 0

    fake_client.obtain_access_tokens.assert_called_once_with(
        code="auth-code-from-fief",
        state="opaque-state",
        channel_slug="default",
    )
    # Created with claims-shaped defaults.
    args, kwargs = fake_user_manager.get_or_create.call_args
    assert kwargs["email"] == "ada@example.com"
    defaults = kwargs["defaults"]
    assert defaults["first_name"] == "Ada"
    assert defaults["last_name"] == "Lovelace"
    assert defaults["is_active"] is True
    assert defaults["is_confirmed"] is True


def test_external_obtain_access_tokens_reuses_existing_user(
    plugin, request_factory, fief_claims
):
    # given
    existing = _fake_user(email="ada@example.com", pk=99)
    fake_client = MagicMock()
    fake_client.obtain_access_tokens.return_value = ObtainAccessTokensResponse(
        claims=fief_claims,
        fief_access_token="fief-access-token",
        fief_refresh_token=None,
    )
    fake_user_manager = MagicMock()
    fake_user_manager.get_or_create.return_value = (existing, False)

    data = {
        "code": "code",
        "state": "state",
        "saleorApiUrl": "https://shop.example.com/graphql/",
        "channelSlug": "default",
    }

    # when
    with (
        patch.object(plugin, "_get_client", return_value=fake_client),
        patch(
            "saleor.plugins.fief.plugin.User.objects", fake_user_manager
        ),
        patch(
            "saleor.plugins.fief.plugin.create_access_token",
            return_value="saleor.access.jwt",
        ),
        patch(
            "saleor.plugins.fief.plugin.create_refresh_token",
            return_value="saleor.refresh.jwt",
        ),
    ):
        result = plugin.external_obtain_access_tokens(
            data, request_factory, None
        )

    # then
    assert result.user is existing
    fake_user_manager.get_or_create.assert_called_once()


def test_external_obtain_access_tokens_raises_on_missing_code(
    plugin, request_factory
):
    # given
    data = {"state": "abc"}

    # when / then
    with pytest.raises(ValidationError):
        plugin.external_obtain_access_tokens(data, request_factory, None)


def test_external_obtain_access_tokens_returns_previous_value_when_inactive(
    request_factory,
):
    inactive = _make_plugin(active=False)
    sentinel = ExternalAccessTokens(token="prev")
    out = inactive.external_obtain_access_tokens(
        {"code": "c", "state": "s"}, request_factory, sentinel
    )
    assert out is sentinel


# ---------------------------------------------------------------------------
# external_refresh
# ---------------------------------------------------------------------------


def test_external_refresh_re_encodes_jwt_on_success(
    plugin, request_factory, fief_claims
):
    # given
    existing = _fake_user(email="ada@example.com", pk=42)
    fake_client = MagicMock()
    fake_client.refresh.return_value = RefreshResponse(
        claims=fief_claims,
        fief_access_token="new-fief-access",
        fief_refresh_token="new-fief-refresh",
        logout_required=False,
    )
    fake_user_manager = MagicMock()
    fake_user_manager.get_or_create.return_value = (existing, False)

    data = {
        "refreshToken": "old-fief-refresh",
        "saleorApiUrl": "https://shop.example.com/graphql/",
        "channelSlug": "default",
    }

    # when
    with (
        patch.object(plugin, "_get_client", return_value=fake_client),
        patch(
            "saleor.plugins.fief.plugin.User.objects", fake_user_manager
        ),
        patch(
            "saleor.plugins.fief.plugin.create_access_token",
            return_value="new.saleor.access.jwt",
        ),
        patch(
            "saleor.plugins.fief.plugin.create_refresh_token",
            return_value="new.saleor.refresh.jwt",
        ),
    ):
        result = plugin.external_refresh(data, request_factory, None)

    # then
    assert isinstance(result, ExternalAccessTokens)
    assert result.token == "new.saleor.access.jwt"
    assert result.refresh_token == "new.saleor.refresh.jwt"
    assert result.user is existing
    fake_client.refresh.assert_called_once_with(
        refresh_token="old-fief-refresh",
        channel_slug="default",
    )


def test_external_refresh_raises_when_logout_required(
    plugin, request_factory, fief_claims
):
    # given
    fake_client = MagicMock()
    fake_client.refresh.return_value = RefreshResponse(
        claims=fief_claims,
        fief_access_token="",
        fief_refresh_token=None,
        logout_required=True,
    )

    data = {
        "refreshToken": "expired",
        "saleorApiUrl": "https://shop.example.com/graphql/",
        "channelSlug": "default",
    }

    # when / then
    with patch.object(plugin, "_get_client", return_value=fake_client):
        with pytest.raises(ValidationError):
            plugin.external_refresh(data, request_factory, None)


def test_external_refresh_raises_on_missing_refresh_token(plugin, request_factory):
    with pytest.raises(ValidationError):
        plugin.external_refresh({}, request_factory, None)


def test_external_refresh_returns_previous_value_when_inactive(request_factory):
    inactive = _make_plugin(active=False)
    sentinel = ExternalAccessTokens(token="prev")
    out = inactive.external_refresh(
        {"refreshToken": "x"}, request_factory, sentinel
    )
    assert out is sentinel


# ---------------------------------------------------------------------------
# external_logout
# ---------------------------------------------------------------------------


def test_external_logout_returns_empty_dict(plugin, request_factory):
    # given
    fake_client = MagicMock()
    fake_client.logout.return_value = LogoutResponse(ok=True)

    data = {
        "refreshToken": "rt",
        "saleorApiUrl": "https://shop.example.com/graphql/",
        "channelSlug": "default",
    }

    # when
    with patch.object(plugin, "_get_client", return_value=fake_client):
        result = plugin.external_logout(data, request_factory, None)

    # then
    assert result == {}
    fake_client.logout.assert_called_once_with(
        refresh_token="rt",
        channel_slug="default",
    )


def test_external_logout_swallows_client_errors(plugin, request_factory):
    """Logout is best-effort — apps/fief failure must not block storefront."""
    fake_client = MagicMock()
    fake_client.logout.side_effect = RuntimeError("apps/fief unreachable")

    with patch.object(plugin, "_get_client", return_value=fake_client):
        result = plugin.external_logout(
            {"saleorApiUrl": "https://shop.example.com/graphql/"},
            request_factory,
            None,
        )

    assert result == {}


def test_external_logout_returns_previous_value_when_inactive(request_factory):
    inactive = _make_plugin(active=False)
    sentinel = {"prev": True}
    out = inactive.external_logout({}, request_factory, sentinel)
    assert out is sentinel


# ---------------------------------------------------------------------------
# external_verify
# ---------------------------------------------------------------------------


def test_external_verify_returns_user_and_payload_for_owned_token(
    plugin, request_factory
):
    # given
    payload = {
        "owner": FiefPlugin.PLUGIN_ID,
        "email": "ada@example.com",
        "type": "access",
        "token": "user-jwt-secret",
    }
    user = _fake_user()

    data = {"token": "saleor.access.jwt"}

    # when
    with (
        patch(
            "saleor.plugins.fief.plugin.is_owner_of_token_valid",
            return_value=True,
        ),
        patch(
            "saleor.plugins.fief.plugin.jwt_decode", return_value=payload
        ),
        patch(
            "saleor.plugins.fief.plugin.get_user_from_payload",
            return_value=user,
        ),
    ):
        result = plugin.external_verify(data, request_factory, (None, {}))

    # then
    assert result == (user, payload)


def test_external_verify_returns_previous_value_when_token_not_owned(
    plugin, request_factory
):
    sentinel = (None, {"prev": True})
    with patch(
        "saleor.plugins.fief.plugin.is_owner_of_token_valid",
        return_value=False,
    ):
        result = plugin.external_verify(
            {"token": "x"}, request_factory, sentinel
        )
    assert result is sentinel


def test_external_verify_returns_previous_value_when_token_missing(
    plugin, request_factory
):
    sentinel = (None, {"prev": True})
    out = plugin.external_verify({}, request_factory, sentinel)
    assert out is sentinel


def test_external_verify_returns_previous_value_when_inactive(request_factory):
    inactive = _make_plugin(active=False)
    sentinel = (None, {"prev": True})
    out = inactive.external_verify({"token": "x"}, request_factory, sentinel)
    assert out is sentinel
