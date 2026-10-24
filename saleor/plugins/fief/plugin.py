"""Fief Saleor BasePlugin (T56 scaffold + T57 ``external_*`` overrides).

This plugin delegates Saleor's external authentication flow to the
opensensor apps/fief application over HTTPS, authenticated by HMAC-SHA256
(T58 verifier on the apps/fief side, ``client.py`` signer on this side).

T57 wires the four ``external_*`` overrides + ``external_verify``:

- ``external_authentication_url`` — proxies the storefront's authorize-URL
  request to apps/fief (T18) and returns ``{"authorizationUrl": ...}``.
- ``external_obtain_access_tokens`` — proxies the OAuth code-exchange to
  apps/fief (T19), upserts a Saleor ``User`` from the returned claims, and
  re-encodes the result as a Saleor-issued JWT pair via ``saleor.core.jwt``.
  Saleor signs the access/refresh tokens internally — apps/fief never sees
  Saleor's signing key (T2 spike).
- ``external_refresh`` — proxies the refresh call to apps/fief (T20). If
  apps/fief signals ``logoutRequired`` the storefront must drop the
  session, surfaced here as a ``ValidationError`` (matches OIDC plugin's
  pattern of raising on refresh failure).
- ``external_logout`` — best-effort: tells apps/fief to revoke the Fief
  refresh token (T21), then returns ``{}`` regardless of outcome.
- ``external_verify`` — verifies a token Saleor itself signed (we tagged
  it with ``owner=PLUGIN_ID`` when we issued it). Mirrors the OIDC
  plugin's ``external_verify`` shape so callers get back
  ``(User, decoded_payload)``.
"""

from __future__ import annotations

import logging
import secrets

from django.contrib.auth.hashers import make_password
from django.core.exceptions import ValidationError
from jwt import ExpiredSignatureError, InvalidTokenError

from ...account.models import User
from ...core.jwt import (
    create_access_token,
    create_refresh_token,
    get_user_from_payload,
    jwt_decode,
)
from ..base_plugin import BasePlugin, ExternalAccessTokens
from ..error_codes import PluginErrorCode
from ..openid_connect.utils import is_owner_of_token_valid
from . import PLUGIN_ID
from .client import FiefPluginClient
from .config import FiefPluginConfig
from .manifest import (
    CONFIG_STRUCTURE,
    DEFAULT_CONFIGURATION,
    PLUGIN_DESCRIPTION,
    PLUGIN_NAME,
)

logger = logging.getLogger(__name__)


class FiefPlugin(BasePlugin):
    """Saleor plugin that delegates external auth to apps/fief over HTTPS."""

    PLUGIN_ID = PLUGIN_ID
    PLUGIN_NAME = PLUGIN_NAME
    PLUGIN_DESCRIPTION = PLUGIN_DESCRIPTION
    DEFAULT_CONFIGURATION = DEFAULT_CONFIGURATION
    CONFIG_STRUCTURE = CONFIG_STRUCTURE
    CONFIGURATION_PER_CHANNEL = False
    DEFAULT_ACTIVE = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        configuration = {item["name"]: item["value"] for item in self.configuration}
        self.config = FiefPluginConfig(
            apps_fief_base_url=configuration.get("apps_fief_base_url") or "",
            hmac_secret=configuration.get("hmac_secret") or "",
            default_connection_id=configuration.get("default_connection_id"),
        )
        # Defer client instantiation until the plugin is actually configured;
        # this keeps ``manage.py check`` and the dashboard plugin list happy
        # even when the operator has not yet filled in the Fief endpoints.
        self._client: FiefPluginClient | None = None

    # ------------------------------------------------------------------
    # client + helpers
    # ------------------------------------------------------------------

    def _get_client(self, *, saleor_api_url: str) -> FiefPluginClient:
        """Return the HMAC-signing HTTP client for this plugin instance.

        Cached per plugin instance because Saleor instantiates plugins per
        request; the cached client is keyed implicitly by the first
        ``saleor_api_url`` it was built with, which is fine because the
        plugin manager creates a new ``FiefPlugin`` per ``saleorApiUrl``
        anyway.
        """
        if not self.config.apps_fief_base_url or not self.config.hmac_secret:
            raise RuntimeError(
                "FiefPlugin is not fully configured: apps_fief_base_url and "
                "hmac_secret must both be set."
            )
        if self._client is None:
            self._client = FiefPluginClient(
                base_url=self.config.apps_fief_base_url,
                hmac_secret=self.config.hmac_secret,
                saleor_api_url=saleor_api_url,
                default_connection_id=self.config.default_connection_id,
            )
        return self._client

    @staticmethod
    def _get_or_create_user(claims: dict) -> User:
        """Look up (or create) the Saleor ``User`` for a Fief claims payload.

        Mirrors the OIDC plugin's ``get_or_create_user_from_payload`` but
        consumes the T55-shaped claims dict that apps/fief returns
        (``email``, ``firstName``, ``lastName``, ...).

        - ``is_active=True``, ``is_confirmed=True`` for newly-created users
          (Saleor treats Fief-authenticated users as confirmed by default,
          identical to the OIDC plugin's behavior).
        - Names are projected from ``firstName`` / ``lastName`` claims when
          present; missing values fall back to empty strings (the User
          model's ``CharField(blank=True)`` default).
        - ``password`` is set to an unusable hash so the user cannot log in
          via Saleor's local password flow — Fief is the only auth path.
        """
        email = claims.get("email")
        if not email:
            raise ValidationError(
                {
                    "email": ValidationError(
                        "Missing email in Fief claims.",
                        code=PluginErrorCode.NOT_FOUND.value,
                    )
                }
            )
        defaults = {
            "is_active": bool(claims.get("isActive", True)),
            "is_confirmed": True,
            "email": email,
            "first_name": claims.get("firstName") or "",
            "last_name": claims.get("lastName") or "",
            "password": make_password(None),
        }
        user, _created = User.objects.get_or_create(email=email, defaults=defaults)
        return user

    def _build_external_access_tokens(self, user: User) -> ExternalAccessTokens:
        """Encode Saleor-side JWT pair tagged with this plugin's owner.

        ``create_access_token`` / ``create_refresh_token`` use Saleor's
        configured RSA key (``saleor.core.jwt_manager``), so the resulting
        token verifies against ``/.well-known/jwks.json`` exactly like a
        natively-issued Saleor token.
        """
        return ExternalAccessTokens(
            token=create_access_token(user),
            refresh_token=create_refresh_token(user),
            csrf_token=secrets.token_hex(32),
            user=user,
        )

    # ------------------------------------------------------------------
    # BasePlugin overrides
    # ------------------------------------------------------------------

    def external_authentication_url(
        self, data: dict, request, previous_value
    ) -> dict:
        if not self.active:
            return previous_value

        redirect_uri = data.get("redirectUri")
        if not redirect_uri:
            raise ValidationError(
                {
                    "redirectUri": ValidationError(
                        "Missing required field - redirectUri",
                        code=PluginErrorCode.NOT_FOUND.value,
                    )
                }
            )

        saleor_api_url = data.get("saleorApiUrl") or ""
        client = self._get_client(saleor_api_url=saleor_api_url)
        response = client.authentication_url(
            redirect_uri=redirect_uri,
            saleor_user_id=data.get("saleorUserId"),
            channel_slug=data.get("channelSlug"),
        )
        return {"authorizationUrl": response.authorization_url}

    def external_obtain_access_tokens(
        self, data: dict, request, previous_value
    ) -> ExternalAccessTokens:
        if not self.active:
            return previous_value

        code = data.get("code")
        if not code:
            raise ValidationError(
                {
                    "code": ValidationError(
                        "Missing required field - code",
                        code=PluginErrorCode.NOT_FOUND.value,
                    )
                }
            )
        state = data.get("state")
        if not state:
            raise ValidationError(
                {
                    "state": ValidationError(
                        "Missing required field - state",
                        code=PluginErrorCode.NOT_FOUND.value,
                    )
                }
            )

        saleor_api_url = data.get("saleorApiUrl") or ""
        client = self._get_client(saleor_api_url=saleor_api_url)
        response = client.obtain_access_tokens(
            code=code,
            state=state,
            channel_slug=data.get("channelSlug"),
        )

        user = self._get_or_create_user(response.claims)
        return self._build_external_access_tokens(user)

    def external_refresh(
        self, data: dict, request, previous_value
    ) -> ExternalAccessTokens:
        if not self.active:
            return previous_value

        refresh_token = data.get("refreshToken")
        if not refresh_token:
            raise ValidationError(
                {
                    "refreshToken": ValidationError(
                        "Missing required field - refreshToken",
                        code=PluginErrorCode.NOT_FOUND.value,
                    )
                }
            )

        saleor_api_url = data.get("saleorApiUrl") or ""
        client = self._get_client(saleor_api_url=saleor_api_url)
        response = client.refresh(
            refresh_token=refresh_token,
            channel_slug=data.get("channelSlug"),
        )

        if response.logout_required:
            # apps/fief signaled the storefront must drop the session.
            # OIDC plugin uses the same shape: refresh failures surface as
            # a ValidationError so the GraphQL layer turns it into a
            # standard auth-error response.
            raise ValidationError(
                {
                    "refreshToken": ValidationError(
                        "Unable to refresh the token. Logout required.",
                        code=PluginErrorCode.INVALID.value,
                    )
                }
            )

        user = self._get_or_create_user(response.claims)
        return self._build_external_access_tokens(user)

    def external_logout(self, data: dict, request, previous_value):
        if not self.active:
            return previous_value

        saleor_api_url = data.get("saleorApiUrl") or ""
        try:
            client = self._get_client(saleor_api_url=saleor_api_url)
            client.logout(
                refresh_token=data.get("refreshToken"),
                channel_slug=data.get("channelSlug"),
            )
        except Exception:
            # Logout is best-effort. Saleor must finish logging the user
            # out locally even if apps/fief / Fief itself is unreachable.
            logger.warning("Fief logout failed; ignoring.", exc_info=True)
        return {}

    def external_verify(
        self, data: dict, request, previous_value
    ) -> tuple[User | None, dict]:
        if not self.active:
            return previous_value

        token = data.get("token")
        if not token:
            return previous_value
        if not is_owner_of_token_valid(token, owner=self.PLUGIN_ID):
            return previous_value
        try:
            payload = jwt_decode(token)
            user = get_user_from_payload(payload)
            if not user:
                return previous_value
        except (ExpiredSignatureError, InvalidTokenError) as exc:
            raise ValidationError({"token": exc}) from exc
        return user, payload
