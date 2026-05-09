"""Fief BasePlugin scaffold (T56).

This task scopes to the loadable scaffolding only:
- registers under PLUGIN_ID = "opensensor.fief"
- exposes the configuration schema apps/fief integrators will fill in
- materializes a typed FiefPluginConfig + FiefPluginClient on init

The four ``external_*`` method overrides land in T57. Until then the
inherited BasePlugin methods are used (each one is a no-op that returns
``previous_value`` per BasePlugin's contract), so loading this plugin
without configuring the apps/fief endpoint will not break Saleor's
authentication path — Saleor just falls through to the next plugin.
"""

from __future__ import annotations

import logging

from ..base_plugin import BasePlugin
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
    """Saleor plugin that delegates external auth to apps/fief over HTTPS.

    Method overrides for ``external_authentication_url``,
    ``external_obtain_access_tokens``, ``external_refresh``,
    ``external_logout`` are intentionally omitted at this scaffold stage
    (T56). Calling them on this plugin returns the inherited no-op result
    so the plugin can be installed and configured before T57 lands the
    real handlers.
    """

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
        # this keeps `manage.py check` and the dashboard plugin list happy
        # even when the operator has not yet filled in the Fief endpoints.
        self._client: FiefPluginClient | None = None

    # ------------------------------------------------------------------
    # helper used by T57 once it lands; safe to call now too
    # ------------------------------------------------------------------

    def _get_client(self, *, saleor_api_url: str) -> FiefPluginClient:
        """Return the HMAC-signing HTTP client for this plugin instance.

        T57 will call this from each ``external_*`` override. Cached per
        plugin instance because Saleor instantiates plugins per request.
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
