"""Typed configuration for the Fief Saleor plugin (T56)."""

from dataclasses import dataclass


@dataclass
class FiefPluginConfig:
    """Settings for the Fief plugin's HTTP client.

    Attributes:
        apps_fief_base_url: Base URL of the apps/fief deployment (the Next.js
            app handling T18-T21 endpoints). Trailing slash optional; the
            client normalizes it.
        hmac_secret: Shared secret used to sign requests to apps/fief (T58
            on the apps side verifies these). Stored using Saleor's SECRET
            configuration type so the value is encrypted at rest by Saleor's
            standard plugin-config encryption path.
        default_connection_id: Optional connection identifier sent on every
            request via the X-Fief-Plugin-Connection header. Channels that
            need a different connection can override per call (T57).

    """

    apps_fief_base_url: str
    hmac_secret: str
    default_connection_id: str | None = None
