"""Saleor plugin manifest for the Fief plugin (T56).

Defines the metadata Saleor's plugin loader and dashboard plugin form
need: the human-readable name, description, default values for each
configuration field, and the form schema (label, help text, type).
"""

from ..base_plugin import ConfigurationTypeField

PLUGIN_NAME = "Fief Auth"
PLUGIN_DESCRIPTION = (
    "Delegates Saleor's external authentication flow to the Fief identity "
    "provider via the opensensor apps/fief application. Calls are signed "
    "with a shared HMAC-SHA256 secret. See task T56/T57."
)
PLUGIN_VERSION = "0.1.0"

DEFAULT_CONFIGURATION = [
    {"name": "apps_fief_base_url", "value": None},
    {"name": "hmac_secret", "value": None},
    {"name": "default_connection_id", "value": None},
]

CONFIG_STRUCTURE = {
    "apps_fief_base_url": {
        "type": ConfigurationTypeField.STRING,
        "help_text": (
            "Base URL of the apps/fief deployment that exposes the "
            "external-authentication-url, external-obtain-access-tokens, "
            "external-refresh, and external-logout HTTPS endpoints."
        ),
        "label": "apps/fief base URL",
    },
    "hmac_secret": {
        "type": ConfigurationTypeField.SECRET,
        "help_text": (
            "Shared HMAC-SHA256 secret used to sign requests to apps/fief. "
            "Must match the secret configured on the apps/fief side (T58 "
            "verifier). Rotate by deploying the new secret to apps/fief "
            "with both old and new values accepted, then updating Saleor."
        ),
        "label": "HMAC shared secret",
    },
    "default_connection_id": {
        "type": ConfigurationTypeField.STRING,
        "help_text": (
            "Optional connection ID sent on every request to apps/fief. "
            "Selects which Fief tenant/client to use when the channel "
            "does not provide a more specific override."
        ),
        "label": "Default connection ID (optional)",
    },
}
