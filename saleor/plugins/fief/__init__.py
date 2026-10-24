"""Fief plugin for Saleor (Path A — opensensor.fief).

Delegates Saleor's `external_*` auth methods to the apps/fief application
over HTTPS, authenticated by HMAC-SHA256 (T58 verifier on the apps side).

Scaffolded by T56; method overrides land in T57.
"""

# PLUGIN_ID must be defined before importing from .plugin, because plugin.py
# imports it back. Mirrors the openid_connect package layout.
PLUGIN_ID = "opensensor.fief"

from .plugin import FiefPlugin  # noqa: E402  (after PLUGIN_ID, on purpose)

__all__ = ["FiefPlugin", "PLUGIN_ID"]
