"""Plugin scaffolding tests for T56.

The actual `external_*` method overrides land in T57. Here we only verify
that the plugin imports, exposes the right metadata, and can be added to
Saleor's BUILTIN_PLUGINS list (i.e. its dotted path resolves and the class
inherits from BasePlugin).
"""

import importlib

from ...base_plugin import BasePlugin
from .. import PLUGIN_ID, FiefPlugin


def test_fief_plugin_is_a_base_plugin_subclass():
    assert issubclass(FiefPlugin, BasePlugin)


def test_fief_plugin_id_constant_matches_module_export():
    assert FiefPlugin.PLUGIN_ID == PLUGIN_ID == "opensensor.fief"


def test_fief_plugin_dotted_path_resolves():
    # Mirrors the pattern Saleor uses to load BUILTIN_PLUGINS in settings.py:
    # "saleor.plugins.fief.plugin.FiefPlugin" must import cleanly.
    module = importlib.import_module("saleor.plugins.fief.plugin")
    assert getattr(module, "FiefPlugin") is FiefPlugin


def test_fief_plugin_default_configuration_is_a_list_of_dicts():
    # Saleor's plugin loader iterates DEFAULT_CONFIGURATION expecting
    # {"name": ..., "value": ...} entries.
    for entry in FiefPlugin.DEFAULT_CONFIGURATION:
        assert "name" in entry
        assert "value" in entry


def test_fief_plugin_has_config_structure_for_every_default():
    default_keys = {e["name"] for e in FiefPlugin.DEFAULT_CONFIGURATION}
    structure_keys = set(FiefPlugin.CONFIG_STRUCTURE.keys())
    assert default_keys == structure_keys
