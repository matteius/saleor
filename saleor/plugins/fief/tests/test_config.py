"""Config + manifest unit tests for the Fief plugin scaffold (T56)."""

from .. import PLUGIN_ID
from ..config import FiefPluginConfig
from ..manifest import (
    CONFIG_STRUCTURE,
    DEFAULT_CONFIGURATION,
    PLUGIN_DESCRIPTION,
    PLUGIN_NAME,
)


def test_plugin_id_is_namespaced():
    # Path A pivot: id locked to opensensor.fief; do not change without
    # also updating the apps/fief side and migrations of plugin config rows.
    assert PLUGIN_ID == "opensensor.fief"


def test_plugin_manifest_has_required_metadata():
    assert PLUGIN_NAME
    assert PLUGIN_DESCRIPTION


def test_default_configuration_keys():
    keys = {entry["name"] for entry in DEFAULT_CONFIGURATION}
    assert "apps_fief_base_url" in keys
    assert "hmac_secret" in keys
    assert "default_connection_id" in keys


def test_config_structure_has_all_keys_with_types():
    # Each key in DEFAULT_CONFIGURATION must have a matching entry in
    # CONFIG_STRUCTURE (Saleor's plugin form generator requires this).
    default_keys = {entry["name"] for entry in DEFAULT_CONFIGURATION}
    structure_keys = set(CONFIG_STRUCTURE.keys())
    assert default_keys == structure_keys


def test_hmac_secret_marked_as_secret_type():
    # The HMAC secret must use the SECRET configuration type so Saleor's
    # admin UI masks it and the encrypted-at-rest path is used.
    assert CONFIG_STRUCTURE["hmac_secret"]["type"] == "Secret"


def test_fief_plugin_config_dataclass_round_trip():
    cfg = FiefPluginConfig(
        apps_fief_base_url="https://apps.fief.example.com",
        hmac_secret="s3cret",
        default_connection_id="conn_abc",
    )
    assert cfg.apps_fief_base_url == "https://apps.fief.example.com"
    assert cfg.hmac_secret == "s3cret"
    assert cfg.default_connection_id == "conn_abc"


def test_fief_plugin_config_default_connection_id_optional():
    cfg = FiefPluginConfig(
        apps_fief_base_url="https://apps.fief.example.com",
        hmac_secret="s3cret",
    )
    assert cfg.default_connection_id is None
