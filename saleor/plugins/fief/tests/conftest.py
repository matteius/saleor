"""Local conftest for fief plugin tests.

The T56 unit tests are pure-Python (HMAC, dataclasses, request shape via
mocked sessions) and do not need a live Postgres instance. The Saleor root
conftest pulls in autouse fixtures that exercise the DB; override the
relevant pytest-django machinery here so the scaffold tests can run on a
fresh checkout without a Postgres credential.

Tests that genuinely need the DB will land with T57's full integration
tests.
"""

import pytest


@pytest.fixture(scope="session")
def django_db_setup():  # noqa: PT004 — pytest-django fixture override
    """No-op DB setup for fief plugin scaffold tests."""
    return


@pytest.fixture(autouse=True)
def _django_db_helper(request):  # noqa: PT004 — pytest-django override
    """Skip DB transaction wrapping; T56 scaffold tests don't touch DB."""
    return


@pytest.fixture(scope="session")
def initialize_test_telemetry():
    """Stub out OpenTelemetry init for these scaffold tests."""
    return


@pytest.fixture(autouse=True)
def clear_telemetry_data(initialize_test_telemetry):  # noqa: PT004
    """No-op replacement for the saleor-wide telemetry-clearing autouse."""
    return


@pytest.fixture(scope="session", autouse=True)
def private_media_root(tmpdir_factory):
    return str(tmpdir_factory.mktemp("private-media"))


@pytest.fixture(autouse=True)
def private_media_setting(private_media_root, settings):
    settings.PRIVATE_MEDIA_ROOT = private_media_root
    return private_media_root


# The fixtures below shadow saleor-wide autouse fixtures that touch the DB
# (default_tax_class, site_settings). Returning ``None`` is fine — the T56
# scaffold tests only care about pure-Python behavior.


@pytest.fixture(autouse=True)
def default_tax_class():  # noqa: PT004
    return None


@pytest.fixture(autouse=True)
def site_settings(settings):  # noqa: PT004
    return None
