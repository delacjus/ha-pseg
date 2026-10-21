"""Pytest fixtures for PSE&G integration tests."""

import pytest

# Fix Python 3.14 inspect.signature annotation issue in HA 2026.10.2 recorder migration
try:
    import homeassistant.components.recorder.core
    import homeassistant.components.recorder.migration

    homeassistant.components.recorder.migration.Recorder = (
        homeassistant.components.recorder.core.Recorder
    )
except Exception:
    pass

# Python 3.14 evaluates annotations lazily; helpers.recorder only imports Session under
# TYPE_CHECKING, so recorder-backed tests (recorder_mock) fail resolving it. Bind it.
try:
    import homeassistant.helpers.recorder as _helpers_recorder
    from sqlalchemy.orm import Session as _SqlaSession

    _helpers_recorder.Session = _SqlaSession
except Exception:
    pass


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    """Enable custom integrations for all tests."""
    yield
