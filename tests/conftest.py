from unittest import mock

import pytest

_MOCK_CLASSES = (
    mock.Mock,
    mock.MagicMock,
    mock.AsyncMock,
    mock.NonCallableMock,
    mock.NonCallableMagicMock,
)
_MOCK_CLASS_BASELINE = {cls: frozenset(vars(cls)) for cls in _MOCK_CLASSES}


@pytest.fixture(autouse=True)
def _reset_mock_class_attributes():
    """Drop attributes a test sets on the mock classes themselves (`c = mock.MagicMock; c.provider = ...`), so they cannot leak into other tests' instances."""
    yield
    for cls, baseline in _MOCK_CLASS_BASELINE.items():
        for name in set(vars(cls)) - baseline:
            delattr(cls, name)
