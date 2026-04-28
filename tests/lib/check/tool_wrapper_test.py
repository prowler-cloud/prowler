"""Unit tests for prowler.lib.check.tool_wrapper.

Covers the leaf helper directly (Provider.is_tool_wrapper_provider delegates
to it). Tests the frozenset fast path, the entry-point fallback for external
plug-ins, the broken-plug-in path, the no-match path, and the module-level
cache.
"""

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def _clear_ep_class_cache():
    """Reset the leaf module's cache between tests so they stay independent."""
    from prowler.lib.check import tool_wrapper

    tool_wrapper._ep_class_cache.clear()
    yield
    tool_wrapper._ep_class_cache.clear()


def _make_entry_point(name, cls):
    """Create a mock entry point whose `load()` returns `cls`."""
    ep = MagicMock()
    ep.name = name
    ep.load.return_value = cls
    return ep


class TestIsToolWrapperProvider:
    """is_tool_wrapper_provider: frozenset + entry-point fallback."""

    @pytest.mark.parametrize("name", ["iac", "llm", "image"])
    def test_returns_true_for_builtin_tool_wrappers(self, name):
        from prowler.lib.check.tool_wrapper import is_tool_wrapper_provider

        assert is_tool_wrapper_provider(name) is True

    @pytest.mark.parametrize("name", ["aws", "azure", "gcp", "github", "kubernetes"])
    def test_returns_false_for_regular_builtins(self, name):
        from prowler.lib.check.tool_wrapper import is_tool_wrapper_provider

        assert is_tool_wrapper_provider(name) is False

    @patch("prowler.lib.check.tool_wrapper.importlib.metadata.entry_points")
    def test_returns_true_for_external_plugin_with_flag(self, mock_eps):
        from prowler.lib.check.tool_wrapper import is_tool_wrapper_provider

        cls = MagicMock(is_external_tool_provider=True)
        mock_eps.return_value = [_make_entry_point("custom_wrapper", cls)]

        assert is_tool_wrapper_provider("custom_wrapper") is True

    @patch("prowler.lib.check.tool_wrapper.importlib.metadata.entry_points")
    def test_returns_false_for_external_plugin_without_flag(self, mock_eps):
        from prowler.lib.check.tool_wrapper import is_tool_wrapper_provider

        cls = MagicMock(is_external_tool_provider=False)
        mock_eps.return_value = [_make_entry_point("vanilla_external", cls)]

        assert is_tool_wrapper_provider("vanilla_external") is False

    @patch("prowler.lib.check.tool_wrapper.importlib.metadata.entry_points")
    def test_returns_false_for_unknown_provider(self, mock_eps):
        from prowler.lib.check.tool_wrapper import is_tool_wrapper_provider

        mock_eps.return_value = []

        assert is_tool_wrapper_provider("does-not-exist") is False


class TestLoadEpClass:
    """_load_ep_class: cache, broken plug-ins, no-match."""

    @patch("prowler.lib.check.tool_wrapper.importlib.metadata.entry_points")
    def test_caches_result_across_calls(self, mock_eps):
        from prowler.lib.check.tool_wrapper import _load_ep_class

        cls = MagicMock(is_external_tool_provider=True)
        mock_eps.return_value = [_make_entry_point("cached_one", cls)]

        first = _load_ep_class("cached_one")
        second = _load_ep_class("cached_one")

        assert first is cls
        assert second is cls
        # entry_points consulted only on the first call
        assert mock_eps.call_count == 1

    @patch("prowler.lib.check.tool_wrapper.importlib.metadata.entry_points")
    def test_returns_none_for_broken_plugin(self, mock_eps):
        from prowler.lib.check.tool_wrapper import _load_ep_class

        broken_ep = MagicMock()
        broken_ep.name = "broken"
        broken_ep.load.side_effect = ImportError("plug-in is broken")
        mock_eps.return_value = [broken_ep]

        assert _load_ep_class("broken") is None

    @patch("prowler.lib.check.tool_wrapper.importlib.metadata.entry_points")
    def test_returns_none_when_no_entry_point_matches(self, mock_eps):
        from prowler.lib.check.tool_wrapper import _load_ep_class

        cls = MagicMock()
        mock_eps.return_value = [_make_entry_point("other_provider", cls)]

        assert _load_ep_class("missing_provider") is None
