"""Tests for ``BaseTool``, the abstract base every tool class inherits from.

Every one of the 12 tool classes registers its tools by inheriting
``register_tools()`` rather than implementing it, so a regression here would
silently change which methods become MCP tools across the entire server. The
mechanism is reflection-based (``inspect.getmembers``), which is easy to get
subtly wrong (registering a private helper, a property, or a sync method), so
each exclusion rule gets its own test.
"""

from prowler_mcp_server.prowler_app.tools.base import BaseTool


class _FakeMCP:
    """Records every method handed to ``.tool()``, standing in for FastMCP."""

    def __init__(self) -> None:
        self.registered: list = []

    def tool(self, method) -> None:
        self.registered.append(method)


class _SampleTools(BaseTool):
    """A tool class exercising every branch ``register_tools`` must handle."""

    async def public_async_tool(self) -> str:
        """A public coroutine method: this is the only thing that gets registered."""
        return "public"

    async def _private_async_helper(self) -> str:
        """Leading underscore: an implementation detail, not a tool."""
        return "private"

    def public_sync_method(self) -> str:
        """Public but synchronous: FastMCP tools must be coroutines."""
        return "sync"


def test_only_public_coroutine_methods_are_registered():
    """The one method that is both public and async is the only tool."""
    mcp = _FakeMCP()
    tools = _SampleTools()

    tools.register_tools(mcp)

    assert mcp.registered == [tools.public_async_tool]


def test_private_methods_are_never_registered():
    """A leading underscore marks an implementation detail, not a tool."""
    mcp = _FakeMCP()
    tools = _SampleTools()

    tools.register_tools(mcp)

    assert tools._private_async_helper not in mcp.registered


def test_synchronous_methods_are_never_registered():
    """FastMCP tools must be coroutines; a sync method would break at call time."""
    mcp = _FakeMCP()
    tools = _SampleTools()

    tools.register_tools(mcp)

    assert tools.public_sync_method not in mcp.registered


def test_the_shared_properties_are_never_registered_as_tools():
    """``api_client`` and ``logger`` are inherited properties, not tools.

    ``inspect.getmembers`` with ``predicate=inspect.ismethod`` does not surface
    properties as methods in the first place, but the explicit skip list in
    ``register_tools`` is what protects this if that ever changes -- so it is
    worth asserting on directly rather than trusting the predicate alone.
    """
    mcp = _FakeMCP()
    tools = _SampleTools()

    tools.register_tools(mcp)

    registered_names = [method.__name__ for method in mcp.registered]
    assert "api_client" not in registered_names
    assert "logger" not in registered_names


def test_a_tool_class_with_no_public_coroutines_registers_nothing():
    """An edge case: nothing to register must not raise."""

    class _EmptyTools(BaseTool):
        def sync_only(self) -> None:
            pass

    mcp = _FakeMCP()
    _EmptyTools().register_tools(mcp)

    assert mcp.registered == []


def test_base_tool_shares_the_api_client_singleton():
    """Every tool must talk to the same client, since ``mock_api_client`` patches
    the singleton in place rather than injecting a client per tool."""
    from prowler_mcp_server.prowler_app.utils.api_client import ProwlerAPIClient

    tools = _SampleTools()

    assert isinstance(tools.api_client, ProwlerAPIClient)
    assert tools.api_client is ProwlerAPIClient()


def test_base_tool_exposes_a_logger():
    tools = _SampleTools()

    assert tools.logger is not None
