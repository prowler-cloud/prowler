"""Tests for the server class every sub-server is built from.

These drive a real `ProwlerMCP` through an in-memory MCP client rather than calling
`tool_errors` directly, because applying that wrapper by hand is exactly what this
class exists to make unnecessary. What matters is that a tool registered *any* of the
ways this server registers them ends up with the error contract, and that it keeps the
name, description and schema FastMCP publishes.
"""

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError
from pydantic import Field

from prowler_mcp_server.lib.errors import ProwlerAPIError
from prowler_mcp_server.lib.server import ProwlerMCP


async def call(server: ProwlerMCP, name: str, arguments: dict | None = None):
    """Call a tool the way a client does, without raising on failure."""
    async with Client(server) as client:
        return await client.call_tool(name, arguments or {}, raise_on_error=False)


async def test_the_parameterised_decorator_form_is_wrapped():
    """`@mcp.tool()` -- how the hub and documentation sub-servers register."""
    server = ProwlerMCP("test", mask_error_details=True)

    @server.tool()
    async def failing() -> dict:
        """A tool that fails."""
        raise ProwlerAPIError("boom", 404, method="GET", path="/x")

    result = await call(server, "failing")

    assert result.is_error
    assert result.content[0].text == "GET /x failed with HTTP 404."


async def test_the_bare_decorator_form_is_wrapped():
    """`@mcp.tool` without parentheses is a different code path in FastMCP."""
    server = ProwlerMCP("test", mask_error_details=True)

    @server.tool
    async def failing() -> dict:
        """A tool that fails."""
        raise ProwlerAPIError("boom", 500, method="GET", path="/y")

    result = await call(server, "failing")

    assert result.is_error
    assert "GET /y failed with HTTP 500." in result.content[0].text


async def test_the_direct_call_form_is_wrapped():
    """`mcp.tool(fn)` -- how `BaseTool` auto-registers its methods."""
    server = ProwlerMCP("test", mask_error_details=True)

    async def failing() -> dict:
        """A tool that fails."""
        raise ProwlerAPIError("boom", 403, method="DELETE", path="/z")

    server.tool(failing)

    result = await call(server, "failing")

    assert result.is_error
    assert "DELETE /z failed with HTTP 403." in result.content[0].text


async def test_a_synchronous_tool_is_wrapped():
    """The documentation sub-server registers plain `def` tools."""
    server = ProwlerMCP("test", mask_error_details=True)

    @server.tool()
    def failing() -> dict:
        """A synchronous tool that fails."""
        raise KeyError("attributes")

    result = await call(server, "failing")

    assert result.is_error
    assert "unexpected KeyError" in result.content[0].text


async def test_a_refusal_reaches_the_caller_word_for_word():
    """A `ToolError` is passed through untouched, masking included.

    That is the whole reason refusals are raised as one: the tool already wrote the
    sentence the caller needs, and nothing downstream improves on it.
    """
    server = ProwlerMCP("test", mask_error_details=True)

    @server.tool()
    async def refusing() -> dict:
        """A tool that refuses its arguments."""
        raise ToolError(
            "Date range cannot exceed 2 days. Requested range: 2025-01-01 to "
            "2025-01-10 (10 days)"
        )

    result = await call(server, "refusing")

    assert result.is_error
    assert result.content[0].text == (
        "Date range cannot exceed 2 days. Requested range: 2025-01-01 to "
        "2025-01-10 (10 days)"
    )


async def test_a_result_is_passed_through_untouched():
    server = ProwlerMCP("test")

    @server.tool()
    async def succeeding(value: int) -> dict:
        """A tool that works."""
        return {"value": value}

    result = await call(server, "succeeding", {"value": 3})

    assert not result.is_error
    assert result.data == {"value": 3}


async def test_wrapping_does_not_disturb_the_published_tool():
    """The wrapper must be invisible to FastMCP's schema generation.

    A wrapper that loses the signature takes the parameters with it, and a tool with no
    parameters and no description is unusable while still looking registered.
    """
    server = ProwlerMCP("test")

    @server.tool()
    async def search(
        query: str = Field(description="What to search for"),
        limit: int = Field(default=10, description="How many results"),
    ) -> dict:
        """Search for things."""
        return {"query": query, "limit": limit}

    async with Client(server) as client:
        (tool,) = await client.list_tools()

    assert tool.name == "search"
    assert tool.description == "Search for things."
    properties = tool.inputSchema["properties"]
    assert properties["query"]["description"] == "What to search for"
    assert properties["limit"]["default"] == 10


@pytest.mark.parametrize("name", ["decorated", "direct"])
async def test_every_registration_carries_the_marker(name):
    """The marker is what lets the contract test prove no tool slipped past."""
    server = ProwlerMCP("test")

    async def direct() -> dict:
        """Registered by direct call."""
        return {}

    @server.tool()
    async def decorated() -> dict:
        """Registered by decorator."""
        return {}

    server.tool(direct)

    tool = await server.get_tool(name)
    assert tool is not None, f"{name!r} was not registered at all"
    # `get_tool` is typed as the base `Tool`; only `FunctionTool` carries `fn`.
    assert getattr(getattr(tool, "fn", None), "__prowler_tool_errors__", False)
