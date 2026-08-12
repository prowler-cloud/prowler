"""The FastMCP subclass every Prowler sub-server is built from."""

from typing import Any

from fastmcp import FastMCP

from prowler_mcp_server.lib.errors import tool_errors


class ProwlerMCP(FastMCP):
    """A FastMCP server whose tools all report failures the same way.

    `FastMCP.tool()` is the single funnel every registration goes through -- the
    `@server.tool()` and bare `@server.tool` decorator forms, and the direct
    `mcp.tool(fn)` call `BaseTool` uses to auto-register -- so applying
    `tool_errors` here covers all of them at once.

    It is applied here rather than by hand because forgetting it is silent and
    expensive: every server sets `mask_error_details=True`, so an unwrapped tool
    answers `Error calling tool 'x'` and nothing else. Nothing about the tool looks
    wrong, and the schema, the name and the description are all still correct.
    """

    def tool(self, name_or_fn: Any = None, **kwargs: Any) -> Any:
        """Register a tool, wrapped so its failures reach the client as `ToolError`."""
        if callable(name_or_fn):
            # Direct call: mcp.tool(fn), or the bare @mcp.tool decorator.
            return super().tool(tool_errors(name_or_fn), **kwargs)

        # Parameterised decorator: @mcp.tool() or @mcp.tool(name="..."). FastMCP hands
        # back the decorator that does the registering, so the wrap goes in front of it.
        register = super().tool(name_or_fn, **kwargs)

        def decorator(fn: Any) -> Any:
            return register(tool_errors(fn))

        return decorator
