"""Assertions for the MCP tool contract every sub-server must honour.

A tool's description and its parameter descriptions are not documentation -- they
are the only thing a model sees when deciding whether and how to call it. A tool
that registers without them is invisible in practice, so these are correctness
assertions rather than style ones.
"""

from mcp.types import Tool

# Mounted namespaces, most specific first so prefix matching is unambiguous.
NAMESPACES = ("prowler_hub_", "prowler_docs_", "prowler_")


def assert_tool_contract(tool: Tool) -> None:
    """Assert the tool and all of its parameters carry a usable description.

    Missing and blank are asserted separately because they are different
    mistakes: a missing description was never written, a blank one exists but was
    left empty. One truthiness check would report both the same way.
    """
    assert tool.description is not None, (
        f"Tool '{tool.name}' has no description. Its docstring is what the model reads."
    )
    assert tool.description.strip(), (
        f"Tool '{tool.name}' has a blank description. "
        "Its docstring is what the model reads."
    )

    # `inputSchema` is a required field of the MCP Tool type, so it is always a
    # dict; a tool that takes no arguments simply has no `properties`.
    for parameter, schema in tool.inputSchema.get("properties", {}).items():
        description = schema.get("description")
        assert description is not None, (
            f"Parameter '{parameter}' of tool '{tool.name}' has no description. "
            "Declare it with pydantic Field(description=...)."
        )
        assert description.strip(), (
            f"Parameter '{parameter}' of tool '{tool.name}' has a blank description. "
            "Declare it with pydantic Field(description=...)."
        )


def assert_namespaced(tool: Tool) -> None:
    """Assert the tool is reachable under one of the published namespaces."""
    assert tool.name.startswith(NAMESPACES), (
        f"Tool '{tool.name}' is outside the published namespaces {NAMESPACES}"
    )


def tools_in_namespace(tools: list[Tool], namespace: str) -> list[Tool]:
    """Return the tools in a namespace.

    ``prowler_`` is a prefix of the other two namespaces, so tools belonging to a
    more specific one are excluded rather than counted twice.
    """
    more_specific = tuple(
        other
        for other in NAMESPACES
        if other != namespace and other.startswith(namespace)
    )
    return [
        tool
        for tool in tools
        if tool.name.startswith(namespace) and not tool.name.startswith(more_specific)
    ]
