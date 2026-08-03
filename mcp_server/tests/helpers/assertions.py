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
    """Assert the tool and all of its parameters carry a description."""
    assert (tool.description or "").strip(), (
        f"Tool '{tool.name}' has no description; its docstring is what the model reads"
    )
    properties = (tool.inputSchema or {}).get("properties", {})
    for parameter, schema in properties.items():
        assert schema.get("description"), (
            f"Parameter '{parameter}' of tool '{tool.name}' has no description; "
            "declare it with pydantic Field(description=...)"
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
