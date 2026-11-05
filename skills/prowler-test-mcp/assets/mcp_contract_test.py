# Example: Prowler MCP Server contract test patterns
# Source: mcp_server/tests/test_server.py

from fastmcp import Client
from tests.helpers.assertions import (
    assert_namespaced,
    assert_tool_contract,
    tools_in_namespace,
)


async def test_every_sub_server_contributes_tools(mcp_root_server):
    """Guard against a silent startup failure.

    `setup_main_server()` wraps each mount in try/except and `load_all_tools`
    swallows per-tool construction errors, so a sub-server that registers nothing
    is still logged as "successfully mounted". Assert each namespace is non-empty
    -- never assert an exact count, which every future branch would have to bump.
    """
    async with Client(mcp_root_server) as client:
        tools = await client.list_tools()

    assert tools_in_namespace(tools, "prowler_hub_"), "Prowler Hub registered no tools"
    assert tools_in_namespace(tools, "prowler_docs_"), (
        "Prowler Docs registered no tools"
    )
    assert tools_in_namespace(tools, "prowler_"), "Prowler App registered no tools"


async def test_every_tool_is_namespaced(mcp_root_server):
    """Tool names are a published interface; nothing may escape the namespaces."""
    async with Client(mcp_root_server) as client:
        tools = await client.list_tools()

    for tool in tools:
        assert_namespaced(tool)


async def test_every_tool_and_parameter_is_described(mcp_root_server):
    """Descriptions are the contract a model reads before calling a tool.

    A tool or parameter with no description is registered but effectively
    invisible, so this is a correctness check rather than a style one.
    """
    async with Client(mcp_root_server) as client:
        tools = await client.list_tools()

    for tool in tools:
        assert_tool_contract(tool)
