"""Tests for the mounted root MCP server.

Reference for later branches: open the client inline with
``async with Client(mcp_root_server)``. FastMCP warns against holding a client in
a fixture because it causes hard-to-diagnose event-loop problems.
"""

from fastmcp import Client

from tests.helpers.assertions import (
    assert_namespaced,
    assert_tool_contract,
    tools_in_namespace,
)


async def test_every_sub_server_contributes_tools(mcp_root_server):
    """Each of the three mounts must expose tools under its own namespace.

    This is the guard against a silent startup failure. ``setup_main_server()``
    wraps each mount in try/except and ``load_all_tools`` swallows per-tool
    construction errors, so a sub-server that registers nothing is still logged as
    "successfully mounted". The `prowler_*` namespace in particular collapses to
    zero tools whenever the API key is missing when the module is first imported.
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
    """Descriptions are the contract a model reads before calling a tool."""
    async with Client(mcp_root_server) as client:
        tools = await client.list_tools()

    for tool in tools:
        assert_tool_contract(tool)


async def test_every_tool_says_whether_it_is_read_only_or_destructive(mcp_root_server):
    """Clients decide whether to ask the user from these hints.

    Left unset, the MCP spec treats a tool as destructive, so a listing would look
    exactly like a deletion.
    """
    async with Client(mcp_root_server) as client:
        tools = {tool.name: tool.annotations for tool in await client.list_tools()}

    for name, annotations in tools.items():
        assert annotations is not None, f"{name} has no annotations"
        assert annotations.readOnlyHint is not None, f"{name} has no readOnlyHint"
        assert annotations.destructiveHint is not None, f"{name} has no destructiveHint"

    destructive = {name for name, a in tools.items() if a.destructiveHint}
    assert destructive == {
        "prowler_create_mute_rule",
        "prowler_update_mute_rule",
        "prowler_set_mutelist",
        "prowler_delete_mutelist",
        "prowler_delete_mute_rule",
        "prowler_delete_provider",
        "prowler_delete_integration",
        "prowler_set_user_role",
    }
    assert tools["prowler_run_attack_paths_query"].readOnlyHint
    assert tools["prowler_hub_list_checks"].readOnlyHint
    assert tools["prowler_docs_search"].readOnlyHint
    assert tools["prowler_get_mutelist"].readOnlyHint
    assert tools["prowler_hub_get_check_code"].readOnlyHint
    assert not tools["prowler_trigger_scan"].readOnlyHint
