from fastmcp import FastMCP


# Initialize main Prowler MCP server
prowler_mcp_server = FastMCP("prowler-mcp-server")


async def setup_main_server():
    """Set up the main Prowler MCP server with all available integrations."""

    # Import Prowler Hub tools with prowler_hub_ prefix
    try:
        from prowler_mcp_server.prowler_hub.server import hub_mcp_server

        await prowler_mcp_server.import_server(hub_mcp_server, prefix="prowler_hub")
    except Exception:
        # TODO: Add error logging
        pass
