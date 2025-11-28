from fastmcp import FastMCP
from prowler_mcp_server.prowler_app.utils.tool_loader import load_all_tools

# Initialize MCP server
app_mcp_server = FastMCP("prowler-app")

# Auto-discover and load all tools from the tools package
load_all_tools(app_mcp_server)
