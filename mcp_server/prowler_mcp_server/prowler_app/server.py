from prowler_mcp_server.lib.server import ProwlerMCP
from prowler_mcp_server.prowler_app.utils.tool_loader import load_all_tools

# Initialize MCP server
app_mcp_server = ProwlerMCP("prowler-app", mask_error_details=True)

# Auto-discover and load all tools from the tools package
load_all_tools(app_mcp_server)
