import os

from fastmcp import FastMCP
from prowler_mcp_server.lib.logger import logger
from starlette.responses import JSONResponse


async def setup_main_server(transport: str) -> FastMCP:
    """Set up the main Prowler MCP server with all available integrations."""

    # Initialize main Prowler MCP server
    prowler_mcp_server = FastMCP("prowler-mcp-server")

    # Import Prowler Hub tools with prowler_hub_ prefix
    try:
        logger.info("Importing Prowler Hub server...")
        from prowler_mcp_server.prowler_hub.server import hub_mcp_server

        await prowler_mcp_server.import_server(hub_mcp_server, prefix="prowler_hub")
        logger.info("Successfully imported Prowler Hub server")
    except Exception as e:
        logger.error(f"Failed to import Prowler Hub server: {e}")

    try:
        logger.info("Importing Prowler App server...")

        if os.getenv("PROWLER_MCP_MODE", None) is None:
            os.environ["PROWLER_MCP_MODE"] = transport

        if not os.path.exists(
            os.path.join(os.path.dirname(__file__), "prowler_app", "server.py")
        ):
            from prowler_mcp_server.prowler_app.utils.server_generator import (
                generate_server_file,
            )

            logger.info("Prowler App server not found, generating...")
            generate_server_file()

        from prowler_mcp_server.prowler_app.server import app_mcp_server

        await prowler_mcp_server.import_server(app_mcp_server, prefix="prowler_app")
        logger.info("Successfully imported Prowler App server")
    except Exception as e:
        logger.error(f"Failed to import Prowler App server: {e}")

    try:
        logger.info("Importing Prowler Documentation server...")
        from prowler_mcp_server.prowler_documentation.server import docs_mcp_server

        await prowler_mcp_server.import_server(docs_mcp_server, prefix="prowler_docs")
        logger.info("Successfully imported Prowler Documentation server")
    except Exception as e:
        logger.error(f"Failed to import Prowler Documentation server: {e}")

    # Add health check endpoint
    @prowler_mcp_server.custom_route("/health", methods=["GET"])
    async def health_check(request):
        return JSONResponse({"status": "healthy", "service": "prowler-mcp-server"})

    return prowler_mcp_server
