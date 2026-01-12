import asyncio

from fastmcp import FastMCP
from prowler_mcp_server import __version__
from prowler_mcp_server.lib.logger import logger
from starlette.responses import JSONResponse

prowler_mcp_server = FastMCP("prowler-mcp-server")


async def setup_main_server():
    """Set up the main Prowler MCP server with all available integrations."""
    # Import Prowler Hub tools with prowler_hub_ prefix
    try:
        logger.info("Importing Prowler Hub server...")
        from prowler_mcp_server.prowler_hub.server import hub_mcp_server

        await prowler_mcp_server.import_server(hub_mcp_server, prefix="prowler_hub")
        logger.info("Successfully imported Prowler Hub server")
    except Exception as e:
        logger.error(f"Failed to import Prowler Hub server: {e}")

    # Import Prowler App tools with prowler_app_ prefix
    try:
        logger.info("Importing Prowler App server...")
        from prowler_mcp_server.prowler_app.server import app_mcp_server

        await prowler_mcp_server.import_server(app_mcp_server, prefix="prowler_app")
        logger.info("Successfully imported Prowler App server")
    except Exception as e:
        logger.error(f"Failed to import Prowler App server: {e}")

    # Import Prowler Documentation tools with prowler_docs_ prefix
    try:
        logger.info("Importing Prowler Documentation server...")
        from prowler_mcp_server.prowler_documentation.server import docs_mcp_server

        await prowler_mcp_server.import_server(docs_mcp_server, prefix="prowler_docs")
        logger.info("Successfully imported Prowler Documentation server")
    except Exception as e:
        logger.error(f"Failed to import Prowler Documentation server: {e}")


# Add health check endpoint
@prowler_mcp_server.custom_route("/health", methods=["GET"])
async def health_check(request) -> JSONResponse:
    """Health check endpoint."""
    return JSONResponse(
        {"status": "healthy", "service": "prowler-mcp-server", "version": __version__}
    )


# Get or create the event loop
try:
    loop = asyncio.get_running_loop()
    # If we have a running loop, schedule the setup as a task
    loop.create_task(setup_main_server())
except RuntimeError:
    # No running loop, use asyncio.run (for standalone execution)
    asyncio.run(setup_main_server())

app = prowler_mcp_server.http_app()
