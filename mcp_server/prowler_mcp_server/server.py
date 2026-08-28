from fastmcp import FastMCP
from starlette.responses import JSONResponse

from prowler_mcp_server import __version__
from prowler_mcp_server.lib.errors import SharedFailureMiddleware
from prowler_mcp_server.lib.logger import logger

# `mask_error_details` keeps an unhandled failure from relaying text this server
# does not control. It is set on every sub-server as well, because it does not
# reach mounted children -- FastMCP warns about exactly that at mount time.
prowler_mcp_server = FastMCP("prowler-mcp-server", mask_error_details=True)

# Middleware, unlike masking, does reach mounted children, so the classifier that
# gives the masked failures a sentence back is wired here once.
prowler_mcp_server.add_middleware(SharedFailureMiddleware())


def setup_main_server():
    """Set up the main Prowler MCP server with all available integrations."""
    # Mount Prowler Hub tools with prowler_hub_ namespace
    try:
        logger.info("Mounting Prowler Hub server...")
        from prowler_mcp_server.prowler_hub.server import hub_mcp_server

        prowler_mcp_server.mount(hub_mcp_server, namespace="prowler_hub")
        logger.info("Successfully mounted Prowler Hub server")
    except Exception as e:
        logger.error(f"Failed to mount Prowler Hub server: {e}")

    # Mount core Prowler tools with prowler_ namespace
    try:
        logger.info("Mounting Prowler tools server...")
        from prowler_mcp_server.prowler_app.server import app_mcp_server

        prowler_mcp_server.mount(app_mcp_server, namespace="prowler")
        logger.info("Successfully mounted Prowler tools server")
    except Exception as e:
        logger.error(f"Failed to mount Prowler tools server: {e}")

    # Mount Prowler Documentation tools with prowler_docs_ namespace
    try:
        logger.info("Mounting Prowler Documentation server...")
        from prowler_mcp_server.prowler_documentation.server import docs_mcp_server

        prowler_mcp_server.mount(docs_mcp_server, namespace="prowler_docs")
        logger.info("Successfully mounted Prowler Documentation server")
    except Exception as e:
        logger.error(f"Failed to mount Prowler Documentation server: {e}")


# Response follows the IETF Health Check Response Format
# (draft-inadarei-api-health-check-06). `version` is the contract version of
# this endpoint; `releaseId` is the package build version.
@prowler_mcp_server.custom_route("/health", methods=["GET"])
async def health_check(_request) -> JSONResponse:
    """Health check endpoint."""
    return JSONResponse(
        {
            "status": "pass",
            "version": "1",
            "releaseId": __version__,
            "serviceId": "prowler-mcp-server",
            "description": "Prowler MCP Server",
        },
        media_type="application/health+json",
        headers={"Cache-Control": "no-store"},
    )


setup_main_server()

# ASGI app for uvicorn deployments; stateless to avoid retaining sessions
app = prowler_mcp_server.http_app(stateless_http=True)
