import asyncio
import sys

from prowler_mcp_server.lib.logger import logger
from prowler_mcp_server.server import prowler_mcp_server, setup_main_server


def main():
    """Main entry point for the MCP server."""
    try:
        logger.info("Starting Prowler MCP server...")
        asyncio.run(setup_main_server())
        prowler_mcp_server.run()
    except KeyboardInterrupt:
        logger.info("Shutting down Prowler MCP server...")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error starting server: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
