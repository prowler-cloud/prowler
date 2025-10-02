import argparse
import asyncio
import os
import sys

from prowler_mcp_server.lib.logger import logger
from prowler_mcp_server.server import setup_main_server


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Prowler MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default=os.getenv("PROWLER_MCP_MODE", "stdio"),
        help="Transport method (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind to for HTTP transport (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind to for HTTP transport (default: 8000)",
    )
    return parser.parse_args()


def main():
    """Main entry point for the MCP server."""
    try:
        args = parse_arguments()

        # Set up server with configuration
        prowler_mcp_server = asyncio.run(setup_main_server(transport=args.transport))

        if args.transport == "stdio":
            prowler_mcp_server.run(transport="stdio")
        elif args.transport == "http":
            prowler_mcp_server.run(transport="http", host=args.host, port=args.port)

    except KeyboardInterrupt:
        logger.info("Shutting down Prowler MCP server...")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error starting server: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
