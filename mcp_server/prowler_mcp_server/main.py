import asyncio
import sys
from prowler_mcp_server.server import setup_main_server, prowler_mcp_server


def main():
    """Main entry point for the MCP server."""
    try:
        asyncio.run(setup_main_server())
        prowler_mcp_server.run()
    except KeyboardInterrupt:
        print("\nShutting down Prowler MCP server...")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
