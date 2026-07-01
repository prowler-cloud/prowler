# Example: BaseTool Abstract Class
# Source: mcp_server/prowler_mcp_server/prowler_app/tools/base.py

import inspect
from abc import ABC
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastmcp import FastMCP

from prowler_mcp_server.lib.logger import logger
from prowler_mcp_server.prowler_app.utils.api_client import ProwlerAPIClient


class BaseTool(ABC):
    """
    Abstract base class for MCP tools.

    Key patterns:
    1. Auto-registers all public async methods as tools
    2. Provides shared api_client and logger via properties
    3. Subclasses just define async methods with Field() parameters
    """

    def __init__(self):
        self._api_client = ProwlerAPIClient()
        self._logger = logger

    @property
    def api_client(self) -> ProwlerAPIClient:
        """Shared API client for making authenticated requests."""
        return self._api_client

    @property
    def logger(self):
        """Logger for structured logging."""
        return self._logger

    def register_tools(self, mcp: "FastMCP") -> None:
        """
        Auto-register all public async methods as MCP tools.

        Subclasses don't need to override this - just define async methods.
        """
        registered_count = 0

        for name, method in inspect.getmembers(self, predicate=inspect.ismethod):
            # Skip private/protected methods
            if name.startswith("_"):
                continue
            # Skip inherited methods
            if name in ["register_tools", "api_client", "logger"]:
                continue
            # Only register async methods
            if inspect.iscoroutinefunction(method):
                mcp.tool(method)
                registered_count += 1
                self.logger.debug(f"Auto-registered tool: {name}")

        self.logger.info(
            f"Auto-registered {registered_count} tools from {self.__class__.__name__}"
        )
