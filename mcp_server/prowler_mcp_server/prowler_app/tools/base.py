import inspect
from abc import ABC
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastmcp import FastMCP

from prowler_mcp_server.lib.logger import logger
from prowler_mcp_server.prowler_app.utils.api_client import ProwlerAPIClient


class BaseTool(ABC):
    """Abstract base class for all MCP tools.

    This class defines the contract that all domain-specific tools must follow.
    It ensures consistency across tool registration and provides common utilities.

    Key responsibilities:
    - Enforce implementation of register_tools() via ABC
    - Provide shared access to API client and logger
    - Define common patterns for tool registration
    - Support dependency injection for the FastMCP instance

    Attributes:
        _api_client: Singleton instance of ProwlerAPIClient for API requests
        _logger: Logger instance for structured logging

    Example:
        class FindingsTools(BaseTool):
            def register_tools(self, mcp: FastMCP) -> None:
                mcp.tool(self.search_security_findings)
                mcp.tool(self.get_finding_details)

            async def search_security_findings(self, severity: list[str] = Field(...)):
                # Implementation with access to self.api_client
                response = await self.api_client.get("/findings")
                return response
    """

    def __init__(self):
        """Initialize the tool.

        Sets up shared dependencies that all tools can access:
        - API client (singleton) for making authenticated requests
        - Logger instance for structured logging
        """
        self._api_client = ProwlerAPIClient()
        self._logger = logger

    @property
    def api_client(self) -> ProwlerAPIClient:
        """Get the shared API client instance.

        Returns:
            Singleton instance of ProwlerAPIClient for making API requests
        """
        return self._api_client

    @property
    def logger(self):
        """Get the logger instance.

        Returns:
            Logger instance for structured logging
        """
        return self._logger

    def register_tools(self, mcp: "FastMCP") -> None:
        """Automatically register all public async methods as tools with FastMCP.

        This method inspects the subclass and automatically registers all public
        async methods (not starting with '_') as tools. Subclasses do not need
        to override this method.

        Args:
            mcp: The FastMCP instance to register tools with
        """
        # Get all methods from the subclass
        registered_count = 0

        for name, method in inspect.getmembers(self, predicate=inspect.ismethod):
            # Skip private/protected methods
            if name.startswith("_"):
                continue

            # Skip methods inherited from BaseTool
            if name in ["register_tools"]:
                continue

            # Skip property getters
            if name in ["api_client", "logger"]:
                continue

            # Check if the method is a coroutine function (async)
            if inspect.iscoroutinefunction(method):
                mcp.tool(method)
                registered_count += 1
                self.logger.debug(f"Auto-registered tool: {name}")

        self.logger.info(
            f"Auto-registered {registered_count} tools from {self.__class__.__name__}"
        )
