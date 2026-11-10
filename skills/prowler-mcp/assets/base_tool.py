# Example: BaseTool Abstract Class (trimmed; docstrings shortened)
# Source: mcp_server/prowler_mcp_server/prowler_app/tools/base.py
#
# Subclasses do NOT override register_tools(): every public async method is
# registered automatically, with MCP annotations derived from its name.

import inspect
from abc import ABC
from typing import TYPE_CHECKING

from mcp.types import ToolAnnotations

if TYPE_CHECKING:
    from fastmcp import FastMCP

from prowler_mcp_server.lib.logger import logger
from prowler_mcp_server.prowler_app.utils.api_client import ProwlerAPIClient

READ_ONLY_PREFIXES = ("get_", "list_", "search_")


class BaseTool(ABC):
    # Tools that change nothing although their name lacks a READ_ONLY_PREFIXES prefix
    read_only_tools: frozenset[str] = frozenset()
    # Tools that remove, replace or hide data although their name lacks "delete_"
    destructive_tools: frozenset[str] = frozenset()

    def __init__(self):
        self._api_client = ProwlerAPIClient()  # singleton
        self._logger = logger

    @property
    def api_client(self) -> ProwlerAPIClient:
        return self._api_client

    @property
    def logger(self):
        return self._logger

    def register_tools(self, mcp: "FastMCP") -> None:
        """Register all public async methods as tools with FastMCP."""
        registered_count = 0

        for name, method in inspect.getmembers(self, predicate=inspect.ismethod):
            if name.startswith("_"):
                continue
            if name in ["register_tools"]:
                continue
            if name in ["api_client", "logger"]:
                continue
            if inspect.iscoroutinefunction(method):
                mcp.tool(method, annotations=self._annotations_for(name))
                registered_count += 1
                self.logger.debug(f"Auto-registered tool: {name}")

        self.logger.info(
            f"Auto-registered {registered_count} tools from {self.__class__.__name__}"
        )

    def _annotations_for(self, name: str) -> ToolAnnotations:
        """Every tool states both hints: left out, MCP treats a tool as destructive."""
        if name.startswith(READ_ONLY_PREFIXES) or name in self.read_only_tools:
            return ToolAnnotations(readOnlyHint=True, destructiveHint=False)
        return ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=name.startswith("delete_")
            or name in self.destructive_tools,
        )


# Subclass example (from prowler_app/tools/roles.py):
#
# class RolesTools(BaseTool):
#     destructive_tools = frozenset({"set_user_role"})  # replaces a user's roles
