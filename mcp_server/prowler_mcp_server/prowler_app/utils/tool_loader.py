"""Utility for auto-discovering and loading MCP tools.

This module provides functionality to automatically discover and register
all BaseTool subclasses from the tools package.
"""

import importlib
import pkgutil

from fastmcp import FastMCP
from prowler_mcp_server.lib.logger import logger
from prowler_mcp_server.prowler_app.tools.base import BaseTool


def load_all_tools(mcp: FastMCP) -> None:
    """Auto-discover and load all BaseTool subclasses from the tools package.

    This function:
    1. Dynamically imports all Python modules in the tools package
    2. Discovers all concrete BaseTool subclasses
    3. Instantiates each tool class
    4. Registers all tools with the provided FastMCP instance

    Args:
        mcp: The FastMCP instance to register tools with
        TOOLS_PACKAGE: The package path containing tool modules (default: prowler_mcp_server.prowler_app.tools)

    Example:
        from fastmcp import FastMCP
        from prowler_mcp_server.prowler_app.utils.tool_loader import load_all_tools

        app = FastMCP("prowler-app")
        load_all_tools(app)
    """
    TOOLS_PACKAGE = "prowler_mcp_server.prowler_app.tools"
    logger.info(f"Auto-discovering tools from package: {TOOLS_PACKAGE}")

    # Import the tools package
    try:
        tools_module = importlib.import_module(TOOLS_PACKAGE)
    except ImportError as e:
        logger.error(f"Failed to import tools package {TOOLS_PACKAGE}: {e}")
        return

    # Get the package path
    if hasattr(tools_module, "__path__"):
        package_path = tools_module.__path__
    else:
        logger.error(f"Package {TOOLS_PACKAGE} has no __path__ attribute")
        return

    # Import all modules in the package
    for _, module_name, _ in pkgutil.iter_modules(package_path):
        try:
            full_module_name = f"{TOOLS_PACKAGE}.{module_name}"
            importlib.import_module(full_module_name)
            logger.debug(f"Imported module: {full_module_name}")
        except Exception as e:
            logger.error(f"Failed to import module {module_name}: {e}")

    # Discover all concrete BaseTool subclasses
    concrete_tools = [
        tool_class
        for tool_class in BaseTool.__subclasses__()
        if not getattr(tool_class, "__abstractmethods__", None)
    ]

    logger.info(f"Discovered {len(concrete_tools)} tool classes")

    # Instantiate and register each tool
    for tool_class in concrete_tools:
        try:
            tool_instance = tool_class()
            tool_instance.register_tools(mcp)
            logger.info(f"Loaded and registered: {tool_class.__name__}")
        except Exception as e:
            logger.error(f"Failed to load tool {tool_class.__name__}: {e}")

    logger.info("Tool loading complete")
