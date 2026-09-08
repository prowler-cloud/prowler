from typing import Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from pydantic import Field

from prowler_mcp_server.lib.types import NonBlankStr
from prowler_mcp_server.prowler_documentation.search_engine import (
    ProwlerDocsSearchEngine,
)

# Initialize FastMCP server
docs_mcp_server = FastMCP("prowler-docs", mask_error_details=True)
prowler_docs_search_engine = ProwlerDocsSearchEngine()


@docs_mcp_server.tool()
def search(
    term: NonBlankStr = Field(
        description="The term to search for in the documentation"
    ),
    page_size: int = Field(
        5,
        description="Number of top results to return. It must be between 1 and 20.",
        ge=1,
        le=20,
    ),
) -> list[dict[str, Any]]:
    """Search in Prowler documentation.

    This tool searches through the official Prowler documentation
    to find relevant information about everything related to Prowler.

    A result is one section of a documentation page, not the page itself: its
    'excerpt' is that section alone. Read the whole page with
    `prowler_docs_get_document`, passing the result's 'path'.

    Returns:
        List of matching documentation sections, most relevant first
    """
    return prowler_docs_search_engine.search(term, page_size)  # type: ignore In the hint we cannot put SearchResult type because JSON API MCP Generator cannot handle Pydantic models yet


@docs_mcp_server.tool()
def get_document(
    doc_path: NonBlankStr = Field(
        description="Path to the documentation file to retrieve. It is the same as the 'path' field of the search results. Use `prowler_docs_search` to find the path first."
    ),
) -> dict[str, str]:
    """Retrieve the full content of a Prowler documentation file.

    Use this after searching to get the complete content of a specific
    documentation file.

    Returns:
        Full content of the documentation file in markdown format.
    """
    content: str | None = prowler_docs_search_engine.get_document(doc_path)
    if content is None:
        # No `from`: this names the path asked for and the tool that produces a
        # valid one, neither of which the shared classifier can know.
        raise ToolError(
            f"The Prowler documentation has no page at '{doc_path}'. Use "
            "prowler_docs_search and pass the 'path' field of a result verbatim."
        )
    return {"content": content}
