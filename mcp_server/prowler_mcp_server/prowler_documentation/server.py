from typing import Any

from fastmcp import FastMCP
from pydantic import Field

from prowler_mcp_server.prowler_documentation.search_engine import (
    ProwlerDocsSearchEngine,
)

# Initialize FastMCP server
docs_mcp_server = FastMCP("prowler-docs")
prowler_docs_search_engine = ProwlerDocsSearchEngine()


@docs_mcp_server.tool()
def search(
    term: str = Field(description="The term to search for in the documentation"),
    page_size: int = Field(
        5,
        description="Number of top results to return to return. It must be between 1 and 20.",
        gt=1,
        lt=20,
    ),
) -> list[dict[str, Any]]:
    """Search in Prowler documentation.

    This tool searches through the official Prowler documentation
    to find relevant information about everything related to Prowler.

    Uses fulltext search to find the most relevant documentation pages
    based on your query.

    Returns:
        List of search results with highlights showing matched terms (in <mark><b> tags)
    """
    return prowler_docs_search_engine.search(term, page_size)  # type: ignore In the hint we cannot put SearchResult type because JSON API MCP Generator cannot handle Pydantic models yet


@docs_mcp_server.tool()
def get_document(
    doc_path: str = Field(
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
        return {"error": f"Document '{doc_path}' not found."}
    else:
        return {"content": content}
