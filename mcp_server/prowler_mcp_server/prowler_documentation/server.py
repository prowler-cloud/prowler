from typing import List

from fastmcp import FastMCP
from prowler_mcp_server.prowler_documentation.search_engine import (
    ProwlerDocsSearchEngine,
    SearchResult,
)

# Initialize FastMCP server
docs_mcp_server = FastMCP("prowler-docs")
prowler_docs_search_engine = ProwlerDocsSearchEngine()


@docs_mcp_server.tool()
def search(
    query: str,
    page_size: int = 5,
) -> List[SearchResult]:
    """
    Search in Prowler documentation.

    This tool searches through the official Prowler documentation
    to find relevant information about security checks, cloud providers,
    compliance frameworks, and usage instructions.

    Uses fulltext search to find the most relevant documentation pages
    based on your query.

    Args:
        query: The search query
        page_size: Number of top results to return (default: 5)

    Returns:
        List of search results with highlights showing matched terms (in <mark><b> tags)
    """
    return prowler_docs_search_engine.search(query, page_size)


@docs_mcp_server.tool()
def get_document(
    doc_path: str,
) -> str:
    """
    Retrieve the full content of a Prowler documentation file.

    Use this after searching to get the complete content of a specific
    documentation file.

    Args:
        doc_path: Path to the documentation file. It is the same as the "path" field of the search results.

    Returns:
        Full content of the documentation file
    """
    content = prowler_docs_search_engine.get_document(doc_path)
    if content is None:
        raise ValueError(f"Document not found: {doc_path}")
    return content
