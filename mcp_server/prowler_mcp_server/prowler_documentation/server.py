from typing import List

from fastmcp import FastMCP
from prowler_mcp_server.prowler_documentation.models import SearchResult
from prowler_mcp_server.prowler_documentation.search_engine import (
    ProwlerDocsSearchEngine,
)
from pydantic import Field

# Initialize FastMCP server
docs_mcp_server = FastMCP("prowler-docs")
prowler_docs_search_engine = ProwlerDocsSearchEngine()


@docs_mcp_server.tool()
def search(
    query: str = Field(description="Search query for Prowler documentation"),
    top_k: int = Field(
        default=5, description="Number of results to return", ge=1, le=20
    ),
) -> List[SearchResult]:
    """
    Search in Prowler documentation.

    This tool searches through the official Prowler documentation
    to find relevant information about security checks, cloud providers,
    compliance frameworks, and usage instructions.

    Returned scores indicate relevance (higher = more relevant):
    - 0: No matching terms
    - 0-5: Low relevance (few/common term matches)
    - 5-20: Good relevance (multiple term matches)
    - 20+: High relevance (many rare term matches)

    Args:
        query: The search query
        top_k: Number of top results to return (1-20)

    Returns:
        List of search results with relevance scores
    """
    return prowler_docs_search_engine.search(query, top_k)


@docs_mcp_server.tool()
def get_document(
    doc_path: str = Field(
        description="Path to the documentation file. It is the same as the 'id' field of the search results."
    ),
) -> str:
    """
    Retrieve the full content of a Prowler documentation file.

    Use this after searching to get the complete content of a specific
    documentation file.

    Args:
        doc_path: Path to the documentation file. It is the same as the "id" field of the search results.

    Returns:
        Full content of the documentation file
    """
    content = prowler_docs_search_engine.get_document(doc_path)
    if content is None:
        raise ValueError(f"Document not found: {doc_path}")
    return content


if __name__ == "__main__":
    docs_mcp_server.run()
