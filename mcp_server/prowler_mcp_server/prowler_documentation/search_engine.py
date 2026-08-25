import httpx
from pydantic import BaseModel, Field

from prowler_mcp_server import __version__


class SearchResult(BaseModel):
    """Search result model."""

    path: str = Field(description="Document path")
    title: str = Field(description="Title of the page the match is on")
    section: str = Field(
        description="Heading of the section the match is in", default=""
    )
    breadcrumbs: list[str] = Field(
        description="Where the page sits in the documentation, from the top-level group down to the page itself",
        default_factory=list,
    )
    url: str = Field(
        description="Documentation URL, anchored at the matching section when it has an anchor"
    )
    excerpt: str = Field(
        description="Text of the matching section, which is a part of the page and not the whole of it",
        default="",
    )
    score: float = Field(
        description="Relevance score for the search result", default=0.0
    )


class ProwlerDocsSearchEngine:
    """Prowler documentation search using Mintlify API."""

    def __init__(self):
        """Initialize the search engine."""
        # The endpoint docs.prowler.com itself calls, with the site's Mintlify
        # project name as the last segment.
        self.api_base_url = "https://leaves.mintlify.com/api/search/prowler"
        self.docs_base_url = "https://docs.prowler.com"

        # HTTP client for Mintlify API
        self.mintlify_client = httpx.Client(
            timeout=30.0,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": f"prowler-mcp-server/{__version__}",
            },
        )

        # HTTP client for Mintlify documentation
        self.docs_client = httpx.Client(
            timeout=30.0,
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "User-Agent": f"prowler-mcp-server/{__version__}",
            },
        )

    def search(self, query: str, page_size: int = 5) -> list[SearchResult]:
        """Search documentation using Mintlify API.

        Args:
            query: Search query string
            page_size: Maximum number of results to return. The API decides how
                many matches it answers with and takes no size of its own, so
                this only trims the list it returned.

        Returns:
            list of search results

        Raises:
            httpx.HTTPError: If the search request failed, which is not the same
                answer as no matches
        """
        # Make request to Mintlify API
        response = self.mintlify_client.post(
            self.api_base_url,
            json={"query": query, "filters": {}},
        )
        response.raise_for_status()
        data = response.json()

        # Parse results
        results = []
        for match in data.get("results", [])[:page_size]:
            metadata = match.get("metadata", {})
            breadcrumbs = metadata.get("breadcrumbs", [])
            doc_path = match.get("page", "")

            # A match is one section of a page rather than the page: the
            # heading it was found under is its header, and the page's own
            # title is the last step of its breadcrumb trail.
            section = match.get("header", "")
            title = breadcrumbs[-1] if breadcrumbs else section

            # Sent as "" for the section a page opens with and as null for
            # the pages that have no anchors at all; both mean the page.
            anchor = metadata.get("hash")
            url = f"{self.docs_base_url}/{doc_path}"
            if anchor:
                url = f"{url}#{anchor}"

            results.append(
                SearchResult(
                    path=doc_path,
                    title=title,
                    section=section,
                    breadcrumbs=breadcrumbs,
                    url=url,
                    excerpt=match.get("content", ""),
                    score=match.get("score", 0.0),
                )
            )

        return results

    def get_document(self, doc_path: str) -> str | None:
        """Get full document content from Mintlify documentation.

        Args:
            doc_path: Path to the documentation file (e.g., "getting-started/installation")

        Returns:
            Full markdown content of the documentation, or None if there is no
            page at that path

        Raises:
            httpx.HTTPError: If the fetch failed for any reason other than a 404
        """
        # Clean up the path
        doc_path = doc_path.rstrip("/")

        # Add .md extension if not present (Mintlify serves both .md and .mdx)
        if not doc_path.endswith(".md"):
            doc_path = f"{doc_path}.md"

        # Construct Mintlify URL
        url = f"{self.docs_base_url}/{doc_path}"

        # Fetch the documentation page
        response = self.docs_client.get(url)
        if response.status_code == 404:
            return None
        response.raise_for_status()

        return response.text
