import httpx
from prowler_mcp_server import __version__
from pydantic import BaseModel, Field


class SearchResult(BaseModel):
    """Search result model."""

    path: str = Field(description="Document path")
    title: str = Field(description="Document title")
    url: str = Field(description="Documentation URL")
    highlights: list[str] = Field(
        description="Highlighted content snippets showing query matches with <mark><b> tags",
        default_factory=list,
    )
    score: float = Field(
        description="Relevance score for the search result", default=0.0
    )


class ProwlerDocsSearchEngine:
    """Prowler documentation search using Mintlify API."""

    def __init__(self):
        """Initialize the search engine."""
        self.api_base_url = (
            "https://api.mintlifytrieve.com/api/chunk_group/group_oriented_autocomplete"
        )
        self.dataset_id = "0096ba11-3f72-463b-9d95-b788495ac392"
        self.api_key = "tr-T6JLeTkFXeNbNPyhijtI9XhIncydQQ3O"
        self.docs_base_url = "https://prowler.mintlify.app"

        # HTTP client for Mintlify API
        self.mintlify_client = httpx.Client(
            timeout=30.0,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": f"prowler-mcp-server/{__version__}",
                "TR-Dataset": self.dataset_id,
                "Authorization": self.api_key,
                "X-API-Version": "V2",
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
        """
        Search documentation using Mintlify API.

        Args:
            query: Search query string
            page_size: Maximum number of results to return

        Returns:
            list of search results
        """
        try:
            # Construct request body
            payload = {
                "query": query,
                "search_type": "fulltext",
                "extend_results": True,
                "highlight_options": {
                    "highlight_window": 10,
                    "highlight_max_num": 1,
                    "highlight_max_length": 2,
                    "highlight_strategy": "exactmatch",
                    "highlight_delimiters": ["?", ",", ".", "!", "\n"],
                },
                "score_threshold": 0.2,
                "filters": {"must_not": [{"field": "tag_set", "match": ["code"]}]},
                "page_size": page_size,
                "group_size": 3,
            }

            # Make request to Mintlify API
            response = self.mintlify_client.post(
                self.api_base_url,
                json=payload,
            )
            response.raise_for_status()
            data = response.json()

            # Parse results
            results = []
            for result in data.get("results", []):
                group = result.get("group", {})
                chunks = result.get("chunks", [])

                # Get document path and title from group
                doc_path = group.get("name", "")
                group_title = group.get("name", "").replace("/", " / ").title()

                # If chunks exist, use the first chunk's title from metadata
                title = group_title
                if chunks:
                    first_chunk = chunks[0].get("chunk", {})
                    metadata = first_chunk.get("metadata", {})
                    title = metadata.get("title", group_title)

                # Construct full URL to docs
                full_url = f"{self.docs_base_url}/{doc_path}"

                # Extract highlights and scores from chunks
                highlights = []
                max_score = 0.0
                for chunk_data in chunks:
                    chunk_highlights = chunk_data.get("highlights", [])
                    highlights.extend(chunk_highlights)
                    # Track the highest score among all chunks in this group
                    chunk_score = chunk_data.get("score", 0.0)
                    max_score = max(max_score, chunk_score)

                results.append(
                    SearchResult(
                        path=doc_path,
                        title=title,
                        url=full_url,
                        highlights=highlights,
                        score=max_score,
                    )
                )

            return results

        except Exception as e:
            # Return empty list on error
            print(f"Search error: {e}")
            return []

    def get_document(self, doc_path: str) -> str | None:
        """
        Get full document content from Mintlify documentation.

        Args:
            doc_path: Path to the documentation file (e.g., "getting-started/installation")

        Returns:
            Full markdown content of the documentation, or None if not found
        """
        try:
            # Clean up the path
            doc_path = doc_path.rstrip("/")

            # Add .md extension if not present (Mintlify serves both .md and .mdx)
            if not doc_path.endswith(".md"):
                doc_path = f"{doc_path}.md"

            # Construct Mintlify URL
            url = f"{self.docs_base_url}/{doc_path}"

            # Fetch the documentation page
            response = self.docs_client.get(url)
            response.raise_for_status()

            return response.text

        except Exception as e:
            print(f"Error fetching document: {e}")
            return None
