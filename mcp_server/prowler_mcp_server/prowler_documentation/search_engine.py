import urllib.parse
from typing import List, Optional

import requests
from pydantic import BaseModel, Field


class SearchResult(BaseModel):
    """Search result model."""

    path: str = Field(description="Document path")
    title: str = Field(description="Document title")
    url: str = Field(description="Documentation URL")
    highlights: List[str] = Field(
        description="Highlighted content snippets showing query matches with <span> tags",
        default_factory=list,
    )


class ProwlerDocsSearchEngine:
    """Prowler documentation search using ReadTheDocs API."""

    def __init__(self):
        """Initialize the search engine."""
        self.api_base_url = "https://docs.prowler.com/_/api/v3/search/"
        self.project_name = "prowler-prowler"
        self.github_raw_base = (
            "https://raw.githubusercontent.com/prowler-cloud/prowler/master/docs"
        )

    def search(self, query: str, page_size: int = 5) -> List[SearchResult]:
        """
        Search documentation using ReadTheDocs API.

        Args:
            query: Search query string
            page_size: Maximum number of results to return

        Returns:
            List of search results
        """
        try:
            # Construct the search query with project filter
            search_query = f"project:{self.project_name} {query}"

            # Make request to ReadTheDocs API with page_size to limit results
            params = {"q": search_query, "page_size": page_size}
            response = requests.get(
                self.api_base_url,
                params=params,
                timeout=10,
            )
            response.raise_for_status()

            data = response.json()

            # Parse results
            results = []
            for hit in data.get("results", []):
                # Extract relevant fields from API response
                blocks = hit.get("blocks", [])
                # Get the document path from the hit's path field
                hit_path = hit.get("path", "")
                doc_path = self._extract_doc_path(hit_path)

                # Construct full URL to docs
                domain = hit.get("domain", "https://docs.prowler.com")
                full_url = f"{domain}{hit_path}" if hit_path else ""

                # Extract highlights from API response
                highlights = []

                # Add title highlights
                page_highlights = hit.get("highlights", {})
                if page_highlights.get("title"):
                    highlights.extend(page_highlights["title"])

                # Add block content highlights (up to 3 snippets)
                for block in blocks[:3]:
                    block_highlights = block.get("highlights", {})
                    if block_highlights.get("content"):
                        highlights.extend(block_highlights["content"])

                results.append(
                    SearchResult(
                        path=doc_path,
                        title=hit.get("title", ""),
                        url=full_url,
                        highlights=highlights,
                    )
                )

            return results

        except Exception as e:
            # Return empty list on error
            print(f"Search error: {e}")
            return []

    def get_document(self, doc_path: str) -> Optional[str]:
        """
        Get full document content from GitHub raw API.

        Args:
            doc_path: Path to the documentation file (e.g., "getting-started/installation")

        Returns:
            Full markdown content of the documentation, or None if not found
        """
        try:
            # Clean up the path
            doc_path = doc_path.rstrip("/")

            # Add .md extension if not present
            if not doc_path.endswith(".md"):
                doc_path = f"{doc_path}.md"

            # Construct GitHub raw URL
            url = f"{self.github_raw_base}/{doc_path}"

            # Fetch the raw markdown
            response = requests.get(url, timeout=10)
            response.raise_for_status()

            return response.text

        except Exception as e:
            print(f"Error fetching document: {e}")
            return None

    def _extract_doc_path(self, url: str) -> str:
        """
        Extract the document path from a full URL.

        Args:
            url: Full documentation URL

        Returns:
            Document path relative to docs base
        """
        if not url:
            return ""

        # Parse URL and extract path
        try:
            parsed = urllib.parse.urlparse(url)
            path = parsed.path

            # Remove the base path prefix if present
            base_path = "/projects/prowler-open-source/en/latest/"
            if path.startswith(base_path):
                path = path[len(base_path) :]

            # Remove .html extension
            if path.endswith(".html"):
                path = path[:-5]

            return path.lstrip("/")
        except Exception:
            return url
