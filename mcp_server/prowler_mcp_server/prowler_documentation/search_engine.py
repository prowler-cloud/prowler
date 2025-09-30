import json
import pickle
import re
from pathlib import Path
from typing import Dict, List, Optional

from prowler_mcp_server.prowler_documentation.models import SearchResult
from rank_bm25 import BM25Okapi


class ProwlerDocsSearchEngine:
    """Prowler documentation server with BM25 search."""

    def __init__(self):
        """Initialize the server and load index."""

        self.base_dir = Path(__file__).parent / "_data"
        self.index_dir = self.base_dir / "index"
        self.docs_dir = self.base_dir / "docs"

        # Load BM25 index and metadata
        self.bm25: Optional[BM25Okapi] = None
        self.doc_metadata: List[Dict] = []
        self._load_index()

    def _load_index(self):
        """Load BM25 index and document metadata."""
        index_file = self.index_dir / "bm25_index.pkl"
        metadata_file = self.index_dir / "doc_metadata.json"

        if not index_file.exists() or not metadata_file.exists():
            from prowler_mcp_server.prowler_documentation.utils.setup_prowler_docs import (
                ProwlerDocsSetup,
            )

            setup = ProwlerDocsSetup()
            setup.setup()

            # Try loading again after setup
            if not index_file.exists() or not metadata_file.exists():
                return

        try:
            # Load BM25 index
            with open(index_file, "rb") as f:
                self.bm25 = pickle.load(f)

            # Load metadata
            with open(metadata_file, "r", encoding="utf-8") as f:
                self.doc_metadata = json.load(f)

        except Exception:
            pass

    def search(self, query: str, top_k: int = 5) -> List[SearchResult]:
        """Search documentation using BM25."""
        if not self.bm25 or not self.doc_metadata:
            return []

        # Tokenize query (same as in setup.py)
        query_tokens = self._tokenize(query)

        # Get BM25 scores
        scores = self.bm25.get_scores(query_tokens)

        # Get top-k results
        top_indices = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[
            :top_k
        ]

        results = []
        for idx in top_indices:
            if scores[idx] > 0:  # Only include results with positive scores
                doc = self.doc_metadata[idx]
                results.append(
                    SearchResult(
                        id=doc["id"],
                        path=doc["path"],
                        title=doc["title"],
                        url=doc["url"],
                        preview=doc["preview"],
                        score=float(scores[idx]),
                    )
                )

        return results

    def get_document(self, doc_path: str) -> Optional[str]:
        """Get full document content by path."""
        doc_file = self.docs_dir / doc_path
        if doc_file.exists():
            return doc_file.read_text(encoding="utf-8")
        return None

    def _tokenize(self, text: str) -> List[str]:
        """Simple tokenization function (same as in setup.py)."""
        text = text.lower()
        text = re.sub(r"[#*`\[\]()]", " ", text)
        tokens = re.findall(r"\b\w+\b", text)
        return tokens
