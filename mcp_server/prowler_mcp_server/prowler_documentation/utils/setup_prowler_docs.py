#!/usr/bin/env python3
"""Setup script for Prowler documentation MCP server.

This script downloads documentation from the Prowler GitHub repository
and creates a BM25 search index for efficient searching.
"""

import json
import os
import pickle
from pathlib import Path
from typing import Dict, List

import requests
from rank_bm25 import BM25Okapi


class ProwlerDocsSetup:
    """Setup Prowler documentation for MCP server."""

    def __init__(self):
        """Initialize setup with base directory."""
        self.base_dir = Path(__file__).parent.parent / "_data"
        self.docs_dir = self.base_dir / "docs"
        self.index_dir = self.base_dir / "index"
        self.github_api_base = "https://api.github.com/repos/prowler-cloud/prowler"
        self.github_raw_base = (
            "https://raw.githubusercontent.com/prowler-cloud/prowler/master"
        )

    def setup(self):
        """Setup Prowler documentation for MCP server."""

        # Create directories
        self.docs_dir.mkdir(parents=True, exist_ok=True)
        self.index_dir.mkdir(parents=True, exist_ok=True)

        # Download documentation
        docs = self.download_docs()

        # Create BM25 index
        self.create_bm25_index(docs)

    def download_docs(self) -> List[Dict]:
        """Download all markdown files from Prowler docs directory."""
        docs = []

        # Get the tree of files in the docs directory
        tree_url = f"{self.github_api_base}/git/trees/master?recursive=1"
        response = requests.get(tree_url)
        response.raise_for_status()

        tree_data = response.json()
        doc_files = [
            item
            for item in tree_data.get("tree", [])
            if item["path"].startswith("docs/") and item["path"].endswith(".md")
        ]

        for file_info in doc_files:
            file_path = file_info["path"]
            file_name = os.path.basename(file_path)
            relative_path = file_path[5:]  # Remove "docs/" prefix

            # Download file content
            raw_url = f"{self.github_raw_base}/{file_path}"

            try:
                response = requests.get(raw_url)
                response.raise_for_status()
                content = response.text

                # Save file locally
                local_path = self.docs_dir / relative_path
                local_path.parent.mkdir(parents=True, exist_ok=True)
                local_path.write_text(content, encoding="utf-8")

                # Add to docs list
                docs.append(
                    {
                        "id": relative_path,
                        "path": relative_path,
                        "title": self._extract_title(content, file_name),
                        "content": content,
                        "url": f"{self.github_raw_base}/{file_path}",
                    }
                )

            except Exception:
                pass

        return docs

    def _extract_title(self, content: str, filename: str) -> str:
        """Extract title from markdown content or use filename."""
        lines = content.split("\n")
        for line in lines:
            if line.startswith("# "):
                return line[2:].strip()
        # Fallback to filename without extension
        return filename.replace(".md", "").replace("-", " ").replace("_", " ").title()

    def create_bm25_index(self, docs: List[Dict]):
        """Create BM25 index from documents."""
        # Prepare documents for indexing
        corpus = []
        doc_metadata = []

        for doc in docs:
            # Tokenize document (simple word splitting, could be improved)
            tokens = self._tokenize(doc["content"])
            corpus.append(tokens)

            # Store metadata
            doc_metadata.append(
                {
                    "id": doc["id"],
                    "path": doc["path"],
                    "title": doc["title"],
                    "url": doc["url"],
                    "preview": doc["content"][:500],  # Store first 500 chars as preview
                }
            )

        # Create BM25 index
        bm25 = BM25Okapi(corpus)

        # Save index and metadata
        index_file = self.index_dir / "bm25_index.pkl"
        metadata_file = self.index_dir / "doc_metadata.json"

        with open(index_file, "wb") as f:
            pickle.dump(bm25, f)

        with open(metadata_file, "w", encoding="utf-8") as f:
            json.dump(doc_metadata, f, indent=2, ensure_ascii=False)

    def _tokenize(self, text: str) -> List[str]:
        """Simple tokenization function."""
        # Convert to lowercase and split by whitespace and common punctuation
        import re

        text = text.lower()
        # Remove markdown formatting
        text = re.sub(r"[#*`\[\]()]", " ", text)
        # Split on whitespace and punctuation
        tokens = re.findall(r"\b\w+\b", text)
        return tokens


def main():
    """Run the setup script."""
    ProwlerDocsSetup().setup()
