from pydantic import BaseModel, Field


class SearchResult(BaseModel):
    """Search result model."""

    id: str = Field(description="Document ID")
    path: str = Field(description="Document path")
    title: str = Field(description="Document title")
    url: str = Field(description="GitHub URL")
    preview: str = Field(description="Content preview")
    score: float = Field(description="BM25 relevance score")
