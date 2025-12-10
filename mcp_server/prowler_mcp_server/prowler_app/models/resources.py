"""Pydantic models for simplified resources responses."""

from prowler_mcp_server.prowler_app.models.base import MinimalSerializerMixin
from pydantic import BaseModel


class SimplifiedResource(MinimalSerializerMixin, BaseModel):
    """Simplified resource with only LLM-relevant information for list operations."""

    id: str
    uid: str
    name: str
    region: str
    service: str
    type: str
    failed_findings_count: int
    tags: dict[str, str] | None = None
    provider_id: str | None = None

    @classmethod
    def from_api_response(cls, data: dict) -> "SimplifiedResource":
        """Transform JSON:API resource response to simplified format."""
        attributes = data["attributes"]
        relationships = data.get("relationships", {})

        # Extract provider information from relationships if available
        provider_id = None
        provider_data = relationships.get("provider", {}).get("data", {})
        if provider_data:
            provider_id = provider_data["id"]

        return cls(
            id=data["id"],
            uid=attributes["uid"],
            name=attributes["name"],
            region=attributes["region"],
            service=attributes["service"],
            type=attributes["type"],
            failed_findings_count=attributes["failed_findings_count"],
            tags=attributes["tags"],
            provider_id=provider_id,
        )


class DetailedResource(SimplifiedResource):
    """Detailed resource with comprehensive information for deep analysis.

    Extends SimplifiedResource with tags, metadata, configuration details,
    temporal information, and relationships.
    Use this when you need complete context about a specific resource.
    """

    metadata: str | None = None
    partition: str | None = None
    inserted_at: str
    updated_at: str
    finding_ids: list[str] | None = None

    @classmethod
    def from_api_response(cls, data: dict) -> "DetailedResource":
        """Transform JSON:API resource response to detailed format."""
        attributes = data["attributes"]
        relationships = data.get("relationships", {})

        # Parse findings relationship
        finding_ids = None
        findings_data = relationships.get("findings", {}).get("data", [])
        if findings_data:
            finding_ids = [f["id"] for f in findings_data]

        # Extract provider information from relationships if available
        provider_id = None
        provider_data = relationships.get("provider", {}).get("data", {})
        if provider_data:
            provider_id = provider_data["id"]

        return cls(
            id=data["id"],
            uid=attributes["uid"],
            name=attributes["name"],
            region=attributes["region"],
            service=attributes["service"],
            type=attributes["type"],
            failed_findings_count=attributes["failed_findings_count"],
            tags=attributes["tags"],
            metadata=attributes["metadata"],
            partition=attributes["partition"],
            inserted_at=attributes["inserted_at"],
            updated_at=attributes["updated_at"],
            finding_ids=finding_ids,
            provider_id=provider_id,
        )


class ResourcesListResponse(BaseModel):
    """Simplified response for resources list queries."""

    resources: list[SimplifiedResource]
    total_num_resources: int
    total_num_pages: int
    current_page: int

    @classmethod
    def from_api_response(cls, response: dict) -> "ResourcesListResponse":
        """Transform JSON:API response to simplified format."""
        data = response["data"]
        meta = response["meta"]
        pagination = meta["pagination"]

        resources = [SimplifiedResource.from_api_response(item) for item in data]

        return cls(
            resources=resources,
            total_num_resources=pagination["count"],
            total_num_pages=pagination["pages"],
            current_page=pagination["page"],
        )


class ResourcesMetadataResponse(BaseModel):
    """Metadata response with unique filter values for resource discovery."""

    services: list[str] | None = None
    regions: list[str] | None = None
    types: list[str] | None = None

    @classmethod
    def from_api_response(cls, response: dict) -> "ResourcesMetadataResponse":
        """Transform JSON:API metadata response to simplified format."""
        data = response["data"]
        attributes = data["attributes"]

        return cls(
            services=attributes.get("services"),
            regions=attributes.get("regions"),
            types=attributes.get("types"),
        )
