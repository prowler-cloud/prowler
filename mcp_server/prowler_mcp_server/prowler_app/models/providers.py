"""Pydantic models for simplified provider responses."""

from typing import Any, Literal

from prowler_mcp_server.prowler_app.models.base import MinimalSerializerMixin
from pydantic import BaseModel


class SimplifiedProvider(MinimalSerializerMixin, BaseModel):
    """Simplified provider for list/search operations."""

    id: str
    uid: str
    alias: str | None = None
    provider: str
    connected: bool | None = None
    secret_type: Literal["role", "service_account", "static"] | None = None

    def _should_exclude(self, key: str, value: Any) -> bool:
        """Override to always include connected and secret_type fields even when None."""
        # Always include these fields regardless of value (None has semantic meaning)
        if key == "connected" or key == "secret_type":
            return False
        # Use parent class logic for other fields
        return super()._should_exclude(key, value)

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> "SimplifiedProvider":
        """Transform JSON:API provider response to simplified format."""
        attributes = data["attributes"]
        connection_data = attributes.get("connection", {})

        return cls(
            id=data["id"],
            uid=attributes["uid"],
            alias=attributes.get("alias"),
            provider=attributes["provider"],
            connected=connection_data.get("connected"),
            secret_type=None,  # Will be populated separately via secret endpoint
        )


class DetailedProvider(SimplifiedProvider):
    """Detailed provider with complete information for deep analysis.

    Extends SimplifiedProvider with temporal metadata and relationships.
    Use this when you need complete context about a specific provider.
    """

    inserted_at: str | None = None
    updated_at: str | None = None
    last_checked_at: str | None = None
    provider_group_ids: list[str] | None = None

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> "DetailedProvider":
        """Transform JSON:API provider response to detailed format."""
        attributes = data["attributes"]
        connection_data = attributes.get("connection", {})
        relationships = data.get("relationships", {})

        # Extract provider groups relationship
        provider_group_ids = None
        groups_data = relationships.get("provider_groups", {}).get("data", [])
        if groups_data:
            provider_group_ids = [group["id"] for group in groups_data]

        return cls(
            id=data["id"],
            uid=attributes["uid"],
            alias=attributes.get("alias"),
            provider=attributes["provider"],
            connected=connection_data.get("connected"),
            inserted_at=attributes.get("inserted_at"),
            updated_at=attributes.get("updated_at"),
            last_checked_at=connection_data.get("last_checked_at"),
            provider_group_ids=provider_group_ids,
        )


class ProvidersListResponse(BaseModel):
    """Simplified response for providers list queries."""

    providers: list[SimplifiedProvider]
    total_num_providers: int
    total_num_pages: int
    current_page: int

    @classmethod
    def from_api_response(cls, response: dict[str, Any]) -> "ProvidersListResponse":
        """Transform JSON:API response to simplified format."""
        data = response["data"]
        meta = response["meta"]
        pagination = meta["pagination"]

        providers = [SimplifiedProvider.from_api_response(item) for item in data]

        return cls(
            providers=providers,
            total_num_providers=pagination["count"],
            total_num_pages=pagination["pages"],
            current_page=pagination["page"],
        )


class ProviderConnectionStatus(MinimalSerializerMixin, BaseModel):
    """Result of provider connection operation."""

    provider: DetailedProvider
    connected: Literal["connected", "failed", "not_tested"]
    error: str | None = None

    @classmethod
    def create(
        cls,
        provider_data: dict[str, Any],
        connection_status: dict[str, Any],
    ) -> "ProviderConnectionStatus":
        """Create connection status from provider data and connection test result."""

        connected: str | None = connection_status.get("connected", None)

        if connected is None:
            connected = "not_tested"
        elif connected:
            connected = "connected"
        else:
            connected = "failed"

        return cls(
            provider=DetailedProvider.from_api_response(provider_data),
            connected=connected,
            error=connection_status.get("error", None),
        )
