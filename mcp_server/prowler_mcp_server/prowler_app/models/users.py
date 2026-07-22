"""Data models for Prowler users.

This module provides Pydantic models for representing Prowler users with
two-tier complexity:
- SimplifiedUser: For list operations with essential identification fields
- DetailedUser: Extends simplified with account metadata and role/membership links

All models inherit from MinimalSerializerMixin to exclude None/empty values
for optimal LLM token usage.
"""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from prowler_mcp_server.prowler_app.models.base import MinimalSerializerMixin
from prowler_mcp_server.prowler_app.models.utils import extract_relationship_ids


class SimplifiedUser(MinimalSerializerMixin, BaseModel):
    """Simplified user representation for list operations.

    Includes core identification fields for efficient overview.
    Used by list_users() tool.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(
        description="Unique UUIDv4 identifier for this user in Prowler database"
    )
    name: str = Field(description="Display name of the user")
    email: str = Field(description="Email address of the user")
    company_name: str | None = Field(
        default=None, description="Company the user belongs to, if provided"
    )

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> "SimplifiedUser":
        """Transform a JSON:API user resource into a simplified model.

        Args:
            data: User data from API response['data'] (single item or list item)

        Returns:
            SimplifiedUser instance
        """
        attributes = data["attributes"]

        return cls(
            id=data["id"],
            name=attributes["name"],
            email=attributes["email"],
            company_name=attributes.get("company_name"),
        )


class DetailedUser(SimplifiedUser):
    """Detailed user representation with account metadata and relationships.

    Extends SimplifiedUser with verification status, join date, and the IDs of
    the roles and memberships associated with the user.
    Used by get_user() and get_current_user() tools.
    """

    model_config = ConfigDict(frozen=True)

    is_verified: bool | None = Field(
        default=None,
        description="Whether the user has verified their email address",
    )
    date_joined: str | None = Field(
        default=None,
        description="ISO 8601 timestamp when the user joined",
    )
    role_ids: list[str] | None = Field(
        default=None,
        description="UUIDv4 identifiers of the roles assigned to the user",
    )
    membership_ids: list[str] | None = Field(
        default=None,
        description="UUIDv4 identifiers of the tenant memberships of the user",
    )

    def _should_exclude(self, key: str, value: Any) -> bool:
        """Always include is_verified even when it is False."""
        if key == "is_verified":
            return value is None
        return super()._should_exclude(key, value)

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> "DetailedUser":
        """Transform a JSON:API user resource into a detailed model.

        Args:
            data: User data from API response['data']

        Returns:
            DetailedUser instance with all fields populated
        """
        attributes = data["attributes"]
        relationships = data.get("relationships", {})

        return cls(
            id=data["id"],
            name=attributes["name"],
            email=attributes["email"],
            company_name=attributes.get("company_name"),
            is_verified=attributes.get("is_verified"),
            date_joined=attributes.get("date_joined"),
            role_ids=extract_relationship_ids(relationships, "roles"),
            membership_ids=extract_relationship_ids(relationships, "memberships"),
        )


class UsersListResponse(BaseModel):
    """Response model for list_users() with pagination metadata.

    Follows the established pattern from ScansListResponse and ProvidersListResponse.
    """

    users: list[SimplifiedUser]
    total_num_users: int
    total_num_pages: int
    current_page: int

    @classmethod
    def from_api_response(cls, response: dict[str, Any]) -> "UsersListResponse":
        """Transform a JSON:API list response into a users list with pagination.

        Args:
            response: Full API response with data and meta

        Returns:
            UsersListResponse with simplified users and pagination metadata
        """
        data = response.get("data", [])
        meta = response.get("meta", {})
        pagination = meta.get("pagination", {})

        users = [SimplifiedUser.from_api_response(item) for item in data]

        return cls(
            users=users,
            total_num_users=pagination.get("count", 0),
            total_num_pages=pagination.get("pages", 0),
            current_page=pagination.get("page", 1),
        )
