"""Data models for Prowler RBAC roles.

This module provides Pydantic models for representing Prowler roles with
two-tier complexity:
- SimplifiedRole: For list operations with essential identification fields
- DetailedRole: Extends simplified with the capabilities the role grants and
  its related users / provider groups

It also provides UserRolesResult, used by the tools that read or change the
roles assigned to a specific user.

All models inherit from MinimalSerializerMixin to exclude None/empty values
for optimal LLM token usage.
"""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from prowler_mcp_server.prowler_app.models.base import MinimalSerializerMixin
from prowler_mcp_server.prowler_app.models.utils import extract_relationship_ids

# Boolean "manage_*" attributes that describe what a role is allowed to do.
# Only the enabled ones are surfaced as a flat `permissions` list.
_MANAGE_PERMISSIONS = (
    "manage_users",
    "manage_account",
    "manage_billing",
    "manage_integrations",
    "manage_providers",
    "manage_scans",
    "manage_ingestions",
    "manage_alerts",
)


class SimplifiedRole(MinimalSerializerMixin, BaseModel):
    """Simplified role representation for list operations.

    Includes core identification fields for efficient overview.
    Used by list_roles() tool.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(
        description="Unique UUIDv4 identifier for this role in Prowler database"
    )
    name: str = Field(description="Human-readable name of the role")
    permission_state: str | None = Field(
        default=None,
        description="Summary of the role's permissions: 'unlimited' (all), 'limited' (some), or 'none'",
    )

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> "SimplifiedRole":
        """Transform a JSON:API role resource into a simplified model.

        Args:
            data: Role data from API response['data'] (single item or list item)

        Returns:
            SimplifiedRole instance
        """
        attributes = data["attributes"]

        return cls(
            id=data["id"],
            name=attributes["name"],
            permission_state=attributes.get("permission_state"),
        )


class DetailedRole(SimplifiedRole):
    """Detailed role representation with granted capabilities and relationships.

    Extends SimplifiedRole with the concrete management capabilities the role
    grants, its visibility scope, and the IDs of related users and provider
    groups. Used by get_role(), get_user_roles() and the role assignment tools.
    """

    model_config = ConfigDict(frozen=True)

    permissions: list[str] | None = Field(
        default=None,
        description="Management capabilities granted by this role (only the enabled ones), e.g. ['manage_users', 'manage_scans']",
    )
    unlimited_visibility: bool | None = Field(
        default=None,
        description="Whether the role can see all providers (True) or only those in its provider groups (False)",
    )
    provider_group_ids: list[str] | None = Field(
        default=None,
        description="UUIDv4 identifiers of the provider groups this role is scoped to. An empty list means the role is not scoped to any provider group.",
    )
    user_ids: list[str] | None = Field(
        default=None,
        description="UUIDv4 identifiers of the users this role is assigned to. An empty list means the role is not assigned to any user.",
    )
    inserted_at: str | None = Field(
        default=None, description="ISO 8601 timestamp when the role was created"
    )
    updated_at: str | None = Field(
        default=None, description="ISO 8601 timestamp when the role was last modified"
    )

    def _should_exclude(self, key: str, value: Any) -> bool:
        """Keep fields whose "empty" form carries meaning.

        ``unlimited_visibility`` is kept even when ``False``, and ``permissions``
        and the relationship lists are kept even when empty so that an empty
        ``permissions``/``user_ids``/``provider_group_ids`` explicitly signals
        "grants no capabilities / not assigned to any user / not scoped to any
        provider group" instead of looking like an omitted, unknown field to an
        agent.
        """
        if key in (
            "unlimited_visibility",
            "permissions",
            "user_ids",
            "provider_group_ids",
        ):
            return value is None
        return super()._should_exclude(key, value)

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> "DetailedRole":
        """Transform a JSON:API role resource into a detailed model.

        Args:
            data: Role data from API response['data'] or an included role

        Returns:
            DetailedRole instance with all fields populated
        """
        attributes = data["attributes"]
        relationships = data.get("relationships", {})

        permissions = [
            permission
            for permission in _MANAGE_PERMISSIONS
            if attributes.get(permission)
        ]

        return cls(
            id=data["id"],
            name=attributes["name"],
            permission_state=attributes.get("permission_state"),
            permissions=permissions,
            unlimited_visibility=attributes.get("unlimited_visibility"),
            provider_group_ids=extract_relationship_ids(
                relationships, "provider_groups"
            ),
            user_ids=extract_relationship_ids(relationships, "users"),
            inserted_at=attributes.get("inserted_at"),
            updated_at=attributes.get("updated_at"),
        )


class RolesListResponse(BaseModel):
    """Response model for list_roles() with pagination metadata.

    Follows the established pattern from ScansListResponse and UsersListResponse.
    """

    roles: list[SimplifiedRole]
    total_num_roles: int
    total_num_pages: int
    current_page: int

    @classmethod
    def from_api_response(cls, response: dict[str, Any]) -> "RolesListResponse":
        """Transform a JSON:API list response into a roles list with pagination.

        Args:
            response: Full API response with data and meta

        Returns:
            RolesListResponse with simplified roles and pagination metadata
        """
        data = response.get("data", [])
        meta = response.get("meta", {})
        pagination = meta.get("pagination", {})

        roles = [SimplifiedRole.from_api_response(item) for item in data]

        return cls(
            roles=roles,
            total_num_roles=pagination.get("count", 0),
            total_num_pages=pagination.get("pages", 0),
            current_page=pagination.get("page", 1),
        )


class UserRolesResult(MinimalSerializerMixin, BaseModel):
    """The roles currently assigned to a user.

    Used by get_user_roles() to report a user's roles, and by the assignment
    tools to report the authoritative role set after a change (with `changed`
    and `message` describing the outcome).
    """

    user_id: str = Field(description="UUIDv4 identifier of the user")
    total_num_roles: int = Field(
        description="Number of roles currently assigned to the user"
    )
    roles: list[DetailedRole] = Field(
        description="The roles currently assigned to the user, with their granted capabilities"
    )
    changed: bool | None = Field(
        default=None,
        description="For assignment operations: whether this call actually modified the user's roles",
    )
    message: str | None = Field(
        default=None,
        description="For assignment operations: human-readable description of the outcome",
    )

    def _should_exclude(self, key: str, value: Any) -> bool:
        """Always include the roles list, even when empty (explicit 'no roles')."""
        if key == "roles":
            return False
        return super()._should_exclude(key, value)

    @classmethod
    def build(
        cls,
        user_id: str,
        roles: list[DetailedRole],
        changed: bool | None = None,
        message: str | None = None,
    ) -> "UserRolesResult":
        """Assemble a result from a user's role list, filling the count."""
        return cls(
            user_id=user_id,
            total_num_roles=len(roles),
            roles=roles,
            changed=changed,
            message=message,
        )
