"""Pydantic models for simplified muting responses."""

from typing import Any

from prowler_mcp_server.prowler_app.models.base import MinimalSerializerMixin
from pydantic import BaseModel, ConfigDict, Field


class MutelistResponse(MinimalSerializerMixin, BaseModel):
    """Simplified mutelist response with Prowler configuration.

    Represents a mutelist configuration that defines which findings
    should be automatically muted based on account patterns, check IDs, regions,
    resources, tags, and exceptions.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(
        description="Unique UUIDv4 identifier for this mutelist in Prowler database"
    )
    configuration: dict[str, Any] = Field(
        description="Mutelist configuration following Prowler format with nested structure: Mutelist → Accounts → Checks → Regions/Resources/Tags/Exceptions"
    )
    inserted_at: str | None = Field(
        default=None,
        description="ISO 8601 timestamp when this mutelist was created",
    )
    updated_at: str | None = Field(
        default=None,
        description="ISO 8601 timestamp when this mutelist was last modified",
    )

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> "MutelistResponse":
        """Transform JSON:API processor response to simplified format.

        The configuration structure follows the Prowler mutelist format:
        {
            "Mutelist": {
                "Accounts": {
                    "<account-pattern>": {
                        "Checks": {
                            "<check-id>": {
                                "Regions": [...],
                                "Resources": [...],
                                "Tags": [...],
                                "Exceptions": {...}
                            }
                        }
                    }
                }
            }
        }
        """
        attributes = data.get("attributes", {})

        return cls(
            id=data["id"],
            configuration=attributes.get("configuration", {}),
            inserted_at=attributes.get("inserted_at"),
            updated_at=attributes.get("updated_at"),
        )


class SimplifiedMuteRule(MinimalSerializerMixin, BaseModel):
    """Simplified mute rule for list/search operations.

    Provides lightweight mute rule information without the full list of finding UIDs.
    Use this for listing and searching operations where you need basic rule information
    but don't need the complete list of affected findings.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(
        description="Unique UUIDv4 identifier for this mute rule in Prowler database"
    )
    name: str = Field(description="Human-readable name for this mute rule")
    reason: str = Field(description="Documented reason for muting these findings")
    enabled: bool = Field(
        description="Whether this mute rule is currently active and applying muting to findings"
    )
    finding_count: int = Field(
        description="Number of findings currently muted by this rule", ge=0
    )
    inserted_at: str | None = Field(
        default=None,
        description="ISO 8601 timestamp when this mute rule was created",
    )
    updated_at: str | None = Field(
        default=None,
        description="ISO 8601 timestamp when this mute rule was last modified",
    )

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> "SimplifiedMuteRule":
        """Transform JSON:API mute rule response to simplified format."""
        attributes = data.get("attributes", {})

        # Calculate finding count from finding_uids list length
        finding_uids = attributes.get("finding_uids", [])

        return cls(
            id=data["id"],
            name=attributes["name"],
            reason=attributes["reason"],
            enabled=attributes["enabled"],
            finding_count=len(finding_uids),
            inserted_at=attributes.get("inserted_at"),
            updated_at=attributes.get("updated_at"),
        )


class DetailedMuteRule(SimplifiedMuteRule):
    """Detailed mute rule with complete information including finding UIDs.

    Extends SimplifiedMuteRule with the full list of finding UIDs being muted and
    creator information (user/service account that created the rule).
    Use this when you need complete context about a specific mute rule, including
    all affected findings and audit trail information.
    """

    finding_uids: list[str] = Field(
        description="List of finding UIDs that are muted by this rule"
    )
    user_creator_id: str | None = Field(
        default=None,
        description="UUIDv4 identifier of the Prowler user from the tenant that created this rule",
    )

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> "DetailedMuteRule":
        """Transform JSON:API mute rule response to detailed format."""
        attributes = data.get("attributes", {})
        relationships = data.get("relationships", {})

        # Extract creator information
        user_creator_id = None
        creator_data = relationships.get("created_by", {}).get("data")
        if creator_data:
            user_creator_id = creator_data.get("id")

        finding_uids = attributes.get("finding_uids", [])

        return cls(
            id=data["id"],
            name=attributes["name"],
            reason=attributes["reason"],
            enabled=attributes["enabled"],
            finding_count=len(finding_uids),
            finding_uids=finding_uids,
            inserted_at=attributes.get("inserted_at"),
            updated_at=attributes.get("updated_at"),
            user_creator_id=user_creator_id,
        )


class MuteRulesListResponse(BaseModel):
    """Simplified response for mute rules list queries with pagination.

    Contains a list of simplified mute rules and pagination metadata.
    Use this for paginated list/search operations to get multiple rules efficiently.
    """

    model_config = ConfigDict(frozen=True)

    mute_rules: list[SimplifiedMuteRule] = Field(
        description="List of simplified mute rules matching the query filters"
    )
    total_num_mute_rules: int = Field(
        description="Total number of mute rules matching the query across all pages",
        ge=0,
    )
    total_num_pages: int = Field(
        description="Total number of pages available for the query results", ge=0
    )
    current_page: int = Field(
        description="Current page number in the paginated results (1-indexed)", ge=1
    )

    @classmethod
    def from_api_response(cls, response: dict[str, Any]) -> "MuteRulesListResponse":
        """Transform JSON:API response to simplified format."""
        data = response.get("data", [])
        meta = response.get("meta", {})
        pagination = meta.get("pagination", {})

        mute_rules = [SimplifiedMuteRule.from_api_response(item) for item in data]

        return cls(
            mute_rules=mute_rules,
            total_num_mute_rules=pagination.get("count", 0),
            total_num_pages=pagination.get("pages", 1),
            current_page=pagination.get("page", 1),
        )
