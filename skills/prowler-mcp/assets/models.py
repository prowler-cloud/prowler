# Example: MCP Models with MinimalSerializerMixin (abridged)
# Source: mcp_server/prowler_mcp_server/prowler_app/models/findings.py
#         mcp_server/prowler_mcp_server/prowler_app/models/base.py (the mixin)
#
# Key patterns:
# - Item models extend MinimalSerializerMixin: None, "", [] and {} are dropped
#   from model_dump() to save tokens.
# - Two tiers: Simplified* for lists, Detailed* (subclass) for one item.
# - *ListResponse reads meta.pagination {count, pages, page}.
# - from_api_response() maps the JSON:API resource; index required keys with []
#   so a contract change fails loudly, use .get() only for optional ones.

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from prowler_mcp_server.prowler_app.models.base import MinimalSerializerMixin


class SimplifiedFinding(MinimalSerializerMixin, BaseModel):
    """Lightweight finding for list responses."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(description="Unique UUIDv4 identifier for this finding")
    uid: str = Field(description="Human-readable unique identifier assigned by Prowler")
    status: Literal["FAIL", "PASS", "MANUAL"] = Field(description="Result status")
    severity: Literal["critical", "high", "medium", "low", "informational"] = Field(
        description="Severity level of the finding"
    )
    check_id: str = Field(description="ID of the check that generated this finding")
    status_extended: str = Field(description="Extended status information")
    muted: bool | None = Field(default=None, description="Whether the finding is muted")
    muted_reason: str | None = Field(default=None, description="Reason for muting")

    @classmethod
    def from_api_response(cls, data: dict) -> "SimplifiedFinding":
        attributes = data["attributes"]
        return cls(
            id=data["id"],
            uid=attributes["uid"],
            status=attributes["status"],
            severity=attributes["severity"],
            # Derived field: check_id lives inside check_metadata in the API
            check_id=attributes["check_metadata"]["checkid"],
            status_extended=attributes["status_extended"],
            muted=attributes["muted"],
            muted_reason=attributes["muted_reason"],
        )


class DetailedFinding(SimplifiedFinding):
    """Full finding for a single-item response; adds timestamps and relationships."""

    model_config = ConfigDict(frozen=True)

    inserted_at: str = Field(description="ISO 8601 timestamp of first insertion")
    scan_id: str | None = Field(default=None, description="UUID of the scan")
    resource_ids: list[str] = Field(
        default_factory=list, description="UUIDs of the associated resources"
    )
    check_metadata: dict = Field(
        description="Check metadata from the API, including remediation (the shipped server models it as CheckMetadata)",
    )

    @classmethod
    def from_api_response(cls, data: dict) -> "DetailedFinding":
        attributes = data["attributes"]
        relationships = data.get("relationships", {})

        scan_data = relationships.get("scan", {}).get("data")
        resources_data = relationships.get("resources", {}).get("data", [])

        return cls(
            id=data["id"],
            uid=attributes["uid"],
            status=attributes["status"],
            severity=attributes["severity"],
            check_id=attributes["check_metadata"]["checkid"],
            status_extended=attributes.get("status_extended"),
            muted=attributes["muted"],
            muted_reason=attributes.get("muted_reason"),
            inserted_at=attributes["inserted_at"],
            scan_id=scan_data["id"] if scan_data else None,
            resource_ids=[r["id"] for r in resources_data],
            check_metadata=attributes["check_metadata"],
        )


class FindingsListResponse(BaseModel):
    """List wrapper with pagination; plain BaseModel, as in the source."""

    model_config = ConfigDict(frozen=True)

    findings: list[SimplifiedFinding] = Field(description="Findings on this page")
    total_num_finding: int = Field(description="Total matches across pages", ge=0)
    total_num_pages: int = Field(description="Total number of pages", ge=0)
    current_page: int = Field(description="Current page (1-indexed)", ge=1)

    @classmethod
    def from_api_response(cls, response: dict) -> "FindingsListResponse":
        pagination = response["meta"]["pagination"]
        return cls(
            findings=[SimplifiedFinding.from_api_response(i) for i in response["data"]],
            total_num_finding=pagination["count"],
            total_num_pages=pagination["pages"],
            current_page=pagination["page"],
        )
