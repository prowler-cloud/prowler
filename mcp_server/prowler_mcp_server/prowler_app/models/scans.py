"""Data models for Prowler scans.

This module provides Pydantic models for representing Prowler security scans
with two-tier complexity:
- SimplifiedScan: For list operations with essential fields
- DetailedScan: Extends simplified with additional operational fields

All models inherit from MinimalSerializerMixin to exclude None/empty values
for optimal LLM token usage.
"""

from typing import Any, Literal

from prowler_mcp_server.prowler_app.models.base import MinimalSerializerMixin
from pydantic import BaseModel, ConfigDict, Field


class SimplifiedScan(MinimalSerializerMixin, BaseModel):
    """Simplified scan representation for list operations.

    Includes core scan fields for efficient overview.
    Used by list_scans() tool.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(
        description="Unique UUIDv4 identifier for this scan in Prowler database"
    )
    name: str | None = Field(
        default=None,
        description="Optional custom name for the scan to help identify it",
    )
    trigger: Literal["manual", "scheduled"] = Field(
        description="How the scan was initiated: 'manual' (user-triggered) or 'scheduled' (automated)"
    )
    state: Literal[
        "available", "scheduled", "executing", "completed", "failed", "cancelled"
    ] = Field(
        description="Current state of the scan: available, scheduled, executing, completed, failed, or cancelled"
    )
    started_at: str | None = Field(
        default=None, description="ISO 8601 timestamp when the scan started execution"
    )
    completed_at: str | None = Field(
        default=None,
        description="ISO 8601 timestamp when the scan finished (completed or failed)",
    )
    provider_id: str = Field(
        description="UUIDv4 identifier of the provider this scan is associated with"
    )

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> "SimplifiedScan":
        """Transform JSON:API scan response to simplified model.

        Args:
            data: Scan data from API response['data'] (single item or list item)

        Returns:
            SimplifiedScan instance
        """
        attributes = data["attributes"]
        relationships = data.get("relationships", {})

        provider_id = relationships.get("provider", {}).get("data", {}).get("id", None)

        return cls(
            id=data["id"],
            name=attributes.get("name"),
            trigger=attributes["trigger"],
            state=attributes["state"],
            started_at=attributes.get("started_at"),
            completed_at=attributes.get("completed_at"),
            provider_id=provider_id,
        )


class DetailedScan(SimplifiedScan):
    """Detailed scan representation with full operational data.

    Extends SimplifiedScan with progress, duration, resources, and relationships.
    Used by get_scan() and create_scan() tools.
    """

    model_config = ConfigDict(frozen=True)

    progress: int | None = Field(
        default=None, description="Scan completion progress as percentage (0-100)"
    )
    duration: int | None = Field(
        default=None,
        description="Total scan duration in seconds from start to completion",
    )
    unique_resource_count: int | None = Field(
        default=None,
        description="Number of unique cloud resources discovered during the scan",
    )
    inserted_at: str | None = Field(
        default=None,
        description="ISO 8601 timestamp when the scan was created in the database",
    )
    scheduled_at: str | None = Field(
        default=None,
        description="ISO 8601 timestamp when the scan was scheduled to run",
    )
    next_scan_at: str | None = Field(
        default=None,
        description="ISO 8601 timestamp for the next scheduled scan (for recurring scans)",
    )

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> "DetailedScan":
        """Transform JSON:API scan response to detailed model.

        Args:
            data: Scan data from API response['data']

        Returns:
            DetailedScan instance with all fields populated
        """
        attributes = data["attributes"]
        relationships = data.get("relationships", {})

        # Extract provider ID from relationship
        provider_rel = relationships.get("provider", {}).get("data", {})
        provider_id = provider_rel.get("id", "")

        # Extract task relationship
        task_rel = relationships.get("task", {}).get("data")
        task_id = task_rel.get("id") if task_rel else None

        # Extract processor relationship
        processor_rel = relationships.get("processor", {}).get("data")
        processor_id = processor_rel.get("id") if processor_rel else None

        return cls(
            id=data["id"],
            name=attributes.get("name"),
            trigger=attributes["trigger"],
            state=attributes["state"],
            started_at=attributes.get("started_at"),
            completed_at=attributes.get("completed_at"),
            provider_id=provider_id,
            progress=attributes.get("progress"),
            duration=attributes.get("duration"),
            unique_resource_count=attributes.get("unique_resource_count"),
            inserted_at=attributes.get("inserted_at"),
            scheduled_at=attributes.get("scheduled_at"),
            next_scan_at=attributes.get("next_scan_at"),
            task_id=task_id,
            processor_id=processor_id,
        )


class ScansListResponse(BaseModel):
    """Response model for list_scans() with pagination metadata.

    Follows established pattern from FindingsListResponse and ProvidersListResponse.
    """

    scans: list[SimplifiedScan]
    total_num_scans: int
    total_num_pages: int
    current_page: int

    @classmethod
    def from_api_response(cls, response: dict[str, Any]) -> "ScansListResponse":
        """Transform JSON:API list response to scans list with pagination.

        Args:
            response: Full API response with data and meta

        Returns:
            ScansListResponse with simplified scans and pagination metadata
        """
        data = response.get("data", [])
        meta = response.get("meta", {})
        pagination = meta.get("pagination", {})

        # Transform each scan
        scans = [SimplifiedScan.from_api_response(item) for item in data]

        return cls(
            scans=scans,
            total_num_scans=pagination.get("count", 0),
            total_num_pages=pagination.get("pages", 0),
            current_page=pagination.get("page", 1),
        )


class ScanCreationResult(MinimalSerializerMixin, BaseModel):
    """Result of scan creation operation.

    Used by trigger_scan() to communicate the outcome of scan creation.
    Status indicates whether scan was created successfully or failed.
    """

    scan: DetailedScan | None = Field(
        default=None,
        description="Detailed scan information if creation succeeded, None otherwise",
    )
    status: Literal["success", "failed"] = Field(
        description="Outcome of scan creation: success (scan created successfully) or failed (error)"
    )
    message: str = Field(
        description="Human-readable message describing the scan creation result"
    )


class ScheduleCreationResult(MinimalSerializerMixin, BaseModel):
    """Result of async schedule creation operation.

    Used by schedule_daily_scan() to communicate scheduling outcome.
    """

    scheduled: bool = Field(
        description="Whether the daily scan schedule was created successfully"
    )
    message: str = Field(
        description="Human-readable message describing the scheduling result"
    )
