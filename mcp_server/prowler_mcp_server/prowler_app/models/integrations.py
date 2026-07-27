"""Pydantic models for simplified integration responses."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from prowler_mcp_server.prowler_app.models.base import MinimalSerializerMixin


class SimplifiedIntegration(MinimalSerializerMixin, BaseModel):
    """Simplified integration for list operations.

    Contains the identification and state fields needed to decide which integration
    to inspect further, without the integration-type specific configuration.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(
        description="Unique UUIDv4 identifier for this integration in Prowler database"
    )
    integration_type: str = Field(
        description="Type of the integration. One of 'amazon_s3', 'aws_security_hub' or 'jira'"
    )
    enabled: bool = Field(
        description="Whether this integration is active. Disabled integrations are never used after a scan and always fail the connection check"
    )
    connected: bool | None = Field(
        default=None,
        description="Result of the last connection check: True if the credentials work, False if they failed, null if the connection was never checked",
    )
    connection_last_checked_at: str | None = Field(
        default=None,
        description="ISO 8601 timestamp of the last connection check, null if it was never checked",
    )
    provider_ids: list[str] = Field(
        default=[],
        description="Prowler UUIDv4 identifiers of the providers this integration is attached to. Empty for tenant-wide integrations such as Jira",
    )
    inserted_at: str | None = Field(
        default=None,
        description="ISO 8601 timestamp when this integration was created",
    )
    updated_at: str | None = Field(
        default=None,
        description="ISO 8601 timestamp when this integration was last modified",
    )

    def _should_exclude(self, key: str, value: Any) -> bool:
        """Override to always include the connected field even when None."""
        # `null` means "never checked", which is different from "not connected"
        if key == "connected":
            return False
        return super()._should_exclude(key, value)

    @classmethod
    def _extract_provider_ids(cls, data: dict[str, Any]) -> list[str]:
        """Read the provider relationship linkage of a JSON:API integration resource."""
        providers = data.get("relationships", {}).get("providers", {}).get("data") or []
        return [provider["id"] for provider in providers]

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> "SimplifiedIntegration":
        """Transform JSON:API integration response to simplified format."""
        attributes = data.get("attributes", {})

        return cls(
            id=data["id"],
            integration_type=attributes["integration_type"],
            enabled=attributes["enabled"],
            connected=attributes.get("connected"),
            connection_last_checked_at=attributes.get("connection_last_checked_at"),
            provider_ids=cls._extract_provider_ids(data),
            inserted_at=attributes.get("inserted_at"),
            updated_at=attributes.get("updated_at"),
        )


class DetailedIntegration(SimplifiedIntegration):
    """Detailed integration including its integration-type specific configuration.

    Credentials are never returned by the Prowler API, so they are never part of this
    model.
    """

    configuration: dict[str, Any] = Field(
        default={},
        description=(
            "Integration-type specific settings. "
            "For 'amazon_s3': 'bucket_name' and 'output_directory'. "
            "For 'aws_security_hub': 'send_only_fails', 'archive_previous_findings' and "
            "'enabled_regions' (the list of AWS regions Security Hub is enabled in, discovered by the connection check). "
            "For 'jira': 'domain', 'projects' (a mapping of project key to project name) and "
            "'issue_types' (a mapping of project key to the available issue types), all discovered by the connection check"
        ),
    )

    @classmethod
    def _build_configuration(
        cls, integration_type: str, configuration: dict[str, Any]
    ) -> dict[str, Any]:
        """Normalize the raw configuration for LLM consumption."""
        configuration = dict(configuration or {})

        if integration_type == "aws_security_hub":
            # The API stores every Security Hub region of the partition with a boolean,
            # which is mostly noise. Only the enabled ones carry information.
            regions = configuration.pop("regions", None)
            if isinstance(regions, dict):
                configuration["enabled_regions"] = sorted(
                    region for region, enabled in regions.items() if enabled
                )

        return configuration

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> "DetailedIntegration":
        """Transform JSON:API integration response to detailed format."""
        attributes = data.get("attributes", {})
        integration_type = attributes["integration_type"]

        return cls(
            id=data["id"],
            integration_type=integration_type,
            enabled=attributes["enabled"],
            connected=attributes.get("connected"),
            connection_last_checked_at=attributes.get("connection_last_checked_at"),
            provider_ids=cls._extract_provider_ids(data),
            inserted_at=attributes.get("inserted_at"),
            updated_at=attributes.get("updated_at"),
            configuration=cls._build_configuration(
                integration_type, attributes.get("configuration", {})
            ),
        )


class IntegrationsListResponse(BaseModel):
    """Simplified response for integration list queries with pagination."""

    model_config = ConfigDict(frozen=True)

    integrations: list[SimplifiedIntegration] = Field(
        description="List of simplified integrations matching the query filters"
    )
    total_num_integrations: int = Field(
        description="Total number of integrations matching the query across all pages",
        ge=0,
    )
    total_num_pages: int = Field(
        description="Total number of pages available for the query results", ge=0
    )
    current_page: int = Field(
        description="Current page number in the paginated results (1-indexed)", ge=1
    )

    @classmethod
    def from_api_response(cls, response: dict[str, Any]) -> "IntegrationsListResponse":
        """Transform JSON:API response to simplified format."""
        data = response.get("data", [])
        pagination = response.get("meta", {}).get("pagination", {})

        return cls(
            integrations=[
                SimplifiedIntegration.from_api_response(item) for item in data
            ],
            total_num_integrations=pagination.get("count", 0),
            total_num_pages=pagination.get("pages", 1),
            current_page=pagination.get("page", 1),
        )


class IntegrationConnectionStatus(MinimalSerializerMixin, BaseModel):
    """Result of an integration connection check."""

    model_config = ConfigDict(frozen=True)

    integration: DetailedIntegration = Field(
        description="State of the integration after the connection check"
    )
    connected: Literal["connected", "failed", "not_tested"] = Field(
        description="Outcome of the connection check: 'connected' if Prowler could reach the destination with the given credentials, 'failed' otherwise, 'not_tested' if the check did not run"
    )
    error: str | None = Field(
        default=None,
        description="Reason why the connection check failed, absent when it succeeded",
    )

    @classmethod
    def create(
        cls,
        integration_data: dict[str, Any],
        connection_status: dict[str, Any],
    ) -> "IntegrationConnectionStatus":
        """Create the connection status from the integration data and the check result."""
        connected: bool | None = connection_status.get("connected", None)

        if connected is None:
            connected = "not_tested"
        elif connected:
            connected = "connected"
        else:
            connected = "failed"

        return cls(
            integration=DetailedIntegration.from_api_response(integration_data),
            connected=connected,
            error=connection_status.get("error", None),
        )


class JiraIssueTypes(MinimalSerializerMixin, BaseModel):
    """Issue types available in a Jira project."""

    model_config = ConfigDict(frozen=True)

    project_key: str = Field(
        description="Jira project key the issue types belong to (e.g. 'PRWLR')"
    )
    issue_types: list[str] = Field(
        description="Issue types that can be used when sending findings to this project (e.g. 'Task', 'Bug', 'Story')"
    )

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> "JiraIssueTypes":
        """Transform JSON:API issue types response to simplified format."""
        # This endpoint returns a non-model resource, so tolerate an unwrapped payload
        attributes = data.get("attributes") or data

        return cls(
            project_key=attributes["project_key"],
            issue_types=attributes.get("issue_types", []),
        )


class JiraDispatchResult(MinimalSerializerMixin, BaseModel):
    """Result of sending findings to Jira as work items."""

    model_config = ConfigDict(frozen=True)

    dispatched: bool = Field(
        description="True if Prowler accepted and ran the dispatch. When this is True the work items may already exist in Jira, so the dispatch must not be retried"
    )
    created_count: int = Field(
        default=0, description="Number of Jira work items successfully created", ge=0
    )
    failed_count: int = Field(
        default=0, description="Number of findings that could not be sent to Jira", ge=0
    )
    error: str | None = Field(
        default=None,
        description="Reason why the dispatch failed or is still in progress, absent when it completed cleanly",
    )
    task_id: str | None = Field(
        default=None,
        description="UUIDv4 of the background task, only present when the dispatch did not finish within the polling window and is still running",
    )

    def _should_exclude(self, key: str, value: Any) -> bool:
        """Override to always include the counters, even when zero."""
        # A zero count is a meaningful outcome, not noise
        if key in ("created_count", "failed_count"):
            return False
        return super()._should_exclude(key, value)

    @classmethod
    def from_task_result(
        cls, result: dict[str, Any], task_id: str | None = None
    ) -> "JiraDispatchResult":
        """Build the dispatch result from the completed background task result."""
        return cls(
            dispatched=True,
            created_count=result.get("created_count", 0),
            failed_count=result.get("failed_count", 0),
            error=result.get("error"),
            task_id=task_id,
        )
