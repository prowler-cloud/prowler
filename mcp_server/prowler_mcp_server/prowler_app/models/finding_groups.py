"""Pydantic models for Prowler Finding Groups responses."""

from typing import Literal

from pydantic import Field

from prowler_mcp_server.prowler_app.models.base import MinimalSerializerMixin


FindingStatus = Literal["FAIL", "PASS", "MANUAL"]
FindingSeverity = Literal["critical", "high", "medium", "low", "informational"]
FindingDelta = Literal["new", "changed"]


def _attributes(data: dict) -> dict:
    return data.get("attributes", {})


def _counter(attributes: dict, key: str) -> int:
    return attributes.get(key) or 0


def _simplified_group_kwargs(data: dict) -> dict:
    attributes = _attributes(data)
    return {
        "check_id": attributes.get("check_id", data.get("id", "")),
        "check_title": attributes.get("check_title"),
        "severity": attributes.get("severity", "informational"),
        "status": attributes.get("status", "MANUAL"),
        "muted": attributes.get("muted", False),
        "impacted_providers": attributes.get("impacted_providers") or [],
        "resources_fail": _counter(attributes, "resources_fail"),
        "resources_total": _counter(attributes, "resources_total"),
        "pass_count": _counter(attributes, "pass_count"),
        "fail_count": _counter(attributes, "fail_count"),
        "manual_count": _counter(attributes, "manual_count"),
        "muted_count": _counter(attributes, "muted_count"),
        "new_count": _counter(attributes, "new_count"),
        "changed_count": _counter(attributes, "changed_count"),
        "first_seen_at": attributes.get("first_seen_at"),
        "last_seen_at": attributes.get("last_seen_at"),
        "failing_since": attributes.get("failing_since"),
    }


class SimplifiedFindingGroup(MinimalSerializerMixin):
    """Finding group summary optimized for browsing many checks."""

    check_id: str = Field(description="Public check ID that identifies this group")
    check_title: str | None = Field(
        default=None, description="Human-readable check title"
    )
    severity: FindingSeverity = Field(description="Highest severity in the group")
    status: FindingStatus = Field(description="Aggregated finding group status")
    muted: bool = Field(
        description="Whether all findings in this group are muted or accepted"
    )
    impacted_providers: list[str] = Field(
        default_factory=list,
        description="Provider types impacted by this finding group",
    )
    resources_fail: int = Field(
        description="Number of non-muted failing resources in this group", ge=0
    )
    resources_total: int = Field(
        description="Total number of resources in this group", ge=0
    )
    pass_count: int = Field(
        description="Number of non-muted PASS findings in this group", ge=0
    )
    fail_count: int = Field(
        description="Number of non-muted FAIL findings in this group", ge=0
    )
    manual_count: int = Field(
        description="Number of non-muted MANUAL findings in this group", ge=0
    )
    muted_count: int = Field(description="Total muted findings in this group", ge=0)
    new_count: int = Field(description="Number of new non-muted findings", ge=0)
    changed_count: int = Field(description="Number of changed non-muted findings", ge=0)
    first_seen_at: str | None = Field(
        default=None, description="First time this group was detected"
    )
    last_seen_at: str | None = Field(
        default=None, description="Last time this group was detected"
    )
    failing_since: str | None = Field(
        default=None, description="First time this group started failing"
    )

    @classmethod
    def from_api_response(cls, data: dict) -> "SimplifiedFindingGroup":
        """Transform JSON:API finding group response to simplified format."""
        return cls(**_simplified_group_kwargs(data))


class DetailedFindingGroup(SimplifiedFindingGroup):
    """Finding group with complete counters and descriptive context."""

    check_description: str | None = Field(
        default=None, description="Description of the check behind this group"
    )
    pass_muted_count: int = Field(description="Muted PASS findings", ge=0)
    fail_muted_count: int = Field(description="Muted FAIL findings", ge=0)
    manual_muted_count: int = Field(description="Muted MANUAL findings", ge=0)
    new_fail_count: int = Field(description="New non-muted FAIL findings", ge=0)
    new_fail_muted_count: int = Field(description="New muted FAIL findings", ge=0)
    new_pass_count: int = Field(description="New non-muted PASS findings", ge=0)
    new_pass_muted_count: int = Field(description="New muted PASS findings", ge=0)
    new_manual_count: int = Field(description="New non-muted MANUAL findings", ge=0)
    new_manual_muted_count: int = Field(description="New muted MANUAL findings", ge=0)
    changed_fail_count: int = Field(description="Changed non-muted FAIL findings", ge=0)
    changed_fail_muted_count: int = Field(
        description="Changed muted FAIL findings", ge=0
    )
    changed_pass_count: int = Field(description="Changed non-muted PASS findings", ge=0)
    changed_pass_muted_count: int = Field(
        description="Changed muted PASS findings", ge=0
    )
    changed_manual_count: int = Field(
        description="Changed non-muted MANUAL findings", ge=0
    )
    changed_manual_muted_count: int = Field(
        description="Changed muted MANUAL findings", ge=0
    )

    @classmethod
    def from_api_response(cls, data: dict) -> "DetailedFindingGroup":
        """Transform JSON:API finding group response to detailed format."""
        attributes = _attributes(data)

        return cls(
            **_simplified_group_kwargs(data),
            check_description=attributes.get("check_description"),
            pass_muted_count=_counter(attributes, "pass_muted_count"),
            fail_muted_count=_counter(attributes, "fail_muted_count"),
            manual_muted_count=_counter(attributes, "manual_muted_count"),
            new_fail_count=_counter(attributes, "new_fail_count"),
            new_fail_muted_count=_counter(attributes, "new_fail_muted_count"),
            new_pass_count=_counter(attributes, "new_pass_count"),
            new_pass_muted_count=_counter(attributes, "new_pass_muted_count"),
            new_manual_count=_counter(attributes, "new_manual_count"),
            new_manual_muted_count=_counter(attributes, "new_manual_muted_count"),
            changed_fail_count=_counter(attributes, "changed_fail_count"),
            changed_fail_muted_count=_counter(attributes, "changed_fail_muted_count"),
            changed_pass_count=_counter(attributes, "changed_pass_count"),
            changed_pass_muted_count=_counter(attributes, "changed_pass_muted_count"),
            changed_manual_count=_counter(attributes, "changed_manual_count"),
            changed_manual_muted_count=_counter(
                attributes, "changed_manual_muted_count"
            ),
        )


class FindingGroupsListResponse(MinimalSerializerMixin):
    """Paginated response for finding group list queries."""

    groups: list[SimplifiedFindingGroup] = Field(
        description="Finding groups matching the query"
    )
    total_num_groups: int = Field(
        description="Total groups matching the query across all pages", ge=0
    )
    total_num_pages: int = Field(description="Total pages available", ge=0)
    current_page: int = Field(description="Current page number", ge=1)

    @classmethod
    def from_api_response(cls, response: dict) -> "FindingGroupsListResponse":
        """Transform JSON:API list response to simplified format."""
        pagination = response.get("meta", {}).get("pagination", {})
        groups = [
            SimplifiedFindingGroup.from_api_response(item)
            for item in response.get("data", [])
        ]

        return cls(
            groups=groups,
            total_num_groups=pagination.get("count", len(groups)),
            total_num_pages=pagination.get("pages", 1),
            current_page=pagination.get("page", 1),
        )


class FindingGroupResourceInfo(MinimalSerializerMixin):
    """Nested resource information for a finding group row."""

    uid: str = Field(description="Provider-native resource UID")
    name: str = Field(description="Resource name")
    service: str = Field(description="Cloud service")
    region: str = Field(description="Cloud region")
    type: str = Field(description="Resource type")
    resource_group: str | None = Field(
        default=None, description="Provider resource group or equivalent"
    )

    @classmethod
    def from_api_response(cls, data: dict) -> "FindingGroupResourceInfo":
        """Transform nested resource data to simplified format."""
        return cls(
            uid=data.get("uid", ""),
            name=data.get("name", ""),
            service=data.get("service", ""),
            region=data.get("region", ""),
            type=data.get("type", ""),
            resource_group=data.get("resource_group"),
        )


class FindingGroupProviderInfo(MinimalSerializerMixin):
    """Nested provider information for a finding group resource row."""

    type: str = Field(description="Provider type")
    uid: str = Field(description="Provider-native account or subscription ID")
    alias: str | None = Field(default=None, description="Provider alias")

    @classmethod
    def from_api_response(cls, data: dict) -> "FindingGroupProviderInfo":
        """Transform nested provider data to simplified format."""
        return cls(
            type=data.get("type", ""),
            uid=data.get("uid", ""),
            alias=data.get("alias"),
        )


class FindingGroupResource(MinimalSerializerMixin):
    """Resource row affected by a finding group."""

    id: str = Field(description="Row identifier for this finding group resource")
    resource: FindingGroupResourceInfo = Field(description="Affected resource")
    provider: FindingGroupProviderInfo = Field(description="Affected provider")
    finding_id: str = Field(
        description="Finding UUID to use with prowler_app_get_finding_details"
    )
    status: FindingStatus = Field(description="Finding status for this resource")
    severity: FindingSeverity = Field(description="Finding severity")
    muted: bool = Field(description="Whether the finding is muted")
    delta: FindingDelta | None = Field(default=None, description="Change status")
    first_seen_at: str | None = Field(default=None, description="First seen time")
    last_seen_at: str | None = Field(default=None, description="Last seen time")
    muted_reason: str | None = Field(default=None, description="Mute reason")

    @classmethod
    def from_api_response(cls, data: dict) -> "FindingGroupResource":
        """Transform JSON:API finding group resource response."""
        attributes = _attributes(data)

        return cls(
            id=data.get("id", ""),
            resource=FindingGroupResourceInfo.from_api_response(
                attributes.get("resource") or {}
            ),
            provider=FindingGroupProviderInfo.from_api_response(
                attributes.get("provider") or {}
            ),
            finding_id=str(attributes.get("finding_id", "")),
            status=attributes.get("status", "MANUAL"),
            severity=attributes.get("severity", "informational"),
            muted=attributes.get("muted", False),
            delta=attributes.get("delta"),
            first_seen_at=attributes.get("first_seen_at"),
            last_seen_at=attributes.get("last_seen_at"),
            muted_reason=attributes.get("muted_reason"),
        )


class FindingGroupResourcesListResponse(MinimalSerializerMixin):
    """Paginated response for finding group resource queries."""

    resources: list[FindingGroupResource] = Field(
        description="Resources matching the finding group query"
    )
    total_num_resources: int = Field(
        description="Total resources matching the query across all pages", ge=0
    )
    total_num_pages: int = Field(description="Total pages available", ge=0)
    current_page: int = Field(description="Current page number", ge=1)

    @classmethod
    def from_api_response(cls, response: dict) -> "FindingGroupResourcesListResponse":
        """Transform JSON:API resource list response to simplified format."""
        pagination = response.get("meta", {}).get("pagination", {})
        resources = [
            FindingGroupResource.from_api_response(item)
            for item in response.get("data", [])
        ]

        return cls(
            resources=resources,
            total_num_resources=pagination.get("count", len(resources)),
            total_num_pages=pagination.get("pages", 1),
            current_page=pagination.get("page", 1),
        )
