"""Finding Groups tools for Prowler App MCP Server.

This module provides read-only tools for finding group triage and drill-downs.
"""

from typing import Any, Literal
from urllib.parse import quote

from pydantic import Field

from prowler_mcp_server.prowler_app.models.finding_groups import (
    DetailedFindingGroup,
    FindingGroupResourcesListResponse,
    FindingGroupsListResponse,
)
from prowler_mcp_server.prowler_app.tools.base import BaseTool


StatusFilter = Literal["FAIL", "PASS", "MANUAL"]
SeverityFilter = Literal["critical", "high", "medium", "low", "informational"]
DeltaFilter = Literal["new", "changed"]

GROUP_DETAIL_FIELDS = (
    "check_id,check_title,check_description,severity,status,muted,"
    "impacted_providers,resources_fail,resources_total,pass_count,fail_count,"
    "manual_count,pass_muted_count,fail_muted_count,manual_muted_count,"
    "muted_count,new_count,changed_count,new_fail_count,new_fail_muted_count,"
    "new_pass_count,new_pass_muted_count,new_manual_count,new_manual_muted_count,"
    "changed_fail_count,changed_fail_muted_count,changed_pass_count,"
    "changed_pass_muted_count,changed_manual_count,changed_manual_muted_count,"
    "first_seen_at,last_seen_at,failing_since"
)

GROUP_LIST_FIELDS = (
    "check_id,check_title,severity,status,muted,impacted_providers,"
    "resources_fail,resources_total,pass_count,fail_count,manual_count,"
    "muted_count,new_count,changed_count,first_seen_at,last_seen_at,failing_since"
)

RESOURCE_FIELDS = (
    "resource,provider,finding_id,status,severity,muted,delta,"
    "first_seen_at,last_seen_at,muted_reason"
)


class FindingGroupsTools(BaseTool):
    """Tools for Finding Groups operations."""

    @staticmethod
    def _bool_value(value: bool | str) -> bool:
        """Normalize bool-like MCP client values."""
        if isinstance(value, bool):
            return value
        return value.lower() == "true"

    @staticmethod
    def _group_endpoint(date_range: tuple[str, str] | None) -> str:
        return "/finding-groups/latest" if date_range is None else "/finding-groups"

    @staticmethod
    def _resource_endpoint(check_id: str, date_range: tuple[str, str] | None) -> str:
        escaped_check_id = quote(check_id, safe="")
        if date_range is None:
            return f"/finding-groups/latest/{escaped_check_id}/resources"
        return f"/finding-groups/{escaped_check_id}/resources"

    def _base_date_params(
        self, date_from: str | None, date_to: str | None
    ) -> tuple[tuple[str, str] | None, dict[str, Any]]:
        date_range = self.api_client.normalize_date_range(
            date_from, date_to, max_days=2
        )
        if date_range is None:
            return None, {}

        return date_range, {
            "filter[inserted_at__gte]": date_range[0],
            "filter[inserted_at__lte]": date_range[1],
        }

    def _apply_common_filters(
        self,
        params: dict[str, Any],
        provider: list[str],
        provider_type: list[str],
        provider_uid: list[str],
        provider_alias: str | None,
        region: list[str],
        service: list[str],
        resource_type: list[str],
        resource_name: str | None,
        resource_uid: str | None,
        resource_group: list[str],
        category: list[str],
        check_id: list[str],
        check_title: str | None,
        severity: list[SeverityFilter],
        status: list[StatusFilter],
        muted: bool | str | None,
        delta: list[DeltaFilter],
    ) -> None:
        if provider:
            params["filter[provider__in]"] = provider
        if provider_type:
            params["filter[provider_type__in]"] = provider_type
        if provider_uid:
            params["filter[provider_uid__in]"] = provider_uid
        if provider_alias:
            params["filter[provider_alias__icontains]"] = provider_alias
        if region:
            params["filter[region__in]"] = region
        if service:
            params["filter[service__in]"] = service
        if resource_type:
            params["filter[resource_type__in]"] = resource_type
        if resource_name:
            params["filter[resource_name__icontains]"] = resource_name
        if resource_uid:
            params["filter[resource_uid__icontains]"] = resource_uid
        if resource_group:
            params["filter[resource_groups__in]"] = resource_group
        if category:
            params["filter[category__in]"] = category
        if check_id:
            params["filter[check_id__in]"] = check_id
        if check_title:
            params["filter[check_title__icontains]"] = check_title
        if severity:
            params["filter[severity__in]"] = severity
        if status:
            params["filter[status__in]"] = status
        if muted is not None:
            params["filter[muted]"] = self._bool_value(muted)
        if delta:
            params["filter[delta__in]"] = delta

    async def list_finding_groups(
        self,
        provider: list[str] = Field(
            default=[],
            description="Filter by provider UUIDs. Multiple values allowed. If empty, all visible providers are returned.",
        ),
        provider_type: list[str] = Field(
            default=[],
            description="Filter by provider type. Multiple values allowed, such as aws, azure, gcp, kubernetes, github, or m365.",
        ),
        provider_uid: list[str] = Field(
            default=[],
            description="Filter by provider-native account, subscription, or project IDs. Multiple values allowed.",
        ),
        provider_alias: str | None = Field(
            default=None,
            description="Filter by provider alias/name using partial matching.",
        ),
        region: list[str] = Field(
            default=[],
            description="Filter by cloud regions. Multiple values allowed.",
        ),
        service: list[str] = Field(
            default=[],
            description="Filter by cloud services. Multiple values allowed.",
        ),
        resource_type: list[str] = Field(
            default=[],
            description="Filter by resource types. Multiple values allowed.",
        ),
        resource_name: str | None = Field(
            default=None,
            description="Filter by resource name using partial matching.",
        ),
        resource_uid: str | None = Field(
            default=None,
            description="Filter by resource UID using partial matching.",
        ),
        resource_group: list[str] = Field(
            default=[],
            description="Filter by resource group values. Multiple values allowed.",
        ),
        category: list[str] = Field(
            default=[],
            description="Filter by finding categories. Multiple values allowed.",
        ),
        check_id: list[str] = Field(
            default=[],
            description="Filter by check IDs. Multiple values allowed.",
        ),
        check_title: str | None = Field(
            default=None,
            description="Filter by check title using partial matching.",
        ),
        severity: list[SeverityFilter] = Field(
            default=[],
            description="Filter by aggregated severity. Empty returns all severities.",
        ),
        status: list[StatusFilter] = Field(
            default=["FAIL"],
            description="Filter by aggregated status. Default returns failing groups. Pass [] to return all statuses.",
        ),
        muted: bool | str | None = Field(
            default=None,
            description="Filter by fully muted group state. Accepts true/false.",
        ),
        include_muted: bool | str = Field(
            default=False,
            description="When false, excludes fully muted groups. Set true to include fully muted groups.",
        ),
        delta: list[DeltaFilter] = Field(
            default=[],
            description="Filter by group delta values: new or changed.",
        ),
        date_from: str | None = Field(
            default=None,
            description="Start date for historical query in YYYY-MM-DD format. Maximum range is 2 days.",
        ),
        date_to: str | None = Field(
            default=None,
            description="End date for historical query in YYYY-MM-DD format. Maximum range is 2 days.",
        ),
        sort: str | None = Field(
            default=None,
            description="Optional sort expression supported by the finding-groups API, such as -fail_count,-severity,check_id.",
        ),
        page_size: int = Field(
            default=50, description="Number of groups to return per page"
        ),
        page_number: int = Field(
            default=1, description="Page number to retrieve (1-indexed)"
        ),
    ) -> dict[str, Any]:
        """List finding groups aggregated by check ID.

        Default behavior returns the latest non-muted FAIL groups for fast triage.
        Without dates this uses `/finding-groups/latest`. With `date_from` or
        `date_to`, this uses `/finding-groups` with a maximum 2-day date window.

        Use this tool to find noisy or high-impact checks, then call
        prowler_app_get_finding_group_details for complete counters or
        prowler_app_list_finding_group_resources to drill into affected resources.
        """
        try:
            self.api_client.validate_page_size(page_size)
            date_range, params = self._base_date_params(date_from, date_to)
            endpoint = self._group_endpoint(date_range)

            self._apply_common_filters(
                params,
                provider,
                provider_type,
                provider_uid,
                provider_alias,
                region,
                service,
                resource_type,
                resource_name,
                resource_uid,
                resource_group,
                category,
                check_id,
                check_title,
                severity,
                status,
                muted,
                delta,
            )

            params["filter[include_muted]"] = self._bool_value(include_muted)
            params["page[size]"] = page_size
            params["page[number]"] = page_number
            params["fields[finding-groups]"] = GROUP_LIST_FIELDS
            if sort:
                params["sort"] = sort

            clean_params = self.api_client.build_filter_params(params)
            api_response = await self.api_client.get(endpoint, params=clean_params)
            response = FindingGroupsListResponse.from_api_response(api_response)
            return response.model_dump()
        except Exception as e:
            self.logger.error(f"Error listing finding groups: {e}")
            return {"error": str(e), "status": "failed"}

    async def get_finding_group_details(
        self,
        check_id: str = Field(
            description="Public check ID that identifies the finding group. This is not a UUID."
        ),
        date_from: str | None = Field(
            default=None,
            description="Start date for historical query in YYYY-MM-DD format. Maximum range is 2 days.",
        ),
        date_to: str | None = Field(
            default=None,
            description="End date for historical query in YYYY-MM-DD format. Maximum range is 2 days.",
        ),
    ) -> dict[str, Any]:
        """Get complete details for one finding group by exact check ID.

        Uses `filter[check_id]` exact matching against latest data by default,
        or historical data when dates are provided. Fully muted groups are
        included by default so accepted risk does not look like a missing group.
        """
        try:
            date_range, params = self._base_date_params(date_from, date_to)
            endpoint = self._group_endpoint(date_range)

            params.update(
                {
                    "filter[check_id]": check_id,
                    "filter[include_muted]": True,
                    "page[size]": 1,
                    "page[number]": 1,
                    "fields[finding-groups]": GROUP_DETAIL_FIELDS,
                }
            )

            clean_params = self.api_client.build_filter_params(params)
            api_response = await self.api_client.get(endpoint, params=clean_params)
            data = api_response.get("data", [])

            if not data:
                return {
                    "error": f"Finding group '{check_id}' not found.",
                    "status": "not_found",
                }

            group = DetailedFindingGroup.from_api_response(data[0])
            return group.model_dump()
        except Exception as e:
            self.logger.error(f"Error getting finding group details: {e}")
            return {"error": str(e), "status": "failed"}

    async def list_finding_group_resources(
        self,
        check_id: str = Field(
            description="Public check ID that identifies the finding group. This is not a UUID."
        ),
        provider: list[str] = Field(
            default=[],
            description="Filter by provider UUIDs. Multiple values allowed.",
        ),
        provider_type: list[str] = Field(
            default=[],
            description="Filter by provider type. Multiple values allowed.",
        ),
        provider_uid: list[str] = Field(
            default=[],
            description="Filter by provider-native account, subscription, or project IDs. Multiple values allowed.",
        ),
        provider_alias: str | None = Field(
            default=None,
            description="Filter by provider alias/name using partial matching.",
        ),
        region: list[str] = Field(
            default=[],
            description="Filter by cloud regions. Multiple values allowed.",
        ),
        service: list[str] = Field(
            default=[],
            description="Filter by cloud services. Multiple values allowed.",
        ),
        resource_type: list[str] = Field(
            default=[],
            description="Filter by resource types. Multiple values allowed.",
        ),
        resource_name: str | None = Field(
            default=None,
            description="Filter by resource name using partial matching.",
        ),
        resource_uid: str | None = Field(
            default=None,
            description="Filter by resource UID using partial matching.",
        ),
        resource_group: list[str] = Field(
            default=[],
            description="Filter by resource group values. Multiple values allowed.",
        ),
        category: list[str] = Field(
            default=[],
            description="Filter by finding categories. Multiple values allowed.",
        ),
        severity: list[SeverityFilter] = Field(
            default=[],
            description="Filter by severity. Empty returns all severities.",
        ),
        status: list[StatusFilter] = Field(
            default=["FAIL"],
            description="Filter by status. Default returns failing resources. Pass [] to return all statuses.",
        ),
        muted: bool | str | None = Field(
            default=None,
            description="Filter by muted state. Accepts true/false. Overrides include_muted when provided.",
        ),
        include_muted: bool | str = Field(
            default=False,
            description="When false, returns only actionable unmuted resources by applying muted=false. Set true to include muted and unmuted resources.",
        ),
        delta: list[DeltaFilter] = Field(
            default=[], description="Filter by delta values: new or changed."
        ),
        date_from: str | None = Field(
            default=None,
            description="Start date for historical query in YYYY-MM-DD format. Maximum range is 2 days.",
        ),
        date_to: str | None = Field(
            default=None,
            description="End date for historical query in YYYY-MM-DD format. Maximum range is 2 days.",
        ),
        sort: str | None = Field(
            default=None,
            description="Optional sort expression supported by the finding group resources API.",
        ),
        page_size: int = Field(
            default=50, description="Number of resources to return per page"
        ),
        page_number: int = Field(
            default=1, description="Page number to retrieve (1-indexed)"
        ),
    ) -> dict[str, Any]:
        """List resources affected by a finding group.

        Without dates this uses `/finding-groups/latest/{check_id}/resources`.
        With `date_from` or `date_to`, this uses
        `/finding-groups/{check_id}/resources` with a maximum 2-day date window.

        Default behavior returns FAIL, unmuted resources so the result is
        actionable. Set `include_muted=True` to include accepted/suppressed
        resources too. Each row includes nested resource and provider data plus
        `finding_id`. Use `prowler_app_get_finding_details(finding_id)` to
        retrieve complete remediation guidance for a specific resource finding.
        """
        try:
            self.api_client.validate_page_size(page_size)
            date_range, params = self._base_date_params(date_from, date_to)
            endpoint = self._resource_endpoint(check_id, date_range)

            if muted is None and not self._bool_value(include_muted):
                muted = False

            self._apply_common_filters(
                params,
                provider,
                provider_type,
                provider_uid,
                provider_alias,
                region,
                service,
                resource_type,
                resource_name,
                resource_uid,
                resource_group,
                category,
                [],
                None,
                severity,
                status,
                muted,
                delta,
            )

            params["page[size]"] = page_size
            params["page[number]"] = page_number
            params["fields[finding-group-resources]"] = RESOURCE_FIELDS
            if sort:
                params["sort"] = sort

            clean_params = self.api_client.build_filter_params(params)
            api_response = await self.api_client.get(endpoint, params=clean_params)
            response = FindingGroupResourcesListResponse.from_api_response(api_response)
            return response.model_dump()
        except Exception as e:
            self.logger.error(f"Error listing finding group resources: {e}")
            return {"error": str(e), "status": "failed"}
