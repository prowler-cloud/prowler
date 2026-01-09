"""Cloud Resources tools for Prowler App MCP Server.

This module provides tools for searching, viewing, and analyzing cloud resources
across all providers.
"""

from typing import Any

from prowler_mcp_server.prowler_app.models.resources import (
    DetailedResource,
    ResourcesListResponse,
    ResourcesMetadataResponse,
)
from prowler_mcp_server.prowler_app.tools.base import BaseTool
from pydantic import Field


class ResourcesTools(BaseTool):
    """Tools for cloud resources operations.

    Provides tools for:
    - Searching and filtering cloud resources
    - Getting detailed resource information
    - Viewing resources overview with statistics
    """

    async def list_resources(
        self,
        provider_type: list[str] = Field(
            default=[],
            description="Filter by  provider type. Multiple values allowed. If empty, all providers are returned. For valid values, please refer to Prowler Hub/Prowler Documentation that you can also find in form of tools in this MCP Server.",
        ),
        provider_alias: str | None = Field(
            default=None,
            description="Filter by specific provider alias/name (partial match supported). Useful for finding resources in specific accounts like 'production' or 'dev'.",
        ),
        provider_uid: str | None = Field(
            default=None,
            description="Filter by provider's native ID (e.g., AWS account ID, Azure subscription ID, GCP project ID). All supported provider types are listed in the Prowler Hub/Prowler Documentation that you can also find in form of tools in this MCP Server",
        ),
        region: list[str] = Field(
            default=[],
            description="Filter by regions. Multiple values allowed (e.g., us-east-1, westus2, europe-west1), format may vary depending on the provider. If empty, all regions are returned.",
        ),
        service: list[str] = Field(
            default=[],
            description="Filter by service. Multiple values allowed (e.g., s3, ec2, iam, keyvault). If empty, all services are returned.",
        ),
        resource_type: list[str] = Field(
            default=[],
            description="Filter by resource type. Format may vary depending on the provider. If empty, all resource types are returned.",
        ),
        resource_name: str | None = Field(
            default=None,
            description="Filter by resource name (partial match supported). Useful for finding specific resources like 'prod-db' or 'test-bucket'.",
        ),
        tag_key: str | None = Field(
            default=None,
            description="Filter resources by tag key (e.g., 'Environment', 'CostCenter', 'Owner').",
        ),
        tag_value: str | None = Field(
            default=None,
            description="Filter resources by tag value (e.g., 'production', 'staging', 'development').",
        ),
        date_from: str | None = Field(
            default=None,
            description="Start date for range query in ISO 8601 format (YYYY-MM-DD, e.g., '2025-01-15'). Full date required. IMPORTANT: Maximum date range is 2 days. If only date_from is provided, date_to is automatically set to 2 days later.",
        ),
        date_to: str | None = Field(
            default=None,
            description="End date for range query in ISO 8601 format (YYYY-MM-DD, e.g., '2025-01-15'). Full date required. If only date_to is provided, date_from is automatically set to 2 days earlier.",
        ),
        search: str | None = Field(
            default=None, description="Free-text search term across resource details"
        ),
        page_size: int = Field(
            default=50, description="Number of results to return per page (max 1000)"
        ),
        page_number: int = Field(
            default=1, description="Page number to retrieve (1-indexed)"
        ),
    ) -> dict[str, Any]:
        """List and filter all resources scanned by Prowler.

        IMPORTANT: This tool returns LIGHTWEIGHT resource information. Use this for fast searching
        and filtering across many resources. For complete configuration details, metadata, and finding
        relationships, use prowler_app_get_resource on specific resources of interest.

        This is the primary tool for browsing resources with rich filtering capabilities.
        Returns current state by default (latest scan per provider). Specify dates to query
        historical data (2-day maximum window).

        Default behavior:
        - Returns latest resources from most recent scans (no date parameters needed)
        - Returns 50 results per page
        - Sorted by service, region, and name for logical grouping

        Date filtering:
        - Without dates: queries resources from the most recent completed scan per provider (most efficient)
        - With dates: queries historical resource state (2-day maximum range between date_from and date_to)

        Each resource includes:
        - Core identification: id (UUID for prowler_app_get_resource), uid, name
        - Location context: region, service, type
        - Security context: failed_findings_count (number of active security issues)
        - Tags: tags associated with the resource

        Useful Workflow:
        1. Use this tool to search and filter resources by provider, region, service, tags, etc.
        2. Use prowler_app_get_resource with the resource 'id' to get complete configuration and metadata
        3. Use prowler_app_search_security_findings to find security issues for specific resources
        4. Use prowler_app_get_finding_details to get details about the security issues for specific resources
        """
        # Validate page_size parameter
        self.api_client.validate_page_size(page_size)

        # Determine endpoint based on date parameters
        date_range = self.api_client.normalize_date_range(
            date_from, date_to, max_days=2
        )

        if date_range is None:
            # No dates provided - use latest resources endpoint
            endpoint = "/resources/latest"
            params = {}
        else:
            # Dates provided - use historical resources endpoint
            endpoint = "/resources"
            params = {
                "filter[updated_at__gte]": date_range[0],
                "filter[updated_at__lte]": date_range[1],
            }

        # Build filter parameters
        if provider_type:
            params["filter[provider_type__in]"] = provider_type
        if provider_alias:
            params["filter[provider_alias__icontains]"] = provider_alias
        if provider_uid:
            params["filter[provider_uid__icontains]"] = provider_uid
        if region:
            params["filter[region__in]"] = region
        if service:
            params["filter[service__in]"] = service
        if resource_type:
            params["filter[type__in]"] = resource_type
        if resource_name:
            params["filter[name__icontains]"] = resource_name
        if tag_key:
            params["filter[tag_key]"] = tag_key
        if tag_value:
            params["filter[tag_value]"] = tag_value
        if search:
            params["filter[search]"] = search

        # Pagination
        params["page[size]"] = page_size
        params["page[number]"] = page_number

        # Return only LLM-relevant fields
        params["fields[resources]"] = (
            "uid,name,region,service,type,failed_findings_count,tags"
        )
        params["sort"] = "service,region,name"

        # Convert lists to comma-separated strings
        clean_params = self.api_client.build_filter_params(params)

        # Get API response and transform to simplified format
        api_response = await self.api_client.get(endpoint, params=clean_params)
        simplified_response = ResourcesListResponse.from_api_response(api_response)

        return simplified_response.model_dump()

    async def get_resource(
        self,
        resource_id: str = Field(
            description="Prowler's internal UUID (v4) for the resource to retrieve, generated when the resource was discovered in the system. Use `prowler_app_list_resources` tool to find the right ID"
        ),
    ) -> dict[str, Any]:
        """Retrieve comprehensive details about a specific resource by its ID.

        IMPORTANT: This tool provides COMPLETE resource details with all available information.
        Use this after finding a specific resource via prowler_app_list_resources.

        This tool provides ALL information that prowler_app_list_resources returns PLUS:

        1. Configuration Details:
           - metadata: Provider-specific configuration (tags, policies, encryption settings, network rules)
           - partition: Provider-specific partition/region grouping (e.g., aws, aws-cn, aws-eusc, aws-us-gov for AWS)

        2. Temporal Tracking:
           - inserted_at: When Prowler first discovered this resource
           - updated_at: When resource configuration last changed

        3. Security Relationships:
           - finding_ids: Prowler's internal UUIDs (v4) of all security findings associated with this resource
           - Use prowler_app_get_finding_details on these IDs to get remediation guidance

        Useful Workflow:
        1. Use prowler_app_list_resources to browse and filter across many resources
        2. Use this tool to drill down into specific resources of interest
        3. Use prowler_app_get_finding_details to get details about the security issues for specific resources
        """
        params = {}

        # Get API response and transform to detailed format
        api_response = await self.api_client.get(
            f"/resources/{resource_id}", params=params
        )
        detailed_resource = DetailedResource.from_api_response(
            api_response.get("data", {})
        )

        return detailed_resource.model_dump()

    async def get_resources_overview(
        self,
        provider_type: list[str] = Field(
            default=[],
            description="Filter by  provider type. Multiple values allowed. If empty, all providers are returned. For valid values, please refer to Prowler Hub/Prowler Documentation that you can also find in form of tools in this MCP Server.",
        ),
        provider_alias: str | None = Field(
            default=None,
            description="Filter by specific provider alias/name (partial match supported).",
        ),
        provider_uid: str | None = Field(
            default=None,
            description="Filter by provider's native ID (e.g., AWS account ID, Azure subscription ID).",
        ),
        date_from: str | None = Field(
            default=None,
            description="Start date for range query in ISO 8601 format (YYYY-MM-DD). Maximum 2-day range.",
        ),
        date_to: str | None = Field(
            default=None,
            description="End date for range query in ISO 8601 format (YYYY-MM-DD).",
        ),
    ) -> dict[str, Any]:
        """Generate a markdown overview of your resources with statistics and insights.

        IMPORTANT: This tool provides HIGH-LEVEL STATISTICS without returning individual resources.
        Use this when you need a summary view before drilling into details.

        The report includes:
        - Total number of resources
        - Available services across your providers
        - Regions where resources are deployed
        - Resource types present in your providers

        Output format: Markdown-formatted report ready to present to users or include in documentation.

        Use cases:
        - Understanding infrastructure footprint
        - Identifying resource concentration (which regions, services)
        - Multi-provider deployment auditing
        - Resource inventory reporting
        - Tags planning (by provider, service, region)
        """
        # Determine endpoint based on date parameters
        date_range = self.api_client.normalize_date_range(
            date_from, date_to, max_days=2
        )

        if date_range is None:
            # No dates provided - use latest metadata endpoint
            metadata_endpoint = "/resources/metadata/latest"
            list_endpoint = "/resources/latest"
            params = {}
        else:
            # Dates provided - use historical endpoints
            metadata_endpoint = "/resources/metadata"
            list_endpoint = "/resources"
            params = {
                "filter[updated_at__gte]": date_range[0],
                "filter[updated_at__lte]": date_range[1],
            }

        # Build common filter parameters
        if provider_type:
            params["filter[provider_type__in]"] = provider_type
        if provider_alias:
            params["filter[provider_alias__icontains]"] = provider_alias
        if provider_uid:
            params["filter[provider_uid__icontains]"] = provider_uid

        # Convert lists to comma-separated strings
        clean_params = self.api_client.build_filter_params(params)

        # Get metadata (services, regions, types)
        metadata_params = clean_params.copy()
        metadata_params["fields[resources-metadata]"] = "services,regions,types"
        metadata_response = await self.api_client.get(
            metadata_endpoint, params=metadata_params
        )
        metadata = ResourcesMetadataResponse.from_api_response(metadata_response)

        # Get total count (using page_size=1 for efficiency)
        count_params = clean_params.copy()
        count_params["page[size]"] = 1
        count_params["page[number]"] = 1
        count_response = await self.api_client.get(list_endpoint, params=count_params)
        total_resources = (
            count_response.get("meta", {}).get("pagination", {}).get("count", 0)
        )

        # Build markdown report
        report_lines = ["# Cloud Resources Overview", ""]

        # Total resources
        report_lines.append(f"**Total Resources**: {total_resources:,} resources")
        report_lines.append("")

        # Services
        if metadata.services:
            report_lines.append("## Services")
            report_lines.append(f"**{len(metadata.services)}** unique services found")
            report_lines.append("")
            for i, service in enumerate(metadata.services, 1):
                report_lines.append(f"{i}. {service}")
            report_lines.append("")

        # Regions
        if metadata.regions:
            report_lines.append("## Regions")
            report_lines.append(f"**{len(metadata.regions)}** unique regions found")
            report_lines.append("")
            for i, region in enumerate(metadata.regions, 1):
                report_lines.append(f"{i}. {region}")
            report_lines.append("")

        # Resource types
        if metadata.types:
            report_lines.append("## Resource Types")
            report_lines.append(
                f"**{len(metadata.types)}** unique resource types found"
            )
            report_lines.append("")
            for i, rtype in enumerate(metadata.types, 1):
                report_lines.append(f"{i}. {rtype}")
            report_lines.append("")

        report = "\n".join(report_lines)
        return {"report": report}
