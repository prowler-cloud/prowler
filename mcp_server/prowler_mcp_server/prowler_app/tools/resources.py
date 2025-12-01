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
            description="Filter resources by tag key (e.g., 'Environment', 'CostCenter', 'Owner'). Useful for cost allocation and ownership tracking.",
        ),
        tag_value: str | None = Field(
            default=None,
            description="Filter resources by tag value (e.g., 'production', 'staging', 'development'). Often used with tag_key for precise filtering.",
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

        This is the primary tool for browsing resources with rich filtering capabilities.
        Returns current state by default (latest scan per provider). Specify dates to query
        historical data (2-day maximum window).

        Default behavior:
        - Returns latest resources from most recent scans (no date parameters needed)
        - Returns 50 results per page
        - Sorted by service, region, and name for logical grouping

        Date filtering:
        - Without dates: queries resources from the most recent completed scan (most efficient)
        - With dates: queries historical resources (2-day maximum range)

        Each resource includes:
        - Core identification: id, uid, name
        - Location context: region, service, type
        - Security context: failed_findings_count

        Returns:
            Paginated list of simplified resources with total count and pagination metadata
        """
        # Validate page_size parameter
        self.api_client.validate_page_size(page_size)

        # Determine endpoint based on date parameters
        date_range = self.api_client.normalize_date_range(
            date_from, date_to, max_days=2
        )

        if date_range is None:
            # No dates provided - use latest resources endpoint
            endpoint = "/api/v1/resources/latest"
            params = {}
        else:
            # Dates provided - use historical resources endpoint
            endpoint = "/api/v1/resources"
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
            description="UUID of the resource to retrieve (must be a valid UUID format, e.g., '019ac0d6-90d5-73e9-9acf-c22e256f1bac'). Returns an error if the resource ID is invalid or not found."
        ),
    ) -> dict[str, Any]:
        """Retrieve comprehensive details about a specific cloud resource by its ID.

        This tool provides MORE detailed information than prowler_app_list_resources. Use this when
        you need to deeply analyze a specific resource or understand its complete configuration
        and security context.

        Additional information compared to prowler_app_list_resources:
        - Metadata: Provider-specific metadata
        - Partition: Provider-specific partition information (e.g., aws, aws-cn, aws-us-gov)
        - Metadata: Provider-specific metadata
        - Finding relationships: IDs of all security findings associated with this resource

        Workflow:
        1. Use prowler_app_list_resources to browse and filter across many resources
        2. Use prowler_app_get_resource to drill down into specific resources of interest

        Returns:
            dict containing detailed resource with comprehensive information
        """
        params = {
            # Return comprehensive fields including temporal metadata
            "fields[resources]": "uid,name,region,service,type,failed_findings_count,tags,metadata,partition,inserted_at,updated_at",
            # Include relationships to findings and provider
            "include": "findings,provider",
        }

        # Get API response and transform to detailed format
        api_response = await self.api_client.get(
            f"/api/v1/resources/{resource_id}", params=params
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
        """Generate a markdown overview of your cloud resources with statistics and insights.

        Use this tool to get a high-level view of your infrastructure footprint without
        retrieving individual resources. Perfect for understanding resource distribution,
        identifying concentration areas, and auditing multi-cloud deployments.

        The report includes:
        - Total resource count
        - Available services across your infrastructure
        - Regions where resources are deployed
        - Resource types present in your environment
        - Resources with security findings (count and percentage)

        Output format: Markdown-formatted report ready to present to users or include in documentation.

        Use cases:
        - Understanding infrastructure footprint
        - Identifying resource concentration (which regions, services)
        - Multi-cloud deployment auditing
        - Resource inventory reporting
        - Cost allocation planning (by service/region)

        Returns:
            Dictionary with 'report' key containing markdown-formatted overview with statistics
        """
        # Determine endpoint based on date parameters
        date_range = self.api_client.normalize_date_range(
            date_from, date_to, max_days=2
        )

        if date_range is None:
            # No dates provided - use latest metadata endpoint
            metadata_endpoint = "/api/v1/resources/metadata/latest"
            list_endpoint = "/api/v1/resources/latest"
            params = {}
        else:
            # Dates provided - use historical endpoints
            metadata_endpoint = "/api/v1/resources/metadata"
            list_endpoint = "/api/v1/resources"
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
