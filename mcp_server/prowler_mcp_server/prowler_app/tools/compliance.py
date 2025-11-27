"""Compliance framework tools for Prowler App MCP Server.

This module provides tools for searching and viewing compliance frameworks.
"""

from typing import Any

from prowler_mcp_server.prowler_app.models.compliance import (
    ComplianceFrameworksListResponse,
)
from prowler_mcp_server.prowler_app.tools.base import BaseTool
from pydantic import Field


class ComplianceTools(BaseTool):
    """Tools for compliance framework operations.

    Provides tools for:
    - Searching compliance frameworks
    - Getting compliance status
    """

    async def search_compliance_frameworks(
        self,
        scan_id: str | None = Field(
            default=None,
            description="UUID of the scan to get compliance frameworks for (must be a valid UUID format, e.g., '019ac0d6-90d5-73e9-9acf-c22e256f1bac'). If omitted, returns compliance data from the latest completed scan of each provider type",
        ),
        compliance_framework_id: str | None = Field(
            default=None,
            description="Filter by specific compliance framework ID (e.g., cis_1.5_aws, pci_dss_v4.0_aws)",
        ),
        region: list[str] = Field(
            default=[],
            description="Filter by cloud regions. Multiple values allowed. If empty, all regions are returned",
        ),
        page_size: int = Field(
            default=50,
            description="Number of results to return per page. Default: 100, Max: 1000",
        ),
        page_number: int = Field(
            default=1, description="Page number to retrieve (1-indexed). Default: 1"
        ),
    ) -> dict[str, Any]:
        """Search and retrieve compliance frameworks with their status.

        Returns high-level compliance framework information showing which standards (CIS, PCI-DSS, HIPAA,
        NIST, ISO 27001, etc.) apply to your environment and their overall compliance status.

        Behavior:
        - With scan_id: Returns compliance data for that specific scan
        - Without scan_id: Returns aggregated compliance data from the latest completed scan of each provider

        Use this tool to:
        - Get a compliance overview for a specific scan or latest scans across all providers
        - See which frameworks are applicable to your cloud environment
        - Understand overall compliance posture with pass/fail percentages
        - Filter frameworks by region or specific framework name

        Each framework includes:
        - Framework identification: compliance_id, framework name, version
        - Cloud context: provider type, region
        - Compliance metrics: total requirements, passed/failed/manual counts, pass percentage

        Returns:
            Paginated list of compliance frameworks with compliance statistics
        """
        # Validate page_size parameter
        self.api_client.validate_page_size(page_size)

        params = {}

        if scan_id:
            params["filter[scan_id]"] = scan_id

        if compliance_framework_id:
            params["filter[compliance_id__icontains]"] = compliance_framework_id
        if region:
            params["filter[region__in]"] = region

        # Pagination
        params["page[size]"] = page_size
        params["page[number]"] = page_number

        # Return only LLM-relevant fields
        params["fields[compliance-overviews]"] = (
            "compliance_id,framework,version,provider,region,total_requirements,"
            "requirements_passed,requirements_failed,requirements_manual"
        )

        clean_params = self.api_client.build_filter_params(params)

        # Get API response and transform to simplified format
        api_response = await self.api_client.get(
            "/api/v1/compliance-overviews", params=clean_params
        )
        simplified_response = ComplianceFrameworksListResponse.from_api_response(
            api_response
        )

        return simplified_response.model_dump()

    # TODO: Create a tool with custom logic to given a compliance framework and
    # a scan id/provider uid, return the compliance general statistics (total
    # requirements, passed, failed, manual) and the requirements that were not
    # met.
