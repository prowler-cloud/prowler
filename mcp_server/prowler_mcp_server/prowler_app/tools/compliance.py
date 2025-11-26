"""Compliance framework tools for Prowler App MCP Server."""

from prowler_mcp_server.prowler_app.models.compliance import (
    ComplianceFrameworksListResponse,
)
from prowler_mcp_server.prowler_app.utils.api_client import ProwlerAPIClient


async def search_compliance_frameworks(
    scan_id: str | None = None,
    framework: str | None = None,
    region: list[str] = [],
    page_size: int = 100,
    page_number: int = 1,
) -> dict[str, any]:
    """Search and retrieve compliance frameworks with their status.

    Returns high-level framework information including pass/fail statistics across all compliance
    standards (CIS, NIST, PCI-DSS, etc.).

    Args:
        scan_id: UUID of the scan to analyze for compliance. If omitted, returns compliance
            data aggregated from the latest completed scan of each provider.
        framework: Filter by specific framework name (e.g., cis, pci-dss, hipaa)
        region: Filter by cloud regions. Multiple values allowed. If empty, all regions are returned.
        page_size: Number of results per page. Default: 100
        page_number: Page number to retrieve (1-indexed). Default: 1

    Returns:
        Paginated list of simplified compliance frameworks with pass/fail statistics

    Raises:
        Exception: If API request fails
    """
    client = ProwlerAPIClient()

    params = {}

    if scan_id:
        params["filter[scan_id]"] = scan_id

    if framework:
        params["filter[framework__icontains]"] = framework
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

    clean_params = client.build_filter_params(params)

    # Get API response and transform to simplified format
    api_response = await client.get("/api/v1/compliance-overviews", params=clean_params)
    simplified_response = ComplianceFrameworksListResponse.from_api_response(
        api_response
    )

    return simplified_response.model_dump()
