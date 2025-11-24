"""Compliance framework tools for Prowler App MCP Server."""

from typing import Literal

from prowler_mcp_server.prowler_app.utils.api_client import ProwlerAPIClient


async def search_compliance_frameworks(
    scan_id: str,
    framework: str | None = None,
    region: list[str] | None = None,
    include_metadata: bool = False,
) -> dict[str, any]:
    """Search and retrieve compliance frameworks with their status for a specific scan.

    Returns high-level framework information including pass/fail statistics across all compliance
    standards (CIS, NIST, PCI-DSS, etc.).

    Args:
        scan_id: UUID of the scan to analyze for compliance
        framework: Filter by specific framework name (e.g., cis, pci-dss, hipaa)
        region: Filter by cloud regions
        include_metadata: Include available regions and other metadata. Default: False

    Returns:
        List of compliance frameworks with pass/fail statistics for the specified scan

    Raises:
        Exception: If API request fails
    """
    client = ProwlerAPIClient()

    params = {
        "filter[scan]": scan_id,
    }

    if framework:
        params["filter[framework__icontains]"] = framework
    if region:
        params["filter[region__in]"] = region

    clean_params = client.build_filter_params(params)

    # Get compliance overviews
    response = await client.get("/api/v1/compliance-overviews", params=clean_params)

    # Optionally get metadata
    if include_metadata:
        metadata_response = await client.get(
            "/api/v1/compliance-overviews/metadata", params=clean_params
        )
        response["meta"] = response.get("meta", {})
        response["meta"]["available_metadata"] = metadata_response.get("data", {})

    return response


async def get_compliance_framework_details(
    scan_id: str,
    compliance_id: str,
    region: list[str] | None = None,
    status: list[Literal["passed", "failed", "manual"]] | None = None,
) -> dict[str, any]:
    """Get detailed requirement-level information for a specific compliance framework.

    Shows which requirements passed, failed, or need manual review across different regions.

    Args:
        scan_id: UUID of the scan to analyze
        compliance_id: Compliance framework ID (e.g., cis_v1.5.0_aws)
        region: Filter by specific regions
        status: Filter by requirement status

    Returns:
        Detailed requirement-level breakdown for a specific compliance framework,
        showing which requirements passed/failed

    Raises:
        Exception: If API request fails
    """
    client = ProwlerAPIClient()

    params = {
        "filter[scan]": scan_id,
        "filter[compliance_id]": compliance_id,
    }

    if region:
        params["filter[region__in]"] = region
    if status:
        # Map to API format (uppercase)
        api_status = [s.upper() for s in status]
        params["filter[status__in]"] = api_status

    clean_params = client.build_filter_params(params)

    return await client.get(
        "/api/v1/compliance-overviews/requirements", params=clean_params
    )


async def get_compliance_requirement_details(
    compliance_id: str,
    requirement_id: str | None = None,
) -> dict[str, any]:
    """Drill down into a specific compliance requirement to see detailed attributes.

    Shows associated checks and descriptions. Useful for understanding what needs to be done
    to meet a specific requirement.

    Args:
        compliance_id: Compliance framework ID (e.g., cis_v1.5.0_aws)
        requirement_id: Specific requirement to get details for (optional)

    Returns:
        Detailed attributes and descriptions for specific compliance requirements,
        including associated checks

    Raises:
        Exception: If API request fails
    """
    client = ProwlerAPIClient()

    params = {
        "filter[compliance_id]": compliance_id,
    }

    if requirement_id:
        params["filter[requirement_id]"] = requirement_id

    clean_params = client.build_filter_params(params)

    return await client.get(
        "/api/v1/compliance-overviews/attributes", params=clean_params
    )
