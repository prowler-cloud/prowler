"""Security Findings tools for Prowler App MCP Server."""

from typing import Literal

from prowler_mcp_server.prowler_app.utils.api_client import ProwlerAPIClient


async def search_security_findings(
    severity: (
        list[Literal["critical", "high", "medium", "low", "informational"]] | None
    ) = None,
    status: list[Literal["FAIL", "PASS", "MANUAL"]] | None = None,
    provider_type: (
        list[Literal["aws", "azure", "gcp", "kubernetes", "m365", "github"]] | None
    ) = None,
    provider_alias: str | None = None,
    region: list[str] | None = None,
    service: list[str] | None = None,
    resource_type: list[str] | None = None,
    check_id: list[str] | None = None,
    muted: bool | None = None,
    delta: list[Literal["new", "changed"]] | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    search: str | None = None,
    page_size: int = 100,
    page_number: int = 1,
) -> dict[str, any]:
    """Search and filter security findings across all cloud providers with rich filtering capabilities.

    By default retrieves the latest findings from the most recent scans. When any date parameter
    is provided, queries historical findings within a 2-day window.

    Args:
        severity: Filter by severity levels
        status: Filter by finding status
        provider_type: Filter by cloud provider
        provider_alias: Filter by specific provider alias/name
        region: Filter by cloud regions
        service: Filter by cloud service (e.g., s3, ec2, iam)
        resource_type: Filter by resource type
        check_id: Filter by specific security check IDs
        muted: Show only muted findings (True) or only active findings (False). If not specified, shows both
        delta: Show only new or changed findings
        date_from: Start date for range query (ISO 8601 date format YYYY-MM-DD). Maps to filter[inserted_at__gte].
                   Can be used alone or with date_to.
                   IMPORTANT: When using date_from and/or date_to, the date range cannot exceed 2 days (API limitation).
                   If only one boundary is provided, the implementation will set the other to maintain the 2-day window.
        date_to: End date for range query (ISO 8601 date format YYYY-MM-DD). Maps to filter[inserted_at__lte].
                 Can be used alone or with date_from.
        search: Free-text search across finding details
        page_size: Number of results per page. Default: 100, Max: 1000
        page_number: Page number to retrieve (1-indexed). Default: 1

    Returns:
        Paginated list of findings with metadata. Each finding includes severity, status, check details,
        and relationships to scans/resources.

    Raises:
        ValueError: If date range exceeds 2 days
        Exception: If API request fails
    """
    client = ProwlerAPIClient()

    # Determine endpoint based on date parameters
    date_range = client.normalize_date_range(date_from, date_to, max_days=2)

    if date_range is None:
        # No dates provided - use latest findings endpoint
        endpoint = "/api/v1/findings/latest"
        params = {}
    else:
        # Dates provided - use historical findings endpoint
        endpoint = "/api/v1/findings"
        params = {
            "filter[inserted_at__gte]": date_range[0],
            "filter[inserted_at__lte]": date_range[1],
        }

    # Build filter parameters
    if severity:
        params["filter[severity__in]"] = severity
    if status:
        params["filter[status__in]"] = status
    if provider_type:
        params["filter[provider_type__in]"] = provider_type
    if provider_alias:
        params["filter[provider_alias__icontains]"] = provider_alias
    if region:
        params["filter[region__in]"] = region
    if service:
        params["filter[service__in]"] = service
    if resource_type:
        params["filter[resource_type__in]"] = resource_type
    if check_id:
        params["filter[check_id__in]"] = check_id
    if muted is not None:
        params["filter[muted]"] = muted
    if delta:
        params["filter[delta__in]"] = delta
    if search:
        params["filter[search]"] = search

    # Pagination
    params["page[size]"] = page_size
    params["page[number]"] = page_number

    # Convert lists to comma-separated strings
    clean_params = client.build_filter_params(params)

    return await client.get(endpoint, params=clean_params)


async def get_finding_details(
    finding_id: str,
    include_resources: bool = False,
    include_scan_info: bool = False,
) -> dict[str, any]:
    """Retrieve comprehensive details about a specific security finding by its ID.

    Args:
        finding_id: UUID of the finding to retrieve
        include_resources: Include full resource details. Default: False
        include_scan_info: Include scan metadata. Default: False

    Returns:
        Comprehensive details for a single finding including all metadata, check information,
        and optional relationships

    Raises:
        Exception: If API request fails
    """
    client = ProwlerAPIClient()

    params = {}
    includes = []
    if include_resources:
        includes.append("resources")
    if include_scan_info:
        includes.append("scan")

    if includes:
        params["include"] = ",".join(includes)

    return await client.get(f"/api/v1/findings/{finding_id}", params=params)


async def get_findings_overview(
    provider_type: (
        list[Literal["aws", "azure", "gcp", "kubernetes", "m365", "github"]] | None
    ) = None,
) -> dict[str, any]:
    """Retrieve high-level statistics and aggregated metrics about findings across your environment.

    Args:
        provider_type: Filter statistics by provider

    Returns:
        High-level statistics and trends about security findings in a human-readable summary format

    Raises:
        Exception: If API request fails
    """
    client = ProwlerAPIClient()

    params = {}
    if provider_type:
        params["filter[provider_type__in]"] = provider_type

    clean_params = client.build_filter_params(params)

    return await client.get("/api/v1/overviews/findings", params=clean_params)
