"""Security Findings tools for Prowler App MCP Server."""

from typing import Literal

from prowler_mcp_server.prowler_app.models.findings import (
    FindingsListResponse,
    FindingsOverview,
    SimplifiedFinding,
)
from prowler_mcp_server.prowler_app.utils.api_client import ProwlerAPIClient


async def search_security_findings(
    severity: list[Literal["critical", "high", "medium", "low", "informational"]] = [],
    status: list[Literal["FAIL", "PASS", "MANUAL"]] = ["FAIL"],
    provider_type: list[str] = [],
    provider_alias: str | None = None,
    region: list[str] = [],
    service: list[str] = [],
    resource_type: list[str] = [],
    check_id: list[str] = [],
    muted: bool | None = None,
    delta: list[Literal["new", "changed"]] = [],
    date_from: str | None = None,
    date_to: str | None = None,
    search: str = "",
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

    # Return only LLM-relevant fields - exclude type, relationships, raw_result
    # Focus on actionable information: uid, status, severity, check_id, check_metadata, status_extended
    params["fields[findings]"] = (
        "uid,status,severity,check_id,check_metadata,status_extended,delta,muted,muted_reason"
    )

    # Convert lists to comma-separated strings
    clean_params = client.build_filter_params(params)

    # Get API response and transform to simplified format
    api_response = await client.get(endpoint, params=clean_params)
    simplified_response = FindingsListResponse.from_api_response(api_response)

    return simplified_response.model_dump()


# TODO: Is it needed to return more information in this tool than in the search_security_findings tool?
async def get_finding_details(
    finding_id: str,
) -> dict[str, any]:
    """Retrieve comprehensive details about a specific security finding by its ID.

    Args:
        finding_id: UUID of the finding to retrieve (from search_security_findings results)

    Returns:
        Simplified finding with all essential security metadata and remediation information

    Raises:
        Exception: If API request fails or finding not found
    """
    client = ProwlerAPIClient()

    params = {
        # Return only LLM-relevant fields
        "fields[findings]": "uid,status,severity,check_id,check_metadata,status_extended,delta,muted,muted_reason"
    }

    # Get API response and transform to simplified format
    api_response = await client.get(f"/api/v1/findings/{finding_id}", params=params)
    simplified_finding = SimplifiedFinding.from_api_response(
        api_response.get("data", {})
    )

    return simplified_finding.model_dump()


async def get_findings_overview(
    provider_type: list[str] = [],
) -> dict[str, any]:
    """Retrieve aggregate statistics about security findings formatted as a human-readable markdown report.

    Provides a high-level summary of findings including total counts, status breakdowns,
    and trending information (new vs changed findings).

    Args:
        provider_type: Filter statistics by cloud provider (e.g., ["aws", "azure"]).
                      Default: [] (all providers)

    Returns:
        Dictionary with 'report' key containing markdown-formatted summary:
        - Summary statistics (total, failed, passed, muted with percentages)
        - Delta analysis (new and changed findings breakdown)
        - Trending information

    Raises:
        Exception: If API request fails
    """
    client = ProwlerAPIClient()

    params = {
        # Return only LLM-relevant aggregate statistics
        "fields[findings-overview]": "new,changed,fail_new,fail_changed,pass_new,pass_changed,muted_new,muted_changed,total,fail,muted,pass"
    }

    if provider_type:
        params["filter[provider_type__in]"] = provider_type

    clean_params = client.build_filter_params(params)

    # Get API response and transform to simplified format
    api_response = await client.get("/api/v1/overviews/findings", params=clean_params)
    overview = FindingsOverview.from_api_response(api_response)

    # Format as markdown report
    total = overview.total
    fail = overview.fail
    passed = overview.passed
    muted = overview.muted
    new = overview.new
    changed = overview.changed

    # Calculate percentages
    fail_pct = (fail / total * 100) if total > 0 else 0
    passed_pct = (passed / total * 100) if total > 0 else 0
    muted_pct = (muted / total * 100) if total > 0 else 0
    unchanged = total - new - changed

    # Build markdown report
    report = f"""# Security Findings Overview

## Summary Statistics
- **Total Findings**: {total:,}
- **Failed Checks**: {fail:,} ({fail_pct:.1f}%)
- **Passed Checks**: {passed:,} ({passed_pct:.1f}%)
- **Muted Findings**: {muted:,} ({muted_pct:.1f}%)

## Delta Analysis
- **New Findings**: {new:,}
  - New failures: {overview.fail_new:,}
  - New passes: {overview.pass_new:,}
  - New muted: {overview.muted_new:,}
- **Changed Findings**: {changed:,}
  - Changed to fail: {overview.fail_changed:,}
  - Changed to pass: {overview.pass_changed:,}
  - Changed to muted: {overview.muted_changed:,}
- **Unchanged**: {unchanged:,}
"""

    return {"report": report}
