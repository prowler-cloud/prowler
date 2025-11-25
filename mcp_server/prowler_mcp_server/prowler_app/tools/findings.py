"""Security Findings tools for Prowler App MCP Server."""

from typing import Literal

from prowler_mcp_server.prowler_app.models.findings import (
    DetailedFinding,
    FindingsListResponse,
    FindingsOverview,
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
    """Search findings with filters, returns simplified findings without temporal metadata.

    Uses /latest endpoint by default, switches to /findings with date range when dates provided.
    Returns simplified findings (excludes inserted_at, scan_id, resource_ids).

    Returns:
        FindingsListResponse as dict with paginated simplified findings

    Raises:
        ValueError: If date range exceeds 2 days
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


async def get_finding_details(
    finding_id: str,
) -> dict[str, any]:
    """Get detailed finding information including temporal metadata and relationships.

    Fetches a single finding with additional fields: inserted_at, updated_at, first_seen_at,
    scan_id, and resource_ids.

    Args:
        finding_id: UUID of the finding

    Returns:
        DetailedFinding model as dict

    Raises:
        Exception: If API request fails
    """
    client = ProwlerAPIClient()

    params = {
        # Return comprehensive fields including temporal metadata
        "fields[findings]": "uid,status,severity,check_id,check_metadata,status_extended,delta,muted,muted_reason,inserted_at,updated_at,first_seen_at",
        # Include relationships to scan and resources
        "include": "scan,resources",
    }

    # Get API response and transform to detailed format
    api_response = await client.get(f"/api/v1/findings/{finding_id}", params=params)
    detailed_finding = DetailedFinding.from_api_response(api_response.get("data", {}))

    return detailed_finding.model_dump()


async def get_findings_overview(
    provider_type: list[str] = [],
) -> dict[str, any]:
    """Get aggregate finding statistics and format as markdown report.

    Fetches overview from /api/v1/overviews/findings and builds markdown report.

    Returns:
        Dict with 'report' key containing markdown-formatted statistics
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
