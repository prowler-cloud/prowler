"""Security Findings tools for Prowler App MCP Server.

This module provides tools for searching, viewing, and analyzing security findings
across all cloud providers.
"""

from typing import Any, Literal

from pydantic import Field

from prowler_mcp_server.prowler_app.models.findings import (
    DetailedFinding,
    FindingsListResponse,
    FindingsOverview,
)
from prowler_mcp_server.prowler_app.tools.base import BaseTool


class FindingsTools(BaseTool):
    """Tools for security findings operations.

    Provides tools for:
    - search_security_findings: Fast and lightweight searching across findings
    - get_finding_details: Get complete details for a specific finding
    - get_findings_overview: Get aggregate statistics and trends across all findings
    """

    async def search_security_findings(
        self,
        severity: list[
            Literal["critical", "high", "medium", "low", "informational"]
        ] = Field(
            default=[],
            description="Filter by severity levels. Multiple values allowed: critical, high, medium, low, informational. If empty, all severities are returned.",
        ),
        status: list[Literal["FAIL", "PASS", "MANUAL"]] = Field(
            default=["FAIL"],
            description="Filter by finding status. Multiple values allowed: FAIL (security issue found), PASS (no issue found), MANUAL (requires manual verification). Default: ['FAIL'] - only returns findings with security issues. To get all findings, pass an empty list [].",
        ),
        provider_type: list[str] = Field(
            default=[],
            description="Filter by cloud provider type. Multiple values allowed. If the parameter is not provided, all providers are returned. For valid values, please refer to Prowler Hub/Prowler Documentation that you can also find in form of tools in this MCP Server.",
        ),
        provider_alias: str | None = Field(
            default=None,
            description="Filter by specific provider alias/name (partial match supported)",
        ),
        region: list[str] = Field(
            default=[],
            description="Filter by cloud regions. Multiple values allowed (e.g., us-east-1, eu-west-1). If empty, all regions are returned.",
        ),
        service: list[str] = Field(
            default=[],
            description="Filter by cloud service. Multiple values allowed (e.g., s3, ec2, iam, keyvault). If empty, all services are returned.",
        ),
        resource_type: list[str] = Field(
            default=[],
            description="Filter by resource type. Multiple values allowed. If empty, all resource types are returned.",
        ),
        check_id: list[str] = Field(
            default=[],
            description="Filter by specific security check IDs. Multiple values allowed. If empty, all check IDs are returned.",
        ),
        muted: (
            bool | str | None
        ) = Field(  # Wrong `str` hint type due to bad MCP Clients implementation
            default=None,
            description="Filter by muted status. True for muted findings only, False for active findings only. If not specified, returns both",
        ),
        delta: list[Literal["new", "changed"]] = Field(
            default=[],
            description="Show only new or changed findings. Multiple values allowed: new (not seen in previous scans), changed (modified since last scan). If empty, all findings are returned.",
        ),
        date_from: str | None = Field(
            default=None,
            description="Start date for range query in ISO 8601 format (YYYY-MM-DD, e.g., '2025-01-15'). Full date required - partial dates like '2025' or '2025-01' are not accepted. IMPORTANT: Maximum date range is 2 days. If only date_from is provided, date_to is automatically set to 2 days later. If only one boundary is provided, the other will be auto-calculated to maintain the 2-day window.",
        ),
        date_to: str | None = Field(
            default=None,
            description="End date for range query in ISO 8601 format (YYYY-MM-DD, e.g., '2025-01-15'). Full date required - partial dates are not accepted. If only date_to is provided, date_from is automatically set to 2 days earlier. Can be used alone or with date_from.",
        ),
        search: str | None = Field(
            default=None, description="Free-text search term across finding details"
        ),
        page_size: int = Field(
            default=50, description="Number of results to return per page"
        ),
        page_number: int = Field(
            default=1, description="Page number to retrieve (1-indexed)"
        ),
    ) -> dict[str, Any]:
        """Search and filter security findings across all cloud providers with rich filtering capabilities.

        IMPORTANT: This tool returns LIGHTWEIGHT findings. Use this for fast searching and filtering across many findings.
        For complete details use prowler_app_get_finding_details on specific findings.

        Default behavior:
        - Returns latest findings from most recent scans (no date parameters needed)
        - Filters to FAIL status only (security issues found)
        - Returns 50 results per page

        Date filtering:
        - Without dates: queries findings from the most recent completed scan across all providers (most efficient)
        - With dates: queries historical findings (2-day maximum range between date_from and date_to)

        Each finding includes:
        - Core identification: id (UUID for get_finding_details), uid, check_id
        - Security context: status (FAIL/PASS/MANUAL), severity (critical/high/medium/low/informational)
        - State tracking: delta (new/changed/unchanged), muted (boolean), muted_reason
        - Extended details: status_extended with additional context

        Workflow:
        1. Use this tool to search and filter findings by severity, status, provider, service, region, etc.
        2. Use prowler_app_get_finding_details with the finding 'id' to get complete information about the finding
        """
        # Validate page_size parameter
        self.api_client.validate_page_size(page_size)

        # Determine endpoint based on date parameters
        date_range = self.api_client.normalize_date_range(
            date_from, date_to, max_days=2
        )

        if date_range is None:
            # No dates provided - use latest findings endpoint
            endpoint = "/findings/latest"
            params = {}
        else:
            # Dates provided - use historical findings endpoint
            endpoint = "/findings"
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
            params["filter[muted]"] = (
                muted if isinstance(muted, bool) else muted == "true"
            )
        if delta:
            params["filter[delta__in]"] = delta
        if search:
            params["filter[search]"] = search

        # Pagination
        params["page[size]"] = page_size
        params["page[number]"] = page_number

        # Return only LLM-relevant fields
        params["fields[findings]"] = (
            "uid,status,severity,check_id,check_metadata,status_extended,delta,muted,muted_reason"
        )
        params["sort"] = "severity,-inserted_at"

        # Convert lists to comma-separated strings
        clean_params = self.api_client.build_filter_params(params)

        # Get API response and transform to simplified format
        api_response = await self.api_client.get(endpoint, params=clean_params)
        simplified_response = FindingsListResponse.from_api_response(api_response)

        return simplified_response.model_dump()

    async def get_finding_details(
        self,
        finding_id: str = Field(
            description="UUID of the finding to retrieve (must be a valid UUID format, e.g., '019ac0d6-90d5-73e9-9acf-c22e256f1bac'). Returns an error if the finding ID is invalid or not found."
        ),
    ) -> dict[str, Any]:
        """Retrieve comprehensive details about a specific security finding by its ID.

        IMPORTANT: This tool returns COMPLETE finding details.
        Use this after finding a specific finding via prowler_app_search_security_findings

        This tool provides ALL information that prowler_app_search_security_findings returns PLUS:

        1. Check Metadata (information about the check script that generated the finding):
           - title: Human-readable phrase used to summarize the check
           - description: Detailed explanation of what the check validates and why it is important
           - risk: What could happen if this check fails
           - remediation: Complete remediation guidance including step-by-step instructions and code snippets with best practices to fix the issue:
             * cli: Command-line commands to fix the issue
             * terraform: Terraform code snippets with best practices
             * nativeiac: Provider native Infrastructure as Code code snippets with best practices to fix the issue
             * other: Other remediation code snippets with best practices, usually used for web interfaces or other tools
             * recommendation: Text description with general best recommended practices to avoid the issue
           - provider: Cloud provider (aws/azure/gcp/etc)
           - service: Service name (s3/ec2/keyvault/etc)
           - resource_type: Resource type being evaluated
           - categories: Security categories this check belongs to
           - additional_urls: List of additional URLs related to the check

        2. Temporal Metadata:
           - inserted_at: When this finding was first inserted into database
           - updated_at: When this finding was last updated
           - first_seen_at: When this finding was first detected across all scans

        3. Relationships:
           - scan_id: UUID of the scan that generated this finding
           - resource_ids: List of UUIDs for cloud resources associated with this finding

        Workflow:
        1. Use prowler_app_search_security_findings to browse and filter findings
        2. Use this tool with the finding 'id' to get remediation guidance and complete context
        """
        params = {
            # Return comprehensive fields including temporal metadata
            "fields[findings]": "uid,status,severity,check_id,check_metadata,status_extended,delta,muted,muted_reason,inserted_at,updated_at,first_seen_at",
            # Include relationships to scan and resources
            "include": "scan,resources",
        }

        # Get API response and transform to detailed format
        api_response = await self.api_client.get(
            f"/findings/{finding_id}", params=params
        )
        detailed_finding = DetailedFinding.from_api_response(
            api_response.get("data", {})
        )

        return detailed_finding.model_dump()

    async def get_findings_overview(
        self,
        provider_type: list[str] = Field(
            default=[],
            description="Filter statistics by cloud provider. Multiple values allowed. If empty, all providers are returned. For valid values, please refer to Prowler Hub/Prowler Documentation that you can also find in form of tools in this MCP Server.",
        ),
    ) -> dict[str, Any]:
        """Get aggregate statistics and trends about security findings as a markdown report.

        This tool provides a HIGH-LEVEL OVERVIEW without retrieving individual findings. Use this when you
        need to understand the overall security posture, trends, or remediation progress across all findings.

        The markdown report includes:

        1. Summary Statistics:
           - Total number of findings
           - Failed checks (security issues) with percentage
           - Passed checks (no issues) with percentage
           - Muted findings (user-suppressed) with percentage

        2. Delta Analysis (Change Tracking):
           - New findings: never seen before in previous scans
             * Broken down by: new failures, new passes, new muted
           - Changed findings: status changed since last scan
             * Broken down by: changed to fail, changed to pass, changed to muted
           - Unchanged findings: same status as previous scan

        This helps answer questions like:
        - "What's my overall security posture?"
        - "How many critical security issues do I have?"
        - "Are we improving or getting worse over time?"
        - "How many new security issues appeared since last scan?"
        """
        params = {
            # Return only LLM-relevant aggregate statistics
            "fields[findings-overview]": "new,changed,fail_new,fail_changed,pass_new,pass_changed,muted_new,muted_changed,total,fail,muted,pass"
        }

        if provider_type:
            params["filter[provider_type__in]"] = provider_type

        clean_params = self.api_client.build_filter_params(params)

        # Get API response and transform to simplified format
        api_response = await self.api_client.get(
            "/overviews/findings", params=clean_params
        )
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
