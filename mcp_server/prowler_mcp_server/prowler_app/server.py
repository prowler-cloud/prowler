"""Custom Prowler App MCP Server - workflow-based tools.

This server provides high-level, workflow-oriented tools for interacting with Prowler App API.
Tools are designed for AI agent workflows, not 1:1 API mapping.
"""

from typing import Any

from fastmcp import FastMCP

# Import all tool modules
from prowler_mcp_server.prowler_app.tools import (
    compliance,
    findings,
    iam,
    integrations,
    muting,
    providers,
    resources,
    scans,
)
from pydantic import Field

# Initialize MCP server
app_mcp_server = FastMCP("prowler-app")


# ============================================================================
# SECURITY FINDINGS
# ============================================================================


@app_mcp_server.tool()
async def search_security_findings(
    severity: list[str] = Field(
        [],
        description="Filter by severity levels. Multiple values allowed: critical, high, medium, low, informational. If empty, all severities are returned.",
    ),
    status: list[str] = Field(
        ["FAIL"],
        description="Filter by finding status. Multiple values allowed: FAIL (security issue found), PASS (no issue found), MANUAL (requires manual verification)",
    ),
    provider_type: list[str] = Field(
        [],
        description="Filter by cloud provider type.",
    ),
    provider_alias: str | None = Field(
        None,
        description="Filter by specific provider alias/name (partial match supported)",
    ),
    region: list[str] = Field(
        [],
        description="Filter by cloud regions. Multiple values allowed (e.g., us-east-1, eu-west-1). If empty, all regions are returned.",
    ),
    service: list[str] = Field(
        [],
        description="Filter by cloud service. Multiple values allowed (e.g., s3, ec2, iam, keyvault). If empty, all services are returned.",
    ),
    resource_type: list[str] = Field(
        [],
        description="Filter by resource type. Multiple values allowed. If empty, all resource types are returned.",
    ),
    check_id: list[str] = Field(
        [],
        description="Filter by specific security check IDs. Multiple values allowed. If empty, all check IDs are returned.",
    ),
    muted: bool | None = Field(
        None,
        description="Filter by muted status. True for muted findings only, False for active findings only. If not specified, returns both",
    ),
    delta: list[str] = Field(
        [],
        description="Show only new or changed findings. Multiple values allowed: new (not seen in previous scans), changed (modified since last scan). If empty, all findings are returned.",
    ),
    date_from: str | None = Field(
        None,
        description="Start date for range query (ISO 8601 format YYYY-MM-DD). IMPORTANT: Maximum date range is 2 days. If only one boundary is provided, the other will be auto-calculated to maintain the 2-day window",
    ),
    date_to: str | None = Field(
        None,
        description="End date for range query (ISO 8601 format YYYY-MM-DD). Can be used alone or with date_from",
    ),
    search: str | None = Field(
        None, description="Free-text search term across finding details"
    ),
    page_size: int = Field(
        100, description="Number of results to return per page. Default: 100, Max: 1000"
    ),
    page_number: int = Field(
        1, description="Page number to retrieve (1-indexed). Default: 1"
    ),
) -> dict[str, Any]:
    """Search and filter security findings across all cloud providers with rich filtering capabilities.

    This is the primary tool for browsing and filtering security findings. Returns lightweight findings
    optimized for searching across large result sets. For detailed information about a specific finding,
    use get_finding_details.

    Default behavior:
    - Returns latest findings from most recent scans (no date parameters needed)
    - Filters to FAIL status only (security issues found)
    - Returns 100 results per page

    Date filtering:
    - Without dates: queries latest findings (most efficient)
    - With dates: queries historical findings (2-day maximum range)

    Each finding includes:
    - Core identification: id, uid, check_id
    - Security context: status, severity, check_metadata (title, description, remediation)
    - State tracking: delta (new/changed), muted status
    - Extended details: status_extended for additional context

    Returns:
        Paginated list of simplified findings with total count and pagination metadata
    """
    return await findings.search_security_findings(
        severity=severity,
        status=status,
        provider_type=provider_type,
        provider_alias=provider_alias,
        region=region,
        service=service,
        resource_type=resource_type,
        check_id=check_id,
        muted=muted,
        delta=delta,
        date_from=date_from,
        date_to=date_to,
        search=search,
        page_size=page_size,
        page_number=page_number,
    )


@app_mcp_server.tool()
async def get_finding_details(
    finding_id: str = Field(description="UUID of the finding to retrieve"),
) -> dict[str, Any]:
    """Retrieve comprehensive details about a specific security finding by its ID.

    This tool provides MORE detailed information than search_security_findings. Use this when you need
    to deeply analyze a specific finding or understand its complete context and history.

    Additional information compared to search_security_findings:
    - Temporal metadata: when the finding was first seen, inserted, and last updated
    - Scan relationship: ID of the scan that generated this finding
    - Resource relationships: IDs of all cloud resources associated with this finding

    Workflow:
    1. Use search_security_findings to browse and filter across many findings
    2. Use get_finding_details to drill down into specific findings of interest

    Returns:
        dict containing detailed finding with comprehensive security metadata, temporal information,
        and relationships to scans and resources
    """
    return await findings.get_finding_details(
        finding_id=finding_id,
    )


@app_mcp_server.tool()
async def get_findings_overview(
    provider_type: list[str] = Field(
        [],
        description="Filter statistics by cloud provider. Multiple values allowed. If empty, all providers are returned.",
    ),
) -> dict[str, Any]:
    """Get high-level statistics about security findings formatted as a human-readable markdown report.

    Use this tool to get a quick overview of your security posture without retrieving individual findings.
    Perfect for understanding trends, identifying areas of concern, and tracking improvements over time.

    The report includes:
    - Summary statistics: total findings, fail/pass/muted counts with percentages
    - Delta analysis: breakdown of new vs changed findings
    - Trending information: how findings are evolving over time

    Output format: Markdown-formatted report ready to present to users or include in documentation.

    Use cases:
    - Quick security posture assessment
    - Tracking remediation progress over time
    - Identifying which providers have most issues
    - Understanding finding trends (improving or degrading)

    Returns:
        Dictionary with 'report' key containing markdown-formatted summary statistics
    """
    return await findings.get_findings_overview(provider_type=provider_type)


# ============================================================================
# COMPLIANCE
# ============================================================================


@app_mcp_server.tool()
async def search_compliance_frameworks(
    scan_id: str | None = Field(
        None,
        description="UUID of the scan to get compliance frameworks for. If omitted, returns compliance data from the latest completed scan of each provider",
    ),
    framework: str | None = Field(
        None,
        description="Filter by specific compliance framework ID (e.g., cis_1.5_aws, pci_dss_v4.0_aws)",
    ),
    region: list[str] = Field(
        [],
        description="Filter by cloud regions. Multiple values allowed. If empty, all regions are returned.",
    ),
    page_size: int = Field(
        100, description="Number of results to return per page. Default: 100"
    ),
    page_number: int = Field(
        1, description="Page number to retrieve (1-indexed). Default: 1"
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
        Paginated list of compliance frameworks with:
        - frameworks: List of framework objects with compliance statistics
        - total_count: Total number of frameworks matching filters
        - page_number: Current page number
        - page_size: Number of results per page
        - has_next: Whether more pages are available
        - has_prev: Whether previous pages exist
    """
    return await compliance.search_compliance_frameworks(
        scan_id=scan_id,
        framework=framework,
        region=region,
        page_size=page_size,
        page_number=page_number,
    )


# TODO: Create a tool with custom logic to given a compliance framework and a
# scan id/provider uid, return the compliance general statistics (total requirements, passed,
#  failed, manual) and the requirements that were not met.


# ============================================================================
# CLOUD PROVIDERS
# ============================================================================


@app_mcp_server.tool()
async def search_cloud_providers(
    provider_id: list[str] | None = Field(
        None,
        description="Get details for specific provider UUID(s). Multiple values allowed. When provided, other filters are ignored",
    ),
    provider_type: list[str] | None = Field(
        None,
        description="Filter by cloud type. Multiple values allowed: aws, azure, gcp, kubernetes, m365, github",
    ),
    alias: str | None = Field(
        None, description="Search by provider alias/name (partial match supported)"
    ),
    connected: bool | None = Field(
        None,
        description="Filter by connection status. True for connected only, False for failed connections",
    ),
    include_secret_info: bool = Field(
        False,
        description="Include associated secret metadata (not secret values) in response",
    ),
) -> dict[str, Any]:
    """View and search configured cloud providers with their connection status.

    Returns a unified view of all cloud accounts across AWS, Azure, GCP, K8s, M365, and GitHub.
    Supports filtering by type, connection status, or alias.

    Returns:
        dict containing the API response with list of configured cloud providers, their connection status, and metadata
    """
    return await providers.search_cloud_providers(
        provider_id=provider_id,
        provider_type=provider_type,
        alias=alias,
        connected=connected,
        include_secret_info=include_secret_info,
    )


@app_mcp_server.tool()
async def connect_provider(
    provider_uid: str = Field(
        description="Unique identifier for the provider (AWS account ID, Azure subscription ID, GCP project ID, etc.)"
    ),
    alias: str | None = Field(
        None,
        description="Friendly name for this provider (e.g., 'Production AWS', 'Dev Azure')",
    ),
    credentials: dict[str, Any] | None = Field(
        None,
        description="Cloud-specific credentials object. Structure varies by provider: AWS (role_arn or access_key_id/secret_access_key), Azure (tenant_id/client_id/client_secret), GCP (service_account_key), K8s (kubeconfig). If not provided, provider is created without credentials",
    ),
) -> dict[str, Any]:
    """Connect new or existing Prowler provider for scanning.

    Handles the complete workflow: stores credentials securely, configures the provider,
    and verifies the connection works. Returns connection status and any configuration issues.
    Smart defaults based on cloud type (AWS role-based auth, Azure service principal, GCP service account, etc.).

    Returns:
        dict containing the provider data, connection status, and status message
    """
    return await providers.connect_provider(
        provider_uid=provider_uid,
        alias=alias,
        credentials=credentials,
    )


@app_mcp_server.tool()
async def delete_provider(
    provider_id: str = Field(description="UUID of the provider to remove"),
) -> dict[str, Any]:
    """Remove a Prowler provider.

    Stops future scans and cleans up unused credentials.

    Returns:
        dict containing status and confirmation message
    """
    return await providers.delete_provider(provider_id=provider_id)


# ============================================================================
# SCANS
# ============================================================================


@app_mcp_server.tool()
async def search_scans(
    scan_id: str | None = Field(
        None, description="Get details for a specific scan UUID"
    ),
    provider_id: str | None = Field(
        None, description="Filter by specific provider UUID"
    ),
    status: list[str] | None = Field(
        None,
        description="Filter by scan status. Multiple values allowed: available, scheduled, executing, completed, failed, cancelled",
    ),
    page_size: int = Field(100, description="Number of results per page. Default: 100"),
    page_number: int = Field(
        1, description="Page number to retrieve (1-indexed). Default: 1"
    ),
    include_summary: bool = Field(
        True,
        description="Include scan summary statistics (resource counts, finding counts, etc.)",
    ),
) -> dict[str, Any]:
    """View and track security scans across all providers.

    Shows scan execution status, progress, duration, and summary statistics.

    Returns:
        dict containing the API response with list of scans and their details
    """
    return await scans.search_scans(
        scan_id=scan_id,
        provider_id=provider_id,
        status=status,
        page_size=page_size,
        page_number=page_number,
        include_summary=include_summary,
    )


@app_mcp_server.tool()
async def run_security_scan(
    provider_ids: list[str] = Field(
        description="UUIDs of providers to scan. Multiple values allowed"
    ),
    schedule: bool = Field(
        False,
        description="If True, creates a daily scheduled scan instead of running once immediately",
    ),
) -> dict[str, Any]:
    """Start a new security scan on cloud providers.

    Can trigger an immediate scan or schedule daily automatic scans.

    Returns:
        dict containing the created scan(s) or schedule information
    """
    return await scans.run_security_scan(
        provider_ids=provider_ids,
        schedule=schedule,
    )


# ============================================================================
# RESOURCES
# ============================================================================


@app_mcp_server.tool()
async def search_resources(
    provider_type: list[str] | None = Field(
        None,
        description="Filter by cloud provider type. Multiple values allowed: aws, azure, gcp, kubernetes, m365, github",
    ),
    provider_alias: str | None = Field(
        None,
        description="Filter by specific provider alias/name (partial match supported)",
    ),
    service: list[str] | None = Field(
        None,
        description="Filter by cloud service. Multiple values allowed (e.g., s3, ec2, iam)",
    ),
    region: list[str] | None = Field(
        None, description="Filter by cloud regions. Multiple values allowed"
    ),
    resource_type: list[str] | None = Field(
        None, description="Filter by resource type. Multiple values allowed"
    ),
    resource_name: str | None = Field(
        None, description="Filter by resource name (partial match supported)"
    ),
    resource_uid: str | None = Field(
        None, description="Filter by exact resource UID (cloud-provider assigned ID)"
    ),
    tag_key: str | None = Field(
        None, description="Filter resources that have a specific tag key"
    ),
    tag_value: str | None = Field(
        None, description="Filter resources that have a specific tag value"
    ),
    tag: str | None = Field(None, description="Filter by tag in key:value format"),
    date_from: str | None = Field(
        None,
        description="Start date for range query (ISO 8601 format YYYY-MM-DD). Maximum date range is 2 days",
    ),
    date_to: str | None = Field(
        None, description="End date for range query (ISO 8601 format YYYY-MM-DD)"
    ),
    search: str | None = Field(
        None, description="Free-text search term across resource details"
    ),
    include_findings: bool = Field(
        False, description="Include associated security findings in response"
    ),
    include_provider: bool = Field(
        False, description="Include provider details in response"
    ),
    page_size: int = Field(100, description="Number of results per page. Default: 100"),
    page_number: int = Field(
        1, description="Page number to retrieve (1-indexed). Default: 1"
    ),
) -> dict[str, Any]:
    """Search and explore cloud resources discovered by Prowler across all providers.

    Provides inventory view of all cloud resources (EC2 instances, S3 buckets, IAM roles, etc.)
    discovered during scans, with rich filtering and tagging support.

    Returns:
        dict containing the API response with list of resources and their details
    """
    return await resources.search_resources(
        provider_type=provider_type,
        provider_alias=provider_alias,
        service=service,
        region=region,
        resource_type=resource_type,
        resource_name=resource_name,
        resource_uid=resource_uid,
        tag_key=tag_key,
        tag_value=tag_value,
        tag=tag,
        date_from=date_from,
        date_to=date_to,
        search=search,
        include_findings=include_findings,
        include_provider=include_provider,
        page_size=page_size,
        page_number=page_number,
    )


@app_mcp_server.tool()
async def get_resource_details(
    resource_id: str = Field(description="UUID of the resource to retrieve"),
    include_findings: bool = Field(
        False, description="Include associated security findings in response"
    ),
    include_provider: bool = Field(
        False, description="Include provider details in response"
    ),
) -> dict[str, Any]:
    """Retrieve comprehensive details about a specific cloud resource by its ID.

    Returns:
        dict containing the API response with single resource data and optional related findings/provider info
    """
    return await resources.get_resource_details(
        resource_id=resource_id,
        include_findings=include_findings,
        include_provider=include_provider,
    )


@app_mcp_server.tool()
async def get_resource_metadata(
    provider_type: list[str] | None = Field(
        None,
        description="Filter by provider type. Multiple values allowed: aws, azure, gcp, kubernetes, m365, github",
    ),
    provider_alias: str | None = Field(
        None, description="Filter by specific provider alias/name"
    ),
    date_from: str | None = Field(
        None,
        description="Start date for range query (ISO 8601 format YYYY-MM-DD). Maximum date range is 2 days",
    ),
    date_to: str | None = Field(
        None, description="End date for range query (ISO 8601 format YYYY-MM-DD)"
    ),
) -> dict[str, Any]:
    """Retrieve available metadata values for dynamic filtering of resources.

    Returns unique values for resource types, services, regions, and tags that exist in your environment.
    Useful for building dynamic filter dropdowns.

    Returns:
        dict containing the API response with available metadata values (resource types, services, regions, tags)
    """
    return await resources.get_resource_metadata(
        provider_type=provider_type,
        provider_alias=provider_alias,
        date_from=date_from,
        date_to=date_to,
    )


# ============================================================================
# INTEGRATIONS
# ============================================================================


@app_mcp_server.tool()
async def list_integrations() -> dict[str, Any]:
    """View all external integrations (Slack, Jira, AWS Security Hub, S3 exports, etc.).

    Shows connection status, last activity, and which providers each integration monitors.

    Returns:
        dict containing the API response with list of configured integrations and their connection status
    """
    return await integrations.list_integrations()


@app_mcp_server.tool()
async def delete_integration(
    integration_id: str = Field(description="UUID of the integration to remove"),
) -> dict[str, Any]:
    """Disconnect and remove an integration.

    Stops automatic syncing but preserves historical sync records.

    Returns:
        dict containing status and confirmation message
    """
    return await integrations.delete_integration(integration_id=integration_id)


# ============================================================================
# MUTING
# ============================================================================


@app_mcp_server.tool()
async def get_mutelist_config() -> dict[str, Any]:
    """Retrieve the current mute list configured in the Prowler Tenant.

    Mute lists allow you to suppress specific findings from appearing in reports.
    Organized by account/provider, check, region, and resource.

    Returns:
        dict containing the API response with current mutelist processor configuration
    """
    return await muting.get_mutelist_config()


@app_mcp_server.tool()
async def create_mutelist(
    mutelist: dict[str, Any] = Field(
        description="Mutelist configuration in JSON format. Structure: {Mutelist: {Accounts: {<provider_uuid>: {Checks: {<check_id_or_*>: {Regions: [regions], Resources: [resources]}}}}}. Use '*' as wildcard for all checks/regions/resources. Account ID should be the provider UUID"
    ),
) -> dict[str, Any]:
    """Create a new mutelist.

    Defines which findings should be muted/suppressed. Organized hierarchically by account, check, region, and resource.
    Example structure:
    {
      "Mutelist": {
        "Accounts": {
          "provider-uuid-here": {
            "Checks": {
              "*": {
                "Regions": ["*"],
                "Resources": ["resource-name-to-mute"]
              }
            }
          }
        }
      }
    }

    Returns:
        dict containing the created mutelist processor
    """
    return await muting.create_mutelist(mutelist=mutelist)


@app_mcp_server.tool()
async def delete_mutelist() -> dict[str, Any]:
    """Delete the current mutelist.

    Removes all mute rules. Findings that were previously muted will become visible again.

    Returns:
        dict containing status and confirmation message
    """
    return await muting.delete_mutelist()


# ============================================================================
# IAM & RBAC
# ============================================================================


@app_mcp_server.tool()
async def list_team_members() -> dict[str, Any]:
    """View all users in your Prowler tenant with their roles and access status.

    Returns:
        dict containing the API response with paginated list of users, their roles, and access status
    """
    return await iam.list_team_members()


@app_mcp_server.tool()
async def get_user_access_details(
    user_id: str = Field(description="UUID of the user to retrieve"),
) -> dict[str, Any]:
    """Get comprehensive access information for a specific user.

    Returns:
        dict containing the API response with user details including all roles, permissions, and tenant memberships
    """
    return await iam.get_user_access_details(user_id=user_id)


@app_mcp_server.tool()
async def list_roles() -> dict[str, Any]:
    """View all roles and their permissions in your Prowler tenant.

    Returns:
        dict containing the API response with list of roles, their permission settings, and user assignments
    """
    return await iam.list_roles()
