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
    severity: list[str] | None = Field(
        None,
        description="Filter by severity levels. Multiple values allowed: critical, high, medium, low, informational",
    ),
    status: list[str] | None = Field(
        None,
        description="Filter by finding status. Multiple values allowed: FAIL (security issue found), PASS (no issue found), MANUAL (requires manual verification)",
    ),
    provider_type: list[str] | None = Field(
        None,
        description="Filter by cloud provider type. Multiple values allowed: aws, azure, gcp, kubernetes, m365, github",
    ),
    provider_alias: str | None = Field(
        None,
        description="Filter by specific provider alias/name (partial match supported)",
    ),
    region: list[str] | None = Field(
        None,
        description="Filter by cloud regions. Multiple values allowed (e.g., us-east-1, eu-west-1)",
    ),
    service: list[str] | None = Field(
        None,
        description="Filter by cloud service. Multiple values allowed (e.g., s3, ec2, iam, keyvault)",
    ),
    resource_type: list[str] | None = Field(
        None, description="Filter by resource type. Multiple values allowed"
    ),
    check_id: list[str] | None = Field(
        None,
        description="Filter by specific security check IDs. Multiple values allowed",
    ),
    muted: bool | None = Field(
        None,
        description="Filter by muted status. True for muted findings only, False for active findings only. If not specified, returns both",
    ),
    delta: list[str] | None = Field(
        None,
        description="Show only new or changed findings. Multiple values allowed: new (not seen in previous scans), changed (modified since last scan)",
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

    By default retrieves the latest findings from the most recent scans. When any date parameter
    is provided, queries historical findings within a 2-day window.

    Returns:
        dict containing the API response with data (list of findings), meta (pagination info), and optional included resources
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
    include_resources: bool = Field(
        False, description="Include full resource details in response"
    ),
    include_scan_info: bool = Field(
        False, description="Include scan metadata in response"
    ),
) -> dict[str, Any]:
    """Retrieve comprehensive details about a specific security finding by its ID.

    Returns:
        dict containing the API response with single finding data and optional included resources/scan info
    """
    return await findings.get_finding_details(
        finding_id=finding_id,
        include_resources=include_resources,
        include_scan_info=include_scan_info,
    )


@app_mcp_server.tool()
async def get_findings_overview(
    provider_type: list[str] | None = Field(
        None,
        description="Filter statistics by provider. Multiple values allowed: aws, azure, gcp, kubernetes, m365, github",
    ),
) -> dict[str, Any]:
    """Retrieve high-level statistics and aggregated metrics about findings across your environment.

    Provides summary statistics like total findings, findings by severity, findings by status, and trends over time.

    Returns:
        dict containing the API response with aggregated statistics in a human-readable summary format
    """
    return await findings.get_findings_overview(provider_type=provider_type)


# ============================================================================
# COMPLIANCE
# ============================================================================


@app_mcp_server.tool()
async def search_compliance_frameworks(
    scan_id: str = Field(
        description="UUID of the scan to get compliance frameworks for"
    ),
    framework: str | None = Field(
        None,
        description="Filter by specific compliance framework ID (e.g., cis_1.5_aws, pci_dss_v4.0_aws)",
    ),
    region: list[str] | None = Field(
        None, description="Filter by cloud regions. Multiple values allowed"
    ),
    include_metadata: bool = Field(
        False, description="Include detailed framework metadata in response"
    ),
) -> dict[str, Any]:
    """Search and retrieve compliance frameworks with their status for a specific scan.

    Shows which compliance frameworks apply to the scan and their overall pass/fail status.

    Returns:
        dict containing the API response with list of compliance frameworks and their status
    """
    return await compliance.search_compliance_frameworks(
        scan_id=scan_id,
        framework=framework,
        region=region,
        include_metadata=include_metadata,
    )


@app_mcp_server.tool()
async def get_compliance_framework_details(
    scan_id: str = Field(description="UUID of the scan"),
    compliance_id: str = Field(
        description="ID of the compliance framework (e.g., cis_1.5_aws, pci_dss_v4.0_aws)"
    ),
    region: list[str] | None = Field(
        None, description="Filter by cloud regions. Multiple values allowed"
    ),
    status: list[str] | None = Field(
        None,
        description="Filter by requirement status. Multiple values allowed: PASS, FAIL, MANUAL",
    ),
) -> dict[str, Any]:
    """Get detailed requirement-level information for a specific compliance framework.

    Shows individual requirements/controls within the framework and their pass/fail status.

    Returns:
        dict containing the API response with detailed compliance requirements and their status
    """
    return await compliance.get_compliance_framework_details(
        scan_id=scan_id,
        compliance_id=compliance_id,
        region=region,
        status=status,
    )


@app_mcp_server.tool()
async def get_compliance_requirement_details(
    compliance_id: str = Field(
        description="ID of the compliance framework (e.g., cis_1.5_aws)"
    ),
    requirement_id: str | None = Field(
        None,
        description="Specific requirement ID within the framework to retrieve details for",
    ),
) -> dict[str, Any]:
    """Drill down into a specific compliance requirement to see detailed attributes.

    Provides information about what the requirement checks, its severity, and related security checks.

    Returns:
        dict containing the API response with detailed requirement attributes
    """
    return await compliance.get_compliance_requirement_details(
        compliance_id=compliance_id,
        requirement_id=requirement_id,
    )


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
