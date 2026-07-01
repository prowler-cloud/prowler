"""Security Scans tools for Prowler App MCP Server.

This module provides tools for managing and monitoring Prowler security scans.
"""

from typing import Any, Literal

from pydantic import Field

from prowler_mcp_server.prowler_app.models.scans import (
    DetailedScan,
    ScanCreationResult,
    ScansListResponse,
    ScheduleCreationResult,
)
from prowler_mcp_server.prowler_app.tools.base import BaseTool


class ScansTools(BaseTool):
    """Tools for security scan operations.

    Provides tools for:
    - prowler_app_list_scans: Search and filter scans with rich filtering capabilities
    - prowler_app_get_scan: Get comprehensive details about a specific scan
    - prowler_app_trigger_scan: Trigger manual security scans for providers
    - prowler_app_schedule_daily_scan: Schedule automated daily scans for continuous monitoring
    - prowler_app_update_scan: Update scan names for better organization
    """

    async def list_scans(
        self,
        provider_id: list[str] = Field(
            default=[],
            description="Filter by Prowler's internal UUID(s) (v4) for specific provider(s), generated when the provider was registered. Use `prowler_app_search_providers` tool to find provider IDs",
        ),
        provider_type: list[str] = Field(
            default=[],
            description="Filter by cloud provider type. For all valid values, please refer to Prowler Hub/Prowler Documentation that you can also find in form of tools in this MCP Server",
        ),
        provider_alias: str | None = Field(
            default=None,
            description="Filter by provider alias/friendly name. Partial match supported (case-insensitive)",
        ),
        state: list[
            Literal[
                "available",
                "scheduled",
                "executing",
                "completed",
                "failed",
                "cancelled",
            ]
        ] = Field(
            default=[],
            description="Filter by scan execution state.",
        ),
        trigger: Literal["manual", "scheduled"] | None = Field(
            default=None,
            description="Filter by how the scan was initiated. Options: 'manual' (user-initiated via prowler_app_trigger_scan), 'scheduled' (automated via prowler_app_schedule_daily_scan)",
        ),
        name: str | None = Field(
            default=None,
            description="Filter by scan name. Partial match supported (case-insensitive)",
        ),
        page_size: int = Field(
            default=50,
            description="Number of results to return per page",
        ),
        page_number: int = Field(
            default=1,
            description="Page number to retrieve (1-indexed)",
        ),
    ) -> dict[str, Any]:
        """List and filter security scans across all providers with rich filtering capabilities.

        IMPORTANT: This tool returns LIGHTWEIGHT scan information. Use this for fast searching and filtering
        across many scans. For complete scan details including progress, duration, and resource counts,
        use prowler_app_get_scan on specific scans of interest.

        Default behavior:
        - Returns all scans
        - Returns 50 scans per page
        - Includes all scan states (available, scheduled, executing, completed, failed, cancelled)

        Each scan includes:
        - Core identification: id (UUID for prowler_app_get_scan), name
        - Execution context: state, trigger (manual/scheduled)
        - Temporal data: started_at, completed_at
        - Provider relationship: provider_id

        Workflow:
        1. Use this tool to search and filter scans by provider, state, or date range
        2. Use prowler_app_get_scan with the scan 'id' to get progress, duration, and resource counts
        3. Use prowler_app_search_security_findings filtered by scan dates to analyze scan results
        """
        # Validate pagination
        self.api_client.validate_page_size(page_size)

        # Build query parameters
        params: dict[str, Any] = {
            "page[size]": page_size,
            "page[number]": page_number,
        }

        # Apply provider filters
        if provider_id:
            params["filter[provider__in]"] = provider_id
        if provider_type:
            params["filter[provider_type__in]"] = provider_type
        if provider_alias:
            params["filter[provider_alias__icontains]"] = provider_alias

        # Apply scan filters
        if state:
            params["filter[state__in]"] = state
        if trigger:
            params["filter[trigger]"] = trigger
        if name:
            params["filter[name__icontains]"] = name

        clean_params = self.api_client.build_filter_params(params)

        api_response = await self.api_client.get("/scans", params=clean_params)
        simplified_response = ScansListResponse.from_api_response(api_response)

        return simplified_response.model_dump()

    async def get_scan(
        self,
        scan_id: str = Field(
            description="Prowler's internal UUID (v4) for the scan to retrieve, generated when the scan was created (e.g., '123e4567-e89b-12d3-a456-426614174000'). Use `prowler_app_list_scans` tool to find scan IDs"
        ),
    ) -> dict[str, Any]:
        """Retrieve comprehensive details about a specific scan by its ID.

        IMPORTANT: This tool returns COMPLETE scan details.
        Use this after finding a specific scan via prowler_app_list_scans.

        This tool provides ALL information that prowler_app_list_scans returns PLUS:

        1. Execution Details:
           - progress: Scan completion progress as percentage (0-100%)
           - duration: Total scan duration in seconds from start to completion
           - unique_resource_count: Number of unique cloud resources discovered during the scan

        2. Temporal Metadata:
           - inserted_at: When the scan was created in the database
           - scheduled_at: When the scan was scheduled to run (for scheduled scans)
           - next_scan_at: When the next scan will run (for recurring daily scans)

        Useful for:
        - Monitoring scan progress during execution (via progress field)
        - Viewing scan results and metrics after completion
        - Debugging failed scans with detailed state information
        - Understanding scan scheduling patterns

        Workflow:
        1. Use prowler_app_list_scans to browse and filter scans
        2. Use this tool with the scan 'id' to monitor progress or view detailed results
        3. For completed scans, use prowler_app_search_security_findings filtered by date to analyze findings
        """
        # Fetch scan with all fields
        params = {
            "fields[scans]": "name,trigger,state,progress,duration,unique_resource_count,started_at,completed_at,scheduled_at,next_scan_at,inserted_at"
        }

        api_response = await self.api_client.get(f"/scans/{scan_id}", params=params)
        detailed_scan = DetailedScan.from_api_response(api_response["data"])

        return detailed_scan.model_dump()

    async def trigger_scan(
        self,
        provider_id: str = Field(
            description="Prowler's internal UUID (v4) for the provider to scan, generated when the provider was registered in the system (e.g., '4d0e2614-6385-4fa7-bf0b-c2e2f75c6877'). Use `prowler_app_search_providers` tool to find the provider ID"
        ),
        name: str | None = Field(
            default=None,
            description="Optional human-friendly name for the scan. Use descriptive names to identify scan purpose or context, e.g., 'Weekly Production Security Audit', 'Pre-Deployment Validation', 'Compliance Check Q4 2025'",
        ),
    ) -> dict[str, Any]:
        """Trigger a manual security scan for a provider.

        IMPORTANT: This tool returns immediately once the scan is created.
        The scan will continue running in the background. Use `prowler_app_get_scan`
        with the returned scan ID to monitor progress and check when it completes.

        Example Useful Workflow:
        1. Use `prowler_app_search_providers` to find the provider_id you want to scan
        2. Use this tool to trigger the scan
        3. Use `prowler_app_get_scan` with the returned scan 'id' to monitor progress
        4. Once completed, use `prowler_app_search_security_findings` to analyze results
        """
        try:
            # Build request data
            request_data: dict[str, Any] = {
                "data": {
                    "type": "scans",
                    "attributes": {},
                    "relationships": {
                        "provider": {
                            "data": {
                                "type": "providers",
                                "id": provider_id,
                            },
                        },
                    },
                },
            }
            if name:
                request_data["data"]["attributes"]["name"] = name

            # Create scan (returns Task)
            self.logger.info(f"Creating scan for provider {provider_id}")
            task_response = await self.api_client.post("/scans", json_data=request_data)

            scan_id = (
                task_response.get("data", {})
                .get("attributes", {})
                .get("task_args", {})
                .get("scan_id", None)
            )

            if not scan_id:
                raise Exception("No scan_id returned from scan creation")

            self.logger.info(f"Scan created successfully: {scan_id}")
            scan_response = await self.api_client.get(f"/scans/{scan_id}")
            scan_info = DetailedScan.from_api_response(scan_response["data"])

            return ScanCreationResult(
                scan=scan_info,
                status="success",
                message=f"Scan {scan_id} created successfully. The scan may take some time to complete. Use prowler_app_get_scan tool with this ID to monitor progress.",
            ).model_dump()

        except Exception as e:
            self.logger.error(f"Scan creation failed: {e}")
            return ScanCreationResult(
                scan=None,
                status="failed",
                message=f"Scan creation failed: {str(e)}",
            ).model_dump()

    async def schedule_daily_scan(
        self,
        provider_id: str = Field(
            description="Prowler's internal UUID (v4) for the provider to scan, generated when the provider was registered in the system (e.g., '4d0e2614-6385-4fa7-bf0b-c2e2f75c6877'). Use `prowler_app_search_providers` tool to find the provider ID"
        ),
    ) -> dict[str, Any]:
        """Schedule automated daily scans for a provider for continuous security monitoring.

        Creates a recurring daily scan schedule that will automatically trigger
        scans every 24 hours (starting from the moment the schedule is created).
        The schedule persists until manually removed and will execute even when
        you're not actively using the system.

        IMPORTANT: This tool returns immediately once the daily schedule is created.
        The schedule will be set up in the background. Use `prowler_app_list_scans`
        filtered by provider_id and trigger='scheduled' to view scheduled scans.

        IMPORTANT: This creates a PERSISTENT schedule. The provider will be scanned
        automatically every 24 hours until the provider is deleted.

        Example Useful Workflow:
        1. Use `prowler_app_search_providers` to find the provider_id you want to monitor
        2. Use this tool to create the daily schedule
        3. Use `prowler_app_list_scans` filtered by provider_id to view scheduled and completed scans
        4. Monitor findings over time with `prowler_app_search_security_findings`
        """
        self.logger.info(f"Creating daily schedule for provider {provider_id}")
        task_response = await self.api_client.post(
            "/schedules/daily",
            json_data={
                "data": {
                    "type": "daily-schedules",
                    "attributes": {
                        "provider_id": provider_id,
                    },
                },
            },
        )
        task_state = (
            task_response.get("data", {}).get("attributes", {}).get("state", None)
        )

        if task_state == "available":
            return_message = "Daily schedule created successfully. The schedule is being set up in the background. Use prowler_app_list_scans with provider_id filter to view scheduled scans."
        else:
            return_message = "Daily schedule creation failed. Please try again later."

        return ScheduleCreationResult(
            scheduled=(task_state == "available"),
            message=return_message,
        ).model_dump()

    async def update_scan(
        self,
        scan_id: str = Field(
            description="Prowler's internal UUID (v4) for the scan to update, generated when the scan was created (e.g., '123e4567-e89b-12d3-a456-426614174000'). Use `prowler_app_list_scans` tool to find the scan ID if you only know the provider or scan name. Returns an error if the scan ID is invalid or not found."
        ),
        name: str = Field(
            description="New human-friendly name for the scan (3-100 characters). Use descriptive names to improve organization and tracking, e.g., 'Production Security Audit - Q4 2025', 'Post-Deployment Compliance Check'. IMPORTANT: Only the scan name can be updated - other attributes (state, progress, duration) are read-only and managed by the system."
        ),
    ) -> dict[str, Any]:
        """Update a scan's name for better organization and tracking.

        IMPORTANT: Only the scan name can be updated. Other scan attributes
        (state, progress, duration, etc.) are read-only and managed by the system.

        Example Useful Workflow:
        1. Use `prowler_app_list_scans` to find the scan you want to rename
        2. Use this tool with the scan 'id' and new name
        """
        api_response = await self.api_client.patch(
            f"/scans/{scan_id}",
            json_data={
                "data": {
                    "type": "scans",
                    "id": scan_id,
                    "attributes": {"name": name},
                },
            },
        )
        detailed_scan = DetailedScan.from_api_response(api_response["data"])

        return detailed_scan.model_dump()
