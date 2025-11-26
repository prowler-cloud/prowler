"""Scan Operations tools for Prowler App MCP Server.

This module provides tools for managing and tracking security scans.
"""

from typing import Any

from prowler_mcp_server.prowler_app.tools.base import BaseTool
from pydantic import Field


class ScansTools(BaseTool):
    """Tools for scan management operations.

    Provides tools for:
    - Searching and viewing scans
    - Running security scans
    """

    async def search_scans(
        self,
        scan_id: str | None = Field(
            default=None, description="Get details for a specific scan UUID"
        ),
        provider_id: str | None = Field(
            default=None, description="Filter by specific provider UUID"
        ),
        status: list[str] | None = Field(
            default=None,
            description="Filter by scan status. Multiple values allowed: available, scheduled, executing, completed, failed, cancelled",
        ),
        page_size: int = Field(
            default=100, description="Number of results per page. Default: 100"
        ),
        page_number: int = Field(
            default=1, description="Page number to retrieve (1-indexed). Default: 1"
        ),
        include_summary: bool = Field(
            default=True,
            description="Include scan summary statistics (resource counts, finding counts, etc.)",
        ),
    ) -> dict[str, Any]:
        """View and track security scans across all providers.

        Shows scan execution status, progress, duration, and summary statistics.

        Returns:
            dict containing the API response with list of scans and their details
        """
        # If specific scan_id requested, fetch individual scan
        if scan_id:
            params = {}
            if include_summary:
                params["include"] = "provider"
            return await self.api_client.get(f"/api/v1/scans/{scan_id}", params=params)

        # Build filter parameters
        params = {}
        if provider_id:
            params["filter[provider]"] = provider_id
        if status:
            params["filter[state__in]"] = status

        # Pagination
        params["page[size]"] = page_size
        params["page[number]"] = page_number

        clean_params = self.api_client.build_filter_params(params)

        return await self.api_client.get("/api/v1/scans", params=clean_params)

    async def run_security_scan(
        self,
        provider_ids: list[str] = Field(
            description="UUIDs of providers to scan. Multiple values allowed"
        ),
        schedule: bool = Field(
            default=False,
            description="If True, creates a daily scheduled scan instead of running once immediately",
        ),
    ) -> dict[str, Any]:
        """Start a new security scan on cloud providers.

        Can trigger an immediate scan or schedule daily automatic scans.

        Returns:
            dict containing scan ID(s) for tracking progress and confirmation message
        """
        self.logger.info(f"Starting scan for providers: {provider_ids}")

        # Create scans for each provider
        scan_responses = []
        for provider_id in provider_ids:
            self.logger.info(f"Creating scan for provider {provider_id}...")

            scan_body = {
                "data": {
                    "type": "scans",
                    "relationships": {
                        "provider": {
                            "data": {
                                "type": "providers",
                                "id": provider_id,
                            }
                        }
                    },
                }
            }

            scan_response = await self.api_client.post(
                "/api/v1/scans", json_data=scan_body
            )
            scan_id = scan_response["data"]["id"]
            self.logger.info(f"Scan created with ID {scan_id}")

            # Schedule if requested
            if schedule:
                self.logger.info(
                    f"Scheduling daily scans for provider {provider_id}..."
                )
                try:
                    await self.api_client.post(
                        "/api/v1/schedules/daily",
                        json_data={
                            "data": {
                                "type": "schedules",
                                "relationships": {
                                    "provider": {
                                        "data": {
                                            "type": "providers",
                                            "id": provider_id,
                                        }
                                    }
                                },
                            }
                        },
                    )
                    self.logger.info("Daily schedule created")
                    scan_response["scheduled"] = True
                except Exception as e:
                    self.logger.warning(f"Error creating schedule: {e}")
                    scan_response["scheduled"] = False

            scan_responses.append(scan_response)

        if len(scan_responses) == 1:
            return {
                "data": scan_responses[0]["data"],
                "status": "scheduled" if schedule else "created",
                "message": (
                    "Scan created and scheduled successfully. Daily recurrence enabled."
                    if schedule
                    else "Scan created successfully."
                ),
                "scan_id": scan_responses[0]["data"]["id"],
            }
        else:
            return {
                "data": [r["data"] for r in scan_responses],
                "status": "scheduled" if schedule else "created",
                "message": f"Created {len(scan_responses)} scans"
                + (" with daily schedules" if schedule else ""),
                "scan_ids": [r["data"]["id"] for r in scan_responses],
            }
