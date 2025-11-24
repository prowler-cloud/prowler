"""Scan Operations tools for Prowler App MCP Server."""

from typing import Literal

from prowler_mcp_server.lib.logger import logger
from prowler_mcp_server.prowler_app.utils.api_client import ProwlerAPIClient


async def search_scans(
    scan_id: str | None = None,
    provider_id: str | None = None,
    status: (
        list[
            Literal[
                "available",
                "executing",
                "completed",
                "failed",
                "cancelled",
                "scheduled",
            ]
        ]
        | None
    ) = None,
    page_size: int = 100,
    page_number: int = 1,
    include_summary: bool = True,
) -> dict[str, any]:
    """View and track security scans across all providers.

    Shows scan history with status (running, completed, failed), duration, findings summary,
    and when they ran. Filter by provider or status.

    Args:
        scan_id: Get details for a specific scan by UUID
        provider_id: Filter scans by specific provider
        status: Filter by scan status
        page_size: Number of results per page. Default: 100, Max: 1000
        page_number: Page number to retrieve (1-indexed). Default: 1
        include_summary: Include findings summary for each scan. Default: True

    Returns:
        List of scans with status, progress, and findings summary

    Raises:
        Exception: If API request fails
    """
    client = ProwlerAPIClient()

    # If specific scan_id requested, fetch individual scan
    if scan_id:
        params = {}
        if include_summary:
            params["include"] = "provider"
        return await client.get(f"/api/v1/scans/{scan_id}", params=params)

    # Build filter parameters
    params = {}
    if provider_id:
        params["filter[provider]"] = provider_id
    if status:
        params["filter[state__in]"] = status

    # Pagination
    params["page[size]"] = page_size
    params["page[number]"] = page_number

    clean_params = client.build_filter_params(params)

    return await client.get("/api/v1/scans", params=clean_params)


async def run_security_scan(
    provider_ids: list[str],
    schedule: bool = False,
) -> dict[str, any]:
    """Start a new security scan on cloud providers.

    Returns scan ID for tracking progress and handles scheduling if requested.

    Args:
        provider_ids: UUIDs of providers to scan
        schedule: Schedule for recurring scans, every 24h. Default: False

    Returns:
        The created scan object with scan ID for tracking

    Raises:
        Exception: If API request fails
    """
    client = ProwlerAPIClient()

    logger.info(f"Starting scan for providers: {provider_ids}")

    # Create scans for each provider
    scan_responses = []
    for provider_id in provider_ids:
        logger.info(f"Creating scan for provider {provider_id}...")

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

        scan_response = await client.post("/api/v1/scans", json_data=scan_body)
        scan_id = scan_response["data"]["id"]
        logger.info(f"Scan created with ID {scan_id}")

        # Schedule if requested
        if schedule:
            logger.info(f"Scheduling daily scans for provider {provider_id}...")
            try:
                await client.post(
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
                logger.info("Daily schedule created")
                scan_response["scheduled"] = True
            except Exception as e:
                logger.warning(f"Error creating schedule: {e}")
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
