"""Integration tools for Prowler App MCP Server - stub implementation."""

from prowler_mcp_server.prowler_app.utils.api_client import ProwlerAPIClient


async def list_integrations() -> dict[str, any]:
    """View all external integrations (Slack, Jira, AWS Security Hub, S3 exports, etc.).

    Shows connection status, last activity, and which providers each integration monitors.

    Returns:
        List of configured integrations with connection status

    Raises:
        Exception: If API request fails
    """
    client = ProwlerAPIClient()
    return await client.get("/api/v1/integrations")


async def delete_integration(integration_id: str) -> dict[str, any]:
    """Disconnect and remove an integration.

    Stops automatic syncing but preserves historical sync records.

    Args:
        integration_id: UUID of the integration to remove

    Returns:
        Confirmation of deletion

    Raises:
        Exception: If API request fails
    """
    client = ProwlerAPIClient()
    await client.delete(f"/api/v1/integrations/{integration_id}")

    return {
        "status": "deleted",
        "message": f"Integration {integration_id} removed successfully",
    }
