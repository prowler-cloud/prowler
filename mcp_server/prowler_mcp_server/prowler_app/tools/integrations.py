"""Integration tools for Prowler App MCP Server.

This module provides tools for managing external integrations
such as Slack, Jira, AWS Security Hub, and S3 exports.
"""

from typing import Any

from prowler_mcp_server.prowler_app.tools.base import BaseTool
from pydantic import Field


class IntegrationsTools(BaseTool):
    """Tools for integration management operations.

    Provides tools for:
    - Viewing configured integrations
    - Deleting integrations
    """

    async def list_integrations(self) -> dict[str, Any]:
        """View all external integrations (Slack, Jira, AWS Security Hub, S3 exports, etc.).

        Shows connection status, last activity, and which providers each integration monitors.

        Returns:
            List of configured integrations with connection status

        Raises:
            Exception: If API request fails
        """
        return await self.api_client.get("/api/v1/integrations")

    async def delete_integration(
        self,
        integration_id: str = Field(description="UUID of the integration to remove"),
    ) -> dict[str, Any]:
        """Disconnect and remove an integration.

        Stops automatic syncing but preserves historical sync records.

        Args:
            integration_id: UUID of the integration to remove

        Returns:
            Confirmation of deletion

        Raises:
            Exception: If API request fails
        """
        await self.api_client.delete(f"/api/v1/integrations/{integration_id}")

        return {
            "status": "deleted",
            "message": f"Integration {integration_id} removed successfully",
        }
