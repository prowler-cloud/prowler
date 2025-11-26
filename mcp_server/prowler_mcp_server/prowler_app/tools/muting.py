"""Muting tools for Prowler App MCP Server.

This module provides tools for managing mutelists and mute rules.
Some functions are stubs for future API implementation.
"""

from typing import Any

from prowler_mcp_server.prowler_app.tools.base import BaseTool
from pydantic import Field


class MutingTools(BaseTool):
    """Tools for muting operations.

    Provides tools for:
    - Managing mutelist configuration
    - Creating and deleting mutelists
    - Managing mute rules (stubs)
    """

    # Mute List functions
    async def get_mutelist_config(self) -> dict[str, Any]:
        """Retrieve the current mute list configured in the Prowler Tenant.

        Returns:
            The current mutelist processor configuration

        Raises:
            Exception: If API request fails
        """
        # Get processors and filter for mutelist type
        processors = await self.api_client.get(
            "/api/v1/processors", params={"filter[processor_type]": "mutelist"}
        )
        return processors

    async def create_mutelist(
        self,
        mutelist: dict[str, Any] = Field(
            description="JSON object with mutelist formatting"
        ),
    ) -> dict[str, Any]:
        """Create a new mutelist.

        Args:
            mutelist: JSON object with mutelist formatting

        Returns:
            The created mutelist processor

        Raises:
            Exception: If API request fails
        """
        body = {
            "data": {
                "type": "processors",
                "attributes": {
                    "processor_type": "mutelist",
                    "configuration": mutelist,
                },
            }
        }
        return await self.api_client.post("/api/v1/processors", json_data=body)

    async def delete_mutelist(self) -> dict[str, Any]:
        """Delete the current mutelist.

        Returns:
            Confirmation of deletion

        Raises:
            Exception: If API request fails
        """
        # First get the mutelist processor ID
        processors = await self.api_client.get(
            "/api/v1/processors", params={"filter[processor_type]": "mutelist"}
        )
        if processors.get("data"):
            processor_id = processors["data"][0]["id"]
            await self.api_client.delete(f"/api/v1/processors/{processor_id}")
            return {
                "status": "deleted",
                "message": f"Mutelist {processor_id} deleted successfully",
            }
        return {"status": "not_found", "message": "No mutelist processor found"}

    # Mute Rules functions (stub - not implemented in API yet)
    async def list_mute_rules(self) -> dict[str, Any]:
        """Get a list of all mute rules with filtering options (stub).

        Returns:
            List of mute rules

        Raises:
            NotImplementedError: Feature not yet available in API
        """
        raise NotImplementedError("Mute rules API not yet available")

    async def create_mute_rule(
        self,
        rule_name: str = Field(description="Name for the mute rule"),
        reason: str = Field(description="Reason for muting the findings"),
        finding_ids: list[str] = Field(description="List of finding IDs to mute"),
    ) -> dict[str, Any]:
        """Create a new mute rule (stub).

        Args:
            rule_name: Name for the mute rule
            reason: Reason for muting the findings
            finding_ids: List of finding IDs to mute

        Returns:
            The created mute rule

        Raises:
            NotImplementedError: Feature not yet available in API
        """
        raise NotImplementedError("Mute rules API not yet available")

    async def delete_mute_rule(
        self,
        mute_rule_id: str = Field(description="UUID of the mute rule to remove"),
    ) -> dict[str, Any]:
        """Delete a mute rule (stub).

        Args:
            mute_rule_id: UUID of the mute rule to remove

        Returns:
            Confirmation of deletion

        Raises:
            NotImplementedError: Feature not yet available in API
        """
        raise NotImplementedError("Mute rules API not yet available")
