"""Muting tools for Prowler App MCP Server - stub implementation."""

from prowler_mcp_server.prowler_app.utils.api_client import ProwlerAPIClient


# Mute List functions
async def get_mutelist_config() -> dict[str, any]:
    """Retrieve the current mute list configured in the Prowler Tenant.

    Returns:
        The current mutelist processor configuration

    Raises:
        Exception: If API request fails
    """
    client = ProwlerAPIClient()
    # Get processors and filter for mutelist type
    processors = await client.get(
        "/api/v1/processors", params={"filter[processor_type]": "mutelist"}
    )
    return processors


async def create_mutelist(mutelist: dict[str, any]) -> dict[str, any]:
    """Create a new mutelist.

    Args:
        mutelist: JSON object with mutelist formatting

    Returns:
        The created mutelist processor

    Raises:
        Exception: If API request fails
    """
    client = ProwlerAPIClient()
    body = {
        "data": {
            "type": "processors",
            "attributes": {
                "processor_type": "mutelist",
                "configuration": mutelist,
            },
        }
    }
    return await client.post("/api/v1/processors", json_data=body)


async def delete_mutelist() -> dict[str, any]:
    """Delete the current mutelist.

    Returns:
        Confirmation of deletion

    Raises:
        Exception: If API request fails
    """
    client = ProwlerAPIClient()
    # First get the mutelist processor ID
    processors = await client.get(
        "/api/v1/processors", params={"filter[processor_type]": "mutelist"}
    )
    if processors.get("data"):
        processor_id = processors["data"][0]["id"]
        await client.delete(f"/api/v1/processors/{processor_id}")
        return {
            "status": "deleted",
            "message": f"Mutelist {processor_id} deleted successfully",
        }
    return {"status": "not_found", "message": "No mutelist processor found"}


# Mute Rules functions (stub - not implemented in API yet)
async def list_mute_rules() -> dict[str, any]:
    """Get a list of all mute rules with filtering options (stub).

    Returns:
        List of mute rules

    Raises:
        NotImplementedError: Feature not yet available in API
    """
    raise NotImplementedError("Mute rules API not yet available")


async def create_mute_rule(
    rule_name: str, reason: str, finding_ids: list[str]
) -> dict[str, any]:
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


async def delete_mute_rule(mute_rule_id: str) -> dict[str, any]:
    """Delete a mute rule (stub).

    Args:
        mute_rule_id: UUID of the mute rule to remove

    Returns:
        Confirmation of deletion

    Raises:
        NotImplementedError: Feature not yet available in API
    """
    raise NotImplementedError("Mute rules API not yet available")
