"""Tests for the compliance tools.

Both compliance tools answer for exactly one scan. ``scan_id`` names it
directly; ``provider_id`` names it indirectly, as "the latest completed scan of
this provider". Passing both is not a refinement of either -- the scan the
caller named may belong to a different provider entirely -- so it is rejected
rather than resolved by preferring one, which would answer confidently for a
provider nobody asked about.

Tools are driven through an in-memory MCP client so FastMCP resolves the
pydantic ``Field`` defaults and a raised failure arrives the way a client sees
it.
"""

import pytest
from fastmcp import Client

from tests.helpers.jsonapi import jsonapi_collection, jsonapi_resource

SCANS = "/api/v1/scans"
OVERVIEWS = "/api/v1/compliance-overviews"
REQUIREMENTS = f"{OVERVIEWS}/requirements"

TOOLS = [
    "prowler_get_compliance_overview",
    "prowler_get_compliance_framework_state_details",
]


def arguments(tool: str, **overrides) -> dict:
    """Build the arguments for either tool, which differ only in compliance_id."""
    payload = dict(overrides)
    if tool.endswith("framework_state_details"):
        payload["compliance_id"] = "cis_1.5_aws"
    return payload


@pytest.mark.parametrize("tool", TOOLS)
async def test_neither_a_scan_nor_a_provider_is_refused_before_any_request(
    mcp_root_server, mock_api_client, mock_router, tool
):
    """There is no scan to answer for, and no way to guess one."""
    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception, match="must be provided"):
            await client.call_tool(tool, arguments(tool))

    assert mock_router.paths() == []


@pytest.mark.parametrize("tool", TOOLS)
async def test_a_scan_and_a_provider_together_are_refused_rather_than_reconciled(
    mcp_root_server, mock_api_client, mock_router, tool
):
    """Silently keeping the scan would answer for whichever provider owns it.

    That report names a scan the caller did ask for, so nothing about it looks
    wrong -- while the provider they also named went unread.
    """
    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception, match="not both"):
            await client.call_tool(
                tool, arguments(tool, scan_id="s1", provider_id="p1")
            )

    assert mock_router.paths() == []


@pytest.mark.parametrize("tool", TOOLS)
async def test_a_provider_on_its_own_resolves_to_its_latest_completed_scan(
    mcp_root_server, mock_api_client, mock_router, tool
):
    """The indirection is the point of accepting a provider at all."""
    mock_router.add(
        "GET",
        SCANS,
        json=jsonapi_collection(
            [jsonapi_resource("scans", "s9", {"state": "completed"})]
        ),
    )
    mock_router.add("GET", OVERVIEWS, json=jsonapi_collection([]))
    mock_router.add("GET", REQUIREMENTS, json=jsonapi_collection([]))
    # Each tool reads the compliance state from its own endpoint; both filter it
    # by the scan that had to be resolved first.
    read = OVERVIEWS if tool.endswith("overview") else REQUIREMENTS

    async with Client(mcp_root_server) as client:
        await client.call_tool(tool, arguments(tool, provider_id="p1"))

    assert mock_router.query_params("GET", SCANS)["filter[provider]"] == "p1"
    assert mock_router.query_params("GET", read)["filter[scan_id]"] == "s9"


@pytest.mark.parametrize("tool", TOOLS)
async def test_a_provider_with_no_completed_scan_is_named_as_the_bad_argument(
    mcp_root_server, mock_api_client, mock_router, tool
):
    """Nothing has been scanned yet, so there is no compliance state to report."""
    mock_router.add("GET", SCANS, json=jsonapi_collection([]))

    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception, match="No completed scans found for provider p1"):
            await client.call_tool(tool, arguments(tool, provider_id="p1"))
