"""Tests for the muting tools.

Muting is permanent and deleting a rule does not undo it, so the one thing
these assertions protect is that an agent is never told a deletion failed when
it did not: the old answer keyed off the *shape* of the API's reply rather than
off anything having gone wrong, and said nothing a caller could act on.
"""

import pytest
from fastmcp import Client

from tests.helpers.jsonapi import jsonapi_document, jsonapi_error, jsonapi_resource

MUTE_RULE = "/api/v1/mute-rules/m1"


async def test_a_deleted_rule_is_reported_deleted_whatever_the_body(
    mcp_root_server, mock_api_client, mock_router
):
    """Prowler answers 204 with no body, but 200 with one is just as much a yes.

    The old check read ``success`` out of the parsed body, which only exists for
    the empty-body case, so a deletion that worked could be reported as
    "Failed to delete mute rule".
    """
    mock_router.add(
        "DELETE",
        MUTE_RULE,
        json=jsonapi_document(jsonapi_resource("mute-rules", "m1", {})),
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool("prowler_delete_mute_rule", {"rule_id": "m1"})

    assert "m1 deleted successfully" in result.data["message"]
    assert "stay muted" in result.data["message"]
    # A flag with one reachable value is not a fact, it is an invitation to
    # branch on a shape that does not exist.
    assert "success" not in result.data


async def test_an_empty_body_deletion_is_reported_the_same_way(
    mcp_root_server, mock_api_client, mock_router
):
    """The 204 path, which is what Prowler actually sends today."""
    mock_router.add("DELETE", MUTE_RULE, status=204)

    async with Client(mcp_root_server) as client:
        result = await client.call_tool("prowler_delete_mute_rule", {"rule_id": "m1"})

    assert "m1 deleted successfully" in result.data["message"]


async def test_a_refused_deletion_is_an_error(
    mcp_root_server, mock_api_client, mock_router
):
    """A rule that was not deleted has to leave the tool as an error."""
    mock_router.add(
        "DELETE", MUTE_RULE, status=404, json=jsonapi_error(404, "Not found.")
    )

    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception, match="Not found"):
            await client.call_tool("prowler_delete_mute_rule", {"rule_id": "m1"})
