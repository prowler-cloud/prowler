"""Tests for the argument types every tool shares.

The bug these pin: "required" alone does not stop a blank identifier. A model
that has no scan or query id to hand sends ``""`` rather than omitting the
argument, and an unguarded empty string travels into a URL path or a request
body -- where it comes back as a 404, or as an API rejection ("This field may
not be blank") that names no argument and leaves the model with nothing to fix.
"""

import pytest
from fastmcp import Client

from tests.helpers.jsonapi import jsonapi_collection, jsonapi_resource

SCAN_ID = "019ac0d6-90d5-73e9-9acf-c22e256f1bac"
QUERIES = f"/api/v1/attack-paths-scans/{SCAN_ID}/queries"


@pytest.mark.parametrize("query_id", ["", "   "], ids=["empty", "whitespace-only"])
async def test_a_blank_identifier_is_rejected_before_any_request_goes_out(
    mcp_root_server, mock_api_client, mock_router, query_id
):
    """The reported failure: a blank `query_id` reached Prowler as a 400.

    The message has to name the argument. Prowler's own answer to the blank value
    ("This field may not be blank") does not say which field, so the model had no
    way to tell `scan_id` from `query_id` from the reply.
    """
    async with Client(mcp_root_server) as client:
        result = await client.call_tool_mcp(
            "prowler_run_attack_paths_query",
            {"scan_id": SCAN_ID, "query_id": query_id},
        )

    assert result.isError is True
    assert "query_id" in result.content[0].text
    assert mock_router.requests == []


async def test_an_identifier_keeps_its_surrounding_whitespace_out_of_the_url(
    mcp_root_server, mock_api_client, mock_router
):
    """A padded id is the same id, and a raw one would build a URL-escaped path."""
    mock_router.add("GET", QUERIES, json=jsonapi_collection([]))

    async with Client(mcp_root_server) as client:
        result = await client.call_tool_mcp(
            "prowler_list_attack_paths_queries", {"scan_id": f"  {SCAN_ID}  "}
        )

    assert result.isError is False
    assert mock_router.paths() == [f"GET {QUERIES}"]


async def test_a_blank_optional_value_is_rejected_rather_than_written(
    mcp_root_server, mock_api_client, mock_router
):
    """An omitted optional means "leave it alone"; a blank one would blank the field.

    The API refuses it, so the only difference an unguarded blank makes is a
    round trip and an error that names nothing.
    """
    async with Client(mcp_root_server) as client:
        result = await client.call_tool_mcp(
            "prowler_update_mute_rule", {"rule_id": SCAN_ID, "name": ""}
        )

    assert result.isError is True
    assert "name" in result.content[0].text
    assert mock_router.requests == []


async def test_an_omitted_optional_string_is_still_omitted(
    mcp_root_server, mock_api_client, mock_router
):
    """`NonBlankStr | None` must not turn "not provided" into a rejection."""
    mock_router.add(
        "GET",
        f"/api/v1/mute-rules/{SCAN_ID}",
        json={
            "data": jsonapi_resource(
                "mute-rules",
                SCAN_ID,
                {
                    "name": "unchanged",
                    "reason": "already reviewed",
                    "enabled": True,
                    "finding_uids": [],
                },
            )
        },
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool_mcp(
            "prowler_update_mute_rule", {"rule_id": SCAN_ID}
        )

    assert result.isError is False


async def test_every_required_string_argument_is_guarded_against_a_blank(
    mcp_root_server,
):
    """A guard only one tool carries is one the next tool will be written without.

    Declared as `minLength` rather than checked inside each tool, so a client sees
    the constraint in the schema before it calls.
    """
    async with Client(mcp_root_server) as client:
        tools = await client.list_tools()

    unguarded = [
        f"{tool.name}.{name}"
        for tool in tools
        for name, schema in tool.inputSchema.get("properties", {}).items()
        # Plain required strings only. A union such as `dict | str` takes a JSON
        # string, where a blank is a parse failure the classifier already
        # explains, and a blank filter is a filter that matches everything.
        if schema.get("type") == "string"
        and name in tool.inputSchema.get("required", [])
        and schema.get("minLength") != 1
    ]

    assert unguarded == []
