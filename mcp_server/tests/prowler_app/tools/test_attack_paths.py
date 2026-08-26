"""Tests for the Attack Paths tools.

An Attack Paths scan is a separate resource from a regular scan, with IDs of its
own, and Prowler only creates one for an AWS provider. So the 404 these tools get
is almost always a regular scan ID passed where an Attack Paths one belongs --
and Prowler's own reason for it, a bare "Not found.", names neither the resource
it looked in nor the tool that returns the right ID.
"""

import pytest
from fastmcp import Client

from tests.helpers.jsonapi import jsonapi_collection, jsonapi_resource

QUERIES = "/api/v1/attack-paths-scans/s1/queries"


async def test_an_id_that_is_not_an_attack_paths_scan_says_which_tool_returns_one(
    mcp_root_server, mock_api_client, mock_router
):
    """Relaying "Not found." sends an agent to re-check an ID it cannot fix.

    The reply has to name the confusion it stands for: regular scan IDs do not
    resolve here, and only AWS providers have an Attack Paths scan at all.
    """
    mock_router.add(
        "GET",
        QUERIES,
        status=404,
        json={"errors": [{"status": "404", "detail": "Not found."}]},
    )

    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception, match="different resource from regular scans"):
            await client.call_tool(
                "prowler_list_attack_paths_queries", {"scan_id": "s1"}
            )


async def test_the_answer_names_the_tool_that_returns_a_usable_id(
    mcp_root_server, mock_api_client, mock_router
):
    """An explanation with no next step leaves the agent guessing IDs."""
    mock_router.add(
        "GET",
        QUERIES,
        status=404,
        json={"errors": [{"status": "404", "detail": "Not found."}]},
    )

    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception, match="prowler_list_attack_paths_scans"):
            await client.call_tool(
                "prowler_list_attack_paths_queries", {"scan_id": "s1"}
            )


async def test_a_failure_that_is_not_a_404_keeps_the_shared_message(
    mcp_root_server, mock_api_client, mock_router
):
    """Only the 404 means a bad ID. A 403 is a permission the ID cannot fix."""
    mock_router.add(
        "GET",
        QUERIES,
        status=403,
        json={"errors": [{"status": "403", "detail": "Denied."}]},
    )

    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception, match="prowler_get_current_user"):
            await client.call_tool(
                "prowler_list_attack_paths_queries", {"scan_id": "s1"}
            )


async def test_queries_come_back_as_a_list(
    mcp_root_server, mock_api_client, mock_router
):
    """The success path is unchanged."""
    mock_router.add(
        "GET",
        QUERIES,
        json=jsonapi_collection(
            [
                jsonapi_resource(
                    "attack-paths-queries",
                    "aws-ec2-instances-internet-exposed",
                    {
                        "name": "Internet exposed EC2",
                        "description": "Find internet-exposed EC2 instances",
                        "provider": "aws",
                        "parameters": [],
                    },
                )
            ]
        ),
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_list_attack_paths_queries", {"scan_id": "s1"}
        )

    assert result.data[0]["id"] == "aws-ec2-instances-internet-exposed"


# ------------------------------------------------------------- running a query

RUN = "/api/v1/attack-paths-scans/s1/queries/run"
SCHEMA = "/api/v1/attack-paths-scans/s1/schema"

EMPTY_RESULT = {
    "data": {
        "type": "attack-paths-query-results",
        "id": "s1",
        "attributes": {"nodes": [], "relationships": []},
    }
}


def _run_args(query_id: str = "aws-ec2-instances-internet-exposed") -> dict[str, str]:
    """Arguments for a query run against the mocked scan."""
    return {"scan_id": "s1", "query_id": query_id}


async def test_a_query_that_matched_nothing_is_an_answer_not_a_failure(
    mcp_root_server, mock_api_client, mock_router
):
    """Prowler answers a query that matched nothing with 404 and the result body.

    Raising on the status called a clean account a failed call and sent the agent
    off to re-check arguments that were right.
    """
    mock_router.add("POST", RUN, status=404, json=EMPTY_RESULT)

    async with Client(mcp_root_server) as client:
        result = await client.call_tool_mcp(
            "prowler_run_attack_paths_query", _run_args()
        )

    assert result.isError is False
    assert "matched nothing" in result.structuredContent["message"]


async def test_an_empty_result_does_not_come_back_as_an_empty_object(
    mcp_root_server, mock_api_client, mock_router
):
    """The serializer drops empty lists, so `{}` is all that would be left."""
    mock_router.add("POST", RUN, status=404, json=EMPTY_RESULT)

    async with Client(mcp_root_server) as client:
        result = await client.call_tool("prowler_run_attack_paths_query", _run_args())

    assert result.data != {}


async def test_a_run_against_an_unknown_scan_still_names_the_confusion(
    mcp_root_server, mock_api_client, mock_router
):
    """A 404 with no result body is the ID being wrong, not an empty answer."""
    mock_router.add(
        "POST",
        RUN,
        status=404,
        json={"errors": [{"status": "404", "detail": "Not found."}]},
    )

    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception, match="different resource from regular scans"):
            await client.call_tool("prowler_run_attack_paths_query", _run_args())


async def test_a_scan_whose_graph_records_no_schema_says_so(
    mcp_root_server, mock_api_client, mock_router
):
    """This 404 is about the graph, not the ID, so it must not blame the ID."""
    mock_router.add(
        "GET",
        SCHEMA,
        status=404,
        json={"detail": "No cartography schema metadata found for this provider"},
    )

    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception, match="no Cartography schema recorded"):
            await client.call_tool(
                "prowler_get_attack_paths_cartography_schema", {"scan_id": "s1"}
            )


async def test_a_schema_request_for_an_unknown_scan_names_the_confusion(
    mcp_root_server, mock_api_client, mock_router
):
    """The other 404 here is the ID, and Prowler writes a JSON:API error for it."""
    mock_router.add(
        "GET",
        SCHEMA,
        status=404,
        json={"errors": [{"status": "404", "detail": "Not found."}]},
    )

    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception, match="different resource from regular scans"):
            await client.call_tool(
                "prowler_get_attack_paths_cartography_schema", {"scan_id": "s1"}
            )
