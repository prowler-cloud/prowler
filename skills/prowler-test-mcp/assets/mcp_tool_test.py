# Example: Prowler MCP Server tool test patterns
# Source: mcp_server/tests/prowler_app/tools/test_findings.py

import pytest
from fastmcp import Client

from tests.helpers.jsonapi import jsonapi_collection, jsonapi_error, jsonapi_resource

LATEST = "/api/v1/findings/latest"
HISTORICAL = "/api/v1/findings"

FINDING_ATTRIBUTES = {
    "uid": "prowler-aws-s3_bucket_public_access-123456789012-us-east-1-my-bucket",
    "status": "FAIL",
    "severity": "high",
    "status_extended": "S3 bucket my-bucket is publicly accessible.",
    "delta": "new",
    "muted": False,
    "muted_reason": None,
    "check_metadata": {"checkid": "s3_bucket_public_access"},
}


async def test_tool_returns_a_simplified_payload(
    mcp_root_server, mock_api_client, mock_router
):
    """Drive the tool through the protocol; assert on the structured result.

    This is the default pattern. Going through the in-memory client is what
    resolves the pydantic `Field(default=...)` declarations on the tool's
    parameters -- calling the method directly leaves omitted arguments as raw
    `FieldInfo` objects, which are truthy and build nonsense filters.
    """
    mock_router.add(
        "GET",
        LATEST,
        json=jsonapi_collection(
            [jsonapi_resource("findings", "f1", FINDING_ATTRIBUTES)]
        ),
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool("prowler_search_security_findings", {})

    assert result.data["findings"][0]["check_id"] == "s3_bucket_public_access"


async def test_tool_arguments_become_api_query_parameters(
    mcp_root_server, mock_api_client, mock_router
):
    """Assert on the recorded request, not only the returned payload.

    The request is where filter translation, pagination and field selection live,
    and it is what breaks silently when an API contract shifts.
    """
    mock_router.add("GET", LATEST, json=jsonapi_collection([]))

    async with Client(mcp_root_server) as client:
        await client.call_tool(
            "prowler_search_security_findings", {"severity": ["critical", "high"]}
        )

    params = mock_router.query_params("GET", LATEST)
    assert params["filter[severity__in]"] == "critical,high"  # lists become CSV
    assert params["filter[status__in]"] == "FAIL"  # the tool's default


async def test_tool_picks_the_right_endpoint(
    mcp_root_server, mock_api_client, mock_router
):
    """Assert which endpoint was called when the tool chooses between several.

    A wrong choice here is a performance regression the response body alone would
    never reveal, so `paths()` is the assertion that catches it.
    """
    mock_router.add("GET", HISTORICAL, json=jsonapi_collection([]))

    async with Client(mcp_root_server) as client:
        await client.call_tool(
            "prowler_search_security_findings", {"date_from": "2025-01-15"}
        )

    assert mock_router.paths() == [f"GET {HISTORICAL}"]


async def test_tool_validates_input_before_calling_the_api(
    mcp_root_server, mock_api_client, mock_router
):
    """Local validation must reject before any request goes out."""
    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception, match="Must be between 1 and 1000"):
            await client.call_tool(
                "prowler_search_security_findings", {"page_size": 5000}
            )

    assert mock_router.requests == []


async def test_tool_surfaces_the_api_error_detail(
    mcp_root_server, mock_api_client, mock_router
):
    """Error text reaches the model, so assert on it rather than on the type alone."""
    mock_router.add(
        "GET", f"{HISTORICAL}/nope", status=404, json=jsonapi_error(404, "Not found.")
    )

    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception, match="Not found."):
            await client.call_tool(
                "prowler_get_finding_details", {"finding_id": "nope"}
            )


async def test_polling_tool_waits_for_a_terminal_task_state(
    mock_api_client, mock_router
):
    """Register a route repeatedly to return a sequence; the last entry repeats."""
    from tests.helpers.jsonapi import task_document

    mock_router.add("GET", "/api/v1/tasks/t1", json=task_document("t1", "executing"))
    mock_router.add("GET", "/api/v1/tasks/t1", json=task_document("t1", "completed"))

    result = await mock_api_client.poll_task_until_complete("t1", poll_interval=0)

    assert result["data"]["attributes"]["state"] == "completed"
