"""Tests for the scans tools.

Both write tools here used to answer a failure with a result object that the
protocol, the client and the model all read as a success, and both are calls
whose outcome an agent acts on:

* ``prowler_trigger_scan`` starts work. Anything that reads as "nothing
  happened" invites a second scan of the same provider.
* ``prowler_schedule_daily_scan`` was deciding whether the schedule existed by
  reading the state of a different thing entirely -- the first scan Prowler
  starts alongside it -- so a schedule that had just been created could be
  reported as a failure. Retrying that can only hit the 409 the API raises for a
  provider that already has one.

Tools are driven through an in-memory MCP client so FastMCP resolves the
pydantic ``Field`` defaults and a raised failure arrives the way a client sees
it.
"""

import pytest
from fastmcp import Client

from tests.helpers.http import MockRouter
from tests.helpers.jsonapi import (
    jsonapi_document,
    jsonapi_error,
    jsonapi_resource,
)

SCANS = "/api/v1/scans"
SCAN = f"{SCANS}/s1"
DAILY = "/api/v1/schedules/daily"

SCAN_ATTRIBUTES = {
    "name": "Nightly",
    "trigger": "manual",
    "state": "executing",
    "progress": 40,
}


def stub_scan_creation(mock_router: MockRouter, scan_id: str = "s1") -> MockRouter:
    """Serve the creation as Prowler does: a task carrying the new scan's ID."""
    return mock_router.add(
        "POST",
        SCANS,
        json=jsonapi_document(
            jsonapi_resource("tasks", "t1", {"task_args": {"scan_id": scan_id}})
        ),
    )


# ------------------------------------------------------------- trigger_scan


async def test_a_refused_scan_is_an_error_not_a_failed_looking_result(
    mcp_root_server, mock_api_client, mock_router
):
    """A rejection has to leave the tool as an error.

    Returned as a result it arrives with ``isError: false``, and a model reading
    a successful tool call has no reason to doubt that a scan is now running.
    """
    mock_router.add(
        "POST", SCANS, status=403, json=jsonapi_error(403, "Insufficient permissions.")
    )

    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception, match="not allowed to do this"):
            await client.call_tool("prowler_trigger_scan", {"provider_id": "p1"})


async def test_a_scan_with_no_id_back_warns_before_a_blind_retry(
    mcp_root_server, mock_api_client, mock_router
):
    """Prowler accepted it, so a second call could start a duplicate scan.

    The message names the provider because that is what makes the suggested
    check actionable without another lookup.
    """
    mock_router.add("POST", SCANS, json={"data": {"attributes": {"task_args": {}}}})

    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception, match="did not return its ID"):
            await client.call_tool("prowler_trigger_scan", {"provider_id": "p1"})

    assert mock_router.paths() == [f"POST {SCANS}"]


async def test_a_scan_whose_read_back_fails_still_hands_over_the_id(
    mcp_root_server, mock_api_client, mock_router
):
    """The scan is running; only reading it back went wrong.

    Reporting the read failure alone would read as "the scan was not created"
    and invite a duplicate, so the error carries the ID to monitor instead.
    """
    stub_scan_creation(mock_router)
    mock_router.add("GET", SCAN, status=500, json=jsonapi_error(500, "Server error."))

    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception, match="Scan s1 was created"):
            await client.call_tool("prowler_trigger_scan", {"provider_id": "p1"})


async def test_a_created_scan_comes_back_with_its_details(
    mcp_root_server, mock_api_client, mock_router
):
    """The success path still reports the scan, which is what gets monitored."""
    stub_scan_creation(mock_router)
    mock_router.add(
        "GET",
        SCAN,
        json=jsonapi_document(jsonapi_resource("scans", "s1", SCAN_ATTRIBUTES)),
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool("prowler_trigger_scan", {"provider_id": "p1"})

    assert result.data["scan"]["id"] == "s1"
    # No status flag: a scan that was not created is raised, so "success" could
    # only ever be the one value and says nothing a reader can act on.
    assert "status" not in result.data


# ------------------------------------------------------ schedule_daily_scan


@pytest.mark.parametrize("first_run_state", ["available", "scheduled", "executing"])
async def test_a_schedule_is_reported_created_whatever_the_first_run_does(
    mcp_root_server, mock_api_client, mock_router, first_run_state
):
    """The task in the answer is the first scan run, not the schedule.

    Prowler commits the recurring schedule inside the request that serves this
    call, so an answer at all means it exists. Reading that task's state as the
    outcome of the scheduling reported a schedule that had just been created as
    a failure.
    """
    mock_router.add(
        "POST",
        DAILY,
        json=jsonapi_document(
            jsonapi_resource("tasks", "t1", {"state": first_run_state})
        ),
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_schedule_daily_scan", {"provider_id": "p1"}
        )

    assert result.data["first_run_state"] == first_run_state
    assert "every 24 hours" in result.data["message"]
    assert "scheduled" not in result.data


async def test_a_failed_first_run_leaves_the_schedule_standing(
    mcp_root_server, mock_api_client, mock_router
):
    """Worth saying, but it is not the schedule that failed.

    The gap it leaves is real -- no findings until tomorrow -- so the message
    points at the manual scan that fills it rather than at the scheduling.
    """
    mock_router.add(
        "POST",
        DAILY,
        json=jsonapi_document(jsonapi_resource("tasks", "t1", {"state": "failed"})),
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_schedule_daily_scan", {"provider_id": "p1"}
        )

    assert result.data["first_run_state"] == "failed"
    assert "schedule is unaffected" in result.data["message"]
    assert "prowler_trigger_scan" in result.data["message"]


async def test_an_existing_schedule_is_relayed_as_the_api_explains_it(
    mcp_root_server, mock_api_client, mock_router
):
    """The 409 already says the useful thing, so the classifier relays it."""
    mock_router.add(
        "POST",
        DAILY,
        status=409,
        json=jsonapi_error(409, "There is already a scheduled scan for this provider."),
    )

    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception, match="already a scheduled scan"):
            await client.call_tool("prowler_schedule_daily_scan", {"provider_id": "p1"})
