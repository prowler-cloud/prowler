"""Tests for the provider tools.

Two behaviours drive most of the assertions here, and both are about telling a
failure apart from an outcome that is merely not final yet:

* Deleting a provider removes it together with its scans, findings and
  resources, in a background task that routinely outlives the polling window.
  A deletion still running is not a failure, and reporting it as one invites a
  retry of a destructive call that is already in flight.
* ``connect_provider`` runs a connection check, and a check that could not be
  run says nothing about the provider's credentials. Reporting it as ``failed``
  blames an AWS role for an expired Prowler credential and sends the user off to
  fix something that works.

Tools are driven through an in-memory MCP client so FastMCP resolves the
pydantic ``Field`` defaults and a raised failure arrives the way a client sees
it.
"""

import pytest
from fastmcp import Client

from tests.helpers.http import MockRouter
from tests.helpers.jsonapi import (
    jsonapi_collection,
    jsonapi_document,
    jsonapi_error,
    jsonapi_resource,
    task_document,
)

PROVIDERS = "/api/v1/providers"
PROVIDER = f"{PROVIDERS}/p1"
CONNECTION = f"{PROVIDER}/connection"
SECRETS = f"{PROVIDERS}/secrets"
TASK = "/api/v1/tasks/t1"

PROVIDER_ATTRIBUTES = {
    "uid": "123456789012",
    "provider": "aws",
    "alias": "production",
    "connection": {"connected": True},
}


@pytest.fixture
def mock_fast_polling(monkeypatch, api_client):
    """Run the real polling loop, with a timeout a test can afford to wait out.

    The timeout path is the one worth testing here -- it is what used to be
    reported as a failed deletion -- so the loop, its exception and the fallback
    that reads the task afterwards all stay real. Only the 60 seconds go.
    """
    original = type(api_client).poll_task_until_complete

    async def _fast(self, task_id, **_overridden):
        return await original(self, task_id, timeout=0.3, poll_interval=0.05)

    monkeypatch.setattr(type(api_client), "poll_task_until_complete", _fast)


def stub_deletion_start(mock_router: MockRouter) -> MockRouter:
    """Serve the DELETE as Prowler does: a task to poll, not a finished deletion."""
    return mock_router.add(
        "DELETE", PROVIDER, json=jsonapi_document(jsonapi_resource("tasks", "t1", {}))
    )


# --------------------------------------------------------------- deletion


async def test_a_refused_deletion_is_an_error_not_a_result(
    mcp_root_server, mock_api_client, mock_router
):
    """Nothing started, so the classifier owns the message.

    Returned as ``{"deleted": false}`` it arrives with ``isError: false`` and a
    model has no reason to treat it as anything but a completed call.
    """
    mock_router.add(
        "DELETE", PROVIDER, status=403, json=jsonapi_error(403, "Not allowed.")
    )

    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception, match="not allowed to do this"):
            await client.call_tool("prowler_delete_provider", {"provider_id": "p1"})


async def test_a_deletion_with_no_task_back_warns_before_a_blind_retry(
    mcp_root_server, mock_api_client, mock_router
):
    """Prowler accepted it, so the deletion is probably running.

    Without the task ID there is nothing to watch it with, which makes "check
    whether it is gone" the only safe instruction.
    """
    mock_router.add("DELETE", PROVIDER, json={"data": {}})

    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception, match="did not return the ID"):
            await client.call_tool("prowler_delete_provider", {"provider_id": "p1"})

    assert mock_router.paths() == [f"DELETE {PROVIDER}"]


async def test_a_finished_deletion_reports_it_plainly(
    mcp_root_server, mock_api_client, mock_router
):
    """The success path is unchanged: the provider is gone."""
    stub_deletion_start(mock_router)
    mock_router.add("GET", TASK, json=task_document("t1", "completed"))

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_delete_provider", {"provider_id": "p1"}
        )

    assert result.data["status"] == "deleted"


async def test_a_deletion_still_running_is_not_reported_as_a_failure(
    mcp_root_server, mock_api_client, mock_router, mock_fast_polling
):
    """Outliving the polling window is normal for a provider with many findings.

    The task ID goes back so the deletion can be followed, and the message says
    not to send it again -- which is the whole point of not calling this failed.
    """
    stub_deletion_start(mock_router)
    mock_router.add("GET", TASK, json=task_document("t1", "executing"))

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_delete_provider", {"provider_id": "p1"}
        )

    assert result.data["status"] == "in_progress"
    assert result.data["task_id"] == "t1"
    assert "Do not send the deletion again" in result.data["message"]


async def test_a_deletion_task_that_stopped_is_an_error_naming_what_is_left(
    mcp_root_server, mock_api_client, mock_router
):
    """Here the provider really is still there, so this one is a failure.

    A provider is removed together with everything attached to it, so a task
    that stopped halfway can leave part of that gone -- which is why the message
    sends the caller to look rather than asserting the state.
    """
    stub_deletion_start(mock_router)
    mock_router.add("GET", TASK, json=task_document("t1", "failed", error="boom"))

    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception, match="ended as 'failed'"):
            await client.call_tool("prowler_delete_provider", {"provider_id": "p1"})


async def test_a_deletion_task_failure_does_not_relay_the_upstream_text(
    mcp_root_server, mock_api_client, mock_router
):
    """The task's own error is a celery traceback; it stays in the log."""
    stub_deletion_start(mock_router)
    mock_router.add(
        "GET",
        TASK,
        json=task_document("t1", "failed", error="Traceback: secret-internal-detail"),
    )

    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception) as raised:
            await client.call_tool("prowler_delete_provider", {"provider_id": "p1"})

    assert "secret-internal-detail" not in str(raised.value)


async def test_a_deletion_whose_progress_cannot_be_read_still_says_do_not_retry(
    mcp_root_server, mock_api_client, mock_router, mock_fast_polling
):
    """The outcome is unknown, which for a destructive call means: do not repeat.

    Reading the task is what tells "still running" from "stopped", so when that
    read fails too the message drops the claim rather than guessing at one.
    """
    stub_deletion_start(mock_router)
    mock_router.add("GET", TASK, status=503, json=jsonapi_error(503, "Unavailable."))

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_delete_provider", {"provider_id": "p1"}
        )

    assert result.data["status"] == "in_progress"
    assert "could not be read" in result.data["message"]
    assert "Do not send the deletion again" in result.data["message"]
    # The failure that got us here is the classifier's to phrase, so its raw
    # text stays in the log rather than riding along in the message.
    assert "API request failed" not in result.data["message"]


# ------------------------------------------------------- connection check


async def test_a_connection_check_that_cannot_run_is_not_reported_as_failed(
    mcp_root_server, mock_api_client, mock_router
):
    """`not_tested` says nothing about the credentials, and that is the point.

    A 401 here is this server's own credential, not the provider's. Calling it
    `failed` tells the user their AWS role is broken when it is fine.
    """
    # Registered in order and consumed in order: the lookup before the create
    # finds nothing, the one after it finds the provider that was just made.
    mock_router.add("GET", PROVIDERS, json=jsonapi_collection([]))
    mock_router.add(
        "GET",
        PROVIDERS,
        json=jsonapi_collection(
            [jsonapi_resource("providers", "p1", PROVIDER_ATTRIBUTES)]
        ),
    )
    mock_router.add(
        "POST",
        PROVIDERS,
        json=jsonapi_document(jsonapi_resource("providers", "p1", PROVIDER_ATTRIBUTES)),
    )
    mock_router.add(
        "POST", CONNECTION, status=401, json=jsonapi_error(401, "Token expired.")
    )
    mock_router.add(
        "GET",
        PROVIDER,
        json=jsonapi_document(jsonapi_resource("providers", "p1", PROVIDER_ATTRIBUTES)),
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_connect_provider",
            {"provider_uid": "123456789012", "provider_type": "aws"},
        )

    assert result.data["connected"] == "not_tested"
    assert "never tested" in result.data["error"]


async def test_a_secret_lookup_failure_does_not_pass_as_having_no_secret(
    mcp_root_server, mock_api_client, mock_router
):
    """Returning None here would send the write down the create branch.

    A provider holds at most one secret, so creating a second one is refused and
    the caller would be told its credentials were rejected when all that
    actually failed was this read.
    """
    mock_router.add(
        "GET",
        PROVIDERS,
        json=jsonapi_collection(
            [jsonapi_resource("providers", "p1", PROVIDER_ATTRIBUTES)]
        ),
    )
    mock_router.add(
        "GET", SECRETS, status=429, json=jsonapi_error(429, "Too many requests.")
    )

    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception, match="rate limiting"):
            await client.call_tool(
                "prowler_connect_provider",
                {
                    "provider_uid": "123456789012",
                    "provider_type": "aws",
                    "credentials": {
                        "aws_access_key_id": "AKIA",
                        "aws_secret_access_key": "s",
                    },
                },
            )

    assert f"POST {SECRETS}" not in mock_router.paths()
