"""Tests for the shared failure classifier.

Two properties are pinned here: a failed tool call answers with ``isError: true``
rather than a result object the client reads as a success, and the only text that
reaches a model is text this server produced.
"""

import json

import pytest
from fastmcp import Client
from pydantic import BaseModel, ValidationError

from prowler_mcp_server.lib.errors import InvalidArgument, _describe_failure
from prowler_mcp_server.prowler_app.utils.api_client import (
    ProwlerAPIError,
    ProwlerAPIUnreachable,
)
from tests.helpers.jsonapi import jsonapi_error

LATEST = "/api/v1/findings/latest"


# ------------------------------------------------------------ classification


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (401, "missing, malformed or expired"),
        (403, "prowler_get_current_user"),
        (429, "rate limiting"),
        (503, "failed on Prowler's side"),
    ],
    ids=["unauthorized", "forbidden", "rate-limited", "unavailable"],
)
def test_the_failures_every_authenticated_tool_shares_get_one_message(status, expected):
    """These four mean the same thing whichever tool hit them."""
    message = _describe_failure(ProwlerAPIError("failed", status))

    assert expected in message


def test_a_rejection_relays_the_apis_own_reason():
    """`errors[].detail` is written by Prowler for a caller, so it is ours to relay."""
    message = _describe_failure(
        ProwlerAPIError("failed", 400, detail="scan_id is not a valid UUID.")
    )

    assert "scan_id is not a valid UUID." in message


def test_a_rejection_with_no_trustworthy_reason_says_so_instead_of_guessing():
    """A body that was not JSON:API leaves `detail` unset, and it stays unrelayed."""
    message = _describe_failure(ProwlerAPIError("failed", 400))

    assert "gave no reason" in message


def test_a_request_that_got_no_answer_says_the_outcome_is_unknown():
    """An unanswered write may well have landed, so repeating it can duplicate it."""
    message = _describe_failure(ProwlerAPIUnreachable("POST /providers got no answer"))

    assert "could not be reached" in message
    assert "unknown" in message


def test_an_argument_this_server_rejected_is_repeated_verbatim():
    """`InvalidArgument` exists to mark a message as one we wrote."""
    message = _describe_failure(
        InvalidArgument("page_size must be between 1 and 1000.")
    )

    assert message == "page_size must be between 1 and 1000."


def test_a_pydantic_rejection_names_the_field_without_echoing_the_value():
    """Pydantic quotes `input_value` back, and these tools take credentials."""

    class Credentials(BaseModel):
        api_token: int

    with pytest.raises(ValidationError) as raised:
        Credentials(api_token="hunter2-the-real-secret")

    message = _describe_failure(raised.value)

    assert "api_token" in message
    assert "hunter2-the-real-secret" not in message


def test_unparseable_json_is_reported_without_quoting_the_input():
    """`JSONDecodeError` is a ValueError whose message quotes what it was given."""
    with pytest.raises(json.JSONDecodeError) as raised:
        json.loads('{"api_token": "hunter2-the-real-secret"')

    message = _describe_failure(raised.value)

    assert "could not be parsed" in message
    assert "hunter2" not in message


def test_an_unrecognised_failure_is_left_masked():
    """Saying nothing is the safe default; the alternative is relaying anything."""
    assert (
        _describe_failure(RuntimeError("connection pool exhausted at 10.0.0.4:5432"))
        is None
    )


# --------------------------------------------------------- through the server


async def test_a_failing_tool_answers_with_is_error_not_a_result(
    mcp_root_server, mock_api_client, mock_router
):
    """An error dict would arrive as `isError: false` and read as a success."""
    mock_router.add("GET", LATEST, status=403, json=jsonapi_error(403, "Denied."))

    async with Client(mcp_root_server) as client:
        result = await client.call_tool_mcp("prowler_search_security_findings", {})

    assert result.isError is True
    assert result.structuredContent is None
    assert "prowler_get_current_user" in result.content[0].text


async def test_an_upstream_body_never_reaches_the_agent(
    mcp_root_server, mock_api_client, mock_router
):
    """A body this server did not write is logged and replaced, never relayed."""
    mock_router.add(
        "GET",
        LATEST,
        status=500,
        text="Traceback: psycopg2 could not connect to internal-db:5432",
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool_mcp("prowler_search_security_findings", {})

    assert result.isError is True
    assert "internal-db" not in result.content[0].text
    assert "failed on Prowler's side" in result.content[0].text


async def test_a_bad_argument_is_rejected_before_any_request_goes_out(
    mcp_root_server, mock_api_client, mock_router
):
    """Local validation saves a round trip, and its message is safe to repeat."""
    async with Client(mcp_root_server) as client:
        result = await client.call_tool_mcp(
            "prowler_search_security_findings", {"page_size": 5000}
        )

    assert result.isError is True
    assert "Must be between 1 and 1000" in result.content[0].text
    assert mock_router.requests == []
