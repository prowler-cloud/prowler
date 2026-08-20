"""Tests for the sentence a failure is described with.

These assert on the *text* a model reads, because that text is the whole contract: a
`ToolError` carries nothing else. What matters is that the API's own words survive
intact, and that a write whose outcome nobody can report says so.

How that sentence reaches a client -- and that no tool can escape it -- is
`test_server.py`.
"""

import httpx
import pytest

from prowler_mcp_server.lib.errors import (
    ApiErrorDetail,
    ProwlerAPIError,
    ProwlerAuthError,
    ProwlerHubError,
    ProwlerTaskError,
    parse_jsonapi_errors,
    render_tool_error,
)

MAY_HAVE_LANDED = "It may have been carried out anyway"


# --------------------------------------------------------------------------- parsing


def test_every_error_of_the_document_is_preserved():
    """A rejected write names one error per invalid field; all of them matter."""
    errors = parse_jsonapi_errors(
        {
            "errors": [
                {"status": "400", "detail": "This field may not be blank."},
                {"status": "400", "detail": "Enter a valid URL."},
            ]
        }
    )

    assert [error.detail for error in errors] == [
        "This field may not be blank.",
        "Enter a valid URL.",
    ]


def test_a_query_parameter_error_is_not_dressed_up_as_a_body_path():
    """`source.parameter` and `source.pointer` are different places, per JSON:API.

    The API sends a parameter for a bad query string (`api/v1/views.py` answers
    `page[size]` and `lookback_days` that way) and a pointer for a bad body field.
    Rendering a parameter bare would read as though `page[size]` were a path into the
    document, which is somewhere the caller never put it.
    """
    (error,) = parse_jsonapi_errors(
        {
            "errors": [
                {
                    "detail": "invalid parameter 'page[size]'",
                    "source": {"parameter": "page[size]"},
                }
            ]
        }
    )

    assert error.parameter == "page[size]"
    assert error.pointer is None
    assert error.render() == "invalid parameter 'page[size]' (parameter page[size])"


def test_the_field_an_error_points_at_is_kept():
    """`source.pointer` is what turns "invalid" into "this field is invalid"."""
    (error,) = parse_jsonapi_errors(
        {
            "errors": [
                {
                    "detail": "This field may not be blank.",
                    "source": {"pointer": "/data/attributes/name"},
                }
            ]
        }
    )

    assert error.render() == ("This field may not be blank. (/data/attributes/name)")


def test_an_error_with_only_a_title_still_says_something():
    """`detail` is the useful field, but the API does not always send one."""
    assert ApiErrorDetail(title="Not Found").render() == "Not Found"


@pytest.mark.parametrize(
    "payload",
    [None, "not a document", {}, {"errors": "not a list"}, {"errors": [None]}],
    ids=["none", "text", "empty", "errors-not-a-list", "member-not-a-dict"],
)
def test_a_body_that_is_not_an_error_document_is_tolerated(payload):
    """Parsing runs while handling a failure; it must not become the failure."""
    assert parse_jsonapi_errors(payload) == ()


def test_an_error_with_nothing_in_it_renders_empty():
    """Rendered to nothing rather than to punctuation, so composition can skip it."""
    assert ApiErrorDetail().render() == ""


# --------------------------------------------------------------------- api failures


def test_a_failed_read_names_the_call_and_the_reason():
    message = render_tool_error(
        ProwlerAPIError(
            "API request failed: 404 - Not found.",
            404,
            method="GET",
            path="/findings/nope",
            errors=parse_jsonapi_errors(
                {"errors": [{"detail": "No Finding matches the given query."}]}
            ),
        )
    )

    assert message == (
        "GET /findings/nope failed with HTTP 404. No Finding matches the given query."
    )


def test_every_error_of_a_rejected_write_reaches_the_client():
    """The API rejects a write with one error per invalid field, and all of them help."""
    message = render_tool_error(
        ProwlerAPIError(
            "API request failed: 400 - blank",
            400,
            method="POST",
            path="/integrations",
            errors=parse_jsonapi_errors(
                {
                    "errors": [
                        {
                            "detail": "This field may not be blank.",
                            "source": {"pointer": "/data/attributes/bucket_name"},
                        },
                        {"detail": "Enter a valid URL."},
                    ]
                }
            ),
        )
    )

    assert message == (
        "POST /integrations failed with HTTP 400. "
        "This field may not be blank. (/data/attributes/bucket_name); "
        "Enter a valid URL."
    )


def test_a_rejected_write_gets_no_warning():
    """A 4xx changed nothing, so there is nothing to warn about."""
    message = render_tool_error(
        ProwlerAPIError("boom", 400, method="POST", path="/scans")
    )

    assert MAY_HAVE_LANDED not in message


def test_a_write_that_hit_a_server_error_warns_it_may_have_landed():
    """The API validates and queues before answering, so a 500 may have gone through."""
    message = render_tool_error(
        ProwlerAPIError("boom", 500, method="DELETE", path="/integrations/i1")
    )

    assert message.startswith("DELETE /integrations/i1 failed with HTTP 500.")
    assert MAY_HAVE_LANDED in message


def test_a_failed_read_never_warns():
    """A read cannot have changed anything, whatever went wrong."""
    message = render_tool_error(
        ProwlerAPIError("boom", 500, method="GET", path="/scans")
    )

    assert MAY_HAVE_LANDED not in message


# ------------------------------------------------------------------ no answer at all


def test_a_write_that_got_no_answer_warns_it_may_have_landed():
    """A timeout is the case the warning exists for."""
    request = httpx.Request("POST", "https://api.testing.invalid/api/v1/scans")
    message = render_tool_error(httpx.ReadTimeout("timed out", request=request))

    assert "POST https://api.testing.invalid/api/v1/scans got no answer" in message
    assert "ReadTimeout" in message
    assert MAY_HAVE_LANDED in message


def test_a_read_that_got_no_answer_does_not_warn():
    request = httpx.Request("GET", "https://api.testing.invalid/api/v1/findings")
    message = render_tool_error(httpx.ReadTimeout("timed out", request=request))

    assert MAY_HAVE_LANDED not in message


def test_a_dropped_connection_names_what_went_wrong():
    request = httpx.Request("POST", "https://api.testing.invalid/api/v1/scans")
    message = render_tool_error(httpx.ConnectError("connection reset", request=request))

    assert "ConnectError: connection reset" in message


def test_an_unfinished_task_warns_it_may_have_landed():
    """The API already accepted the work, so the outcome is open, not refused."""
    message = render_tool_error(
        ProwlerTaskError(
            "Task t1 polling timed out after 60 seconds.", task_id="t1", state="timeout"
        )
    )

    assert message.startswith("Task t1 polling timed out after 60 seconds.")
    assert MAY_HAVE_LANDED in message


# -------------------------------------------------------------- refusals before send


def test_a_stray_value_error_is_reported_as_a_bug():
    """The distinction the previous passthrough branch could not make.

    A model factory rejecting an API payload, or an `int()` on something that is not a
    number, is not the caller's mistake. Describing it like a validation message sends
    an agent off rewriting arguments that were never the problem.
    """
    message = render_tool_error(
        ValueError("Missing pagination metadata in API response")
    )

    assert "unexpected ValueError" in message
    assert "bug in the server" in message


def test_an_authentication_failure_says_so():
    """A `ValueError` subclass, so it must be recognised before the generic branch."""
    assert render_tool_error(ProwlerAuthError("Token has expired")) == (
        "Prowler authentication failed: Token has expired"
    )


# ---------------------------------------------------------------------- other hosts


def test_a_hub_failure_reads_like_an_api_failure():
    """Same sentence as the Prowler API, with the service named.

    The Hub can be down while the API is fine, so which one failed is worth the two
    extra words -- but the shape must not differ, or the two look like two contracts.
    """
    message = render_tool_error(
        ProwlerHubError(
            "hub failed",
            status_code=404,
            path="/check/test",
            body='{"error": "Not found"}',
        )
    )

    assert message == "Prowler Hub GET /check/test failed with HTTP 404. Not found"


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ('{"error": "Not found"}', "Not found"),
        ('{"message": "Bad gateway"}', "Bad gateway"),
        ('{"detail": "Rate limited"}', "Rate limited"),
        ("Service Unavailable", "Service Unavailable"),
        ('{"unexpected": "shape"}', '{"unexpected": "shape"}'),
    ],
    ids=["error", "message", "detail", "plain-text", "unknown-json"],
)
def test_an_upstream_message_is_pulled_out_of_whatever_shape_it_came_in(body, expected):
    """Hosts that are not the Prowler API each have their own error shape.

    Relaying the raw body puts JSON braces, or a whole HTML page, in front of the model.
    """
    message = render_tool_error(
        ProwlerHubError("hub failed", status_code=500, path="/checks", body=body)
    )

    assert message.endswith(expected)


def test_an_upstream_body_is_truncated():
    """An HTML error page must not flood the model's context."""
    message = render_tool_error(
        ProwlerHubError("hub failed", status_code=500, path="/checks", body="x" * 2000)
    )

    assert "x" * 500 in message
    assert "x" * 501 not in message


# --------------------------------------------------------------------- server bugs


def test_a_bug_in_this_server_is_reported_as_a_bug():
    """Named as ours, so the caller stops trying to fix it by changing arguments."""
    message = render_tool_error(KeyError("attributes"))

    assert "unexpected KeyError" in message
    assert "bug in the server" in message
