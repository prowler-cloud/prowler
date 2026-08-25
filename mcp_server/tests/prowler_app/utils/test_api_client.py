"""Tests for the shared Prowler API client.

Reference for later branches: drive the client through ``mock_api_client`` +
``mock_router`` and assert on the recorded request, so the real URL joining,
query encoding and header assembly stay covered.
"""

import httpx
import pytest

from prowler_mcp_server.prowler_app.utils.api_client import (
    ProwlerAPIError,
    ProwlerAPIUnreachable,
)
from tests.helpers.jsonapi import jsonapi_collection, jsonapi_error, jsonapi_resource
from tests.helpers.tokens import FAKE_API_KEY


async def test_get_sends_an_authenticated_jsonapi_request(mock_api_client, mock_router):
    """A GET carries the API key and the JSON:API content negotiation headers."""
    mock_router.add(
        "GET",
        "/api/v1/findings",
        json=jsonapi_collection(
            [jsonapi_resource("findings", "f1", {"severity": "high"})]
        ),
    )

    await mock_api_client.get("/findings")

    request = mock_router.request_for("GET", "/api/v1/findings")
    assert request.headers["authorization"] == f"Api-Key {FAKE_API_KEY}"
    assert request.headers["accept"] == "application/vnd.api+json"
    assert request.headers["user-agent"].startswith("prowler-mcp-server/")


async def test_get_forwards_query_parameters(mock_api_client, mock_router):
    """Filter parameters reach the wire with their JSON:API bracket syntax intact."""
    mock_router.add("GET", "/api/v1/findings", json=jsonapi_collection([]))

    await mock_api_client.get(
        "/findings", params={"page[size]": 5, "filter[severity__in]": "critical"}
    )

    assert mock_router.query_params("GET", "/api/v1/findings") == {
        "page[size]": "5",
        "filter[severity__in]": "critical",
    }


async def test_error_response_surfaces_the_jsonapi_detail(mock_api_client, mock_router):
    """A failed request carries the API's own `errors[].detail`."""
    mock_router.add(
        "GET",
        "/api/v1/findings/nope",
        status=404,
        json=jsonapi_error(404, "Not found."),
    )

    with pytest.raises(
        ProwlerAPIError, match=r"API request failed: 404 - Not found\."
    ) as raised:
        await mock_api_client.get("/findings/nope")

    assert raised.value.status_code == 404
    assert raised.value.detail == "Not found."


async def test_a_body_that_is_not_jsonapi_is_never_repeated(
    mock_api_client, mock_router
):
    """A body that is not JSON:API leaves `detail` unset, so nothing is relayed."""
    mock_router.add(
        "GET",
        "/api/v1/findings",
        status=502,
        text="<html><body>Traceback: secret-internal-host:5432</body></html>",
    )

    with pytest.raises(ProwlerAPIError) as raised:
        await mock_api_client.get("/findings")

    assert raised.value.detail is None
    assert "secret-internal-host" not in str(raised.value)


async def test_a_request_that_got_no_answer_is_not_an_api_error(
    mock_api_client, mock_router
):
    """`ProwlerAPIError` means the API answered, so a timeout must not use it."""

    def timed_out(request):
        raise httpx.ReadTimeout("Timed out reading the response", request=request)

    mock_router.add_handler("GET", "/api/v1/findings", timed_out)

    with pytest.raises(ProwlerAPIUnreachable) as raised:
        await mock_api_client.get("/findings")

    assert not isinstance(raised.value, ProwlerAPIError)


def test_build_filter_params_normalises_types_for_the_api(mock_api_client):
    """Booleans become lowercase strings, sequences become CSV, `None` is dropped."""
    result = mock_api_client.build_filter_params(
        {
            "filter[muted]": True,
            "filter[severity__in]": ["high", "critical"],
            "filter[status]": None,
            "page[size]": 50,
        }
    )

    assert result == {
        "filter[muted]": "true",
        "filter[severity__in]": "high,critical",
        "page[size]": 50,
    }


def test_the_api_client_is_a_singleton(isolated_api_client):
    """Every tool must share one client so the HTTP connection pool is shared."""
    assert isolated_api_client() is isolated_api_client()
