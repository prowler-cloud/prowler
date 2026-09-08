"""Tests for the finding groups tools.

Two behaviours are easy to invert by accident and get their own tests:
`list_finding_group_resources` defaults to unmuted-only resources *unless*
`include_muted` is set (an explicit `muted` filter always wins), and every
list/detail call switches between the `/latest` and dated endpoints based on
whether a date range was supplied.
"""

import pytest
from fastmcp import Client

from tests.helpers.jsonapi import jsonapi_collection, jsonapi_resource

GROUPS_LATEST = "/api/v1/finding-groups/latest"
GROUPS = "/api/v1/finding-groups"
GROUP_RESOURCES_LATEST = (
    "/api/v1/finding-groups/latest/s3_bucket_public_access/resources"
)

GROUP_ATTRIBUTES = {
    "check_id": "s3_bucket_public_access",
    "severity": "high",
    "status": "FAIL",
    "muted": False,
    "resources_fail": 3,
    "resources_total": 10,
}


async def test_list_finding_groups_defaults_to_the_latest_endpoint(
    mcp_root_server, mock_api_client, mock_router
):
    mock_router.add("GET", GROUPS_LATEST, json=jsonapi_collection([]))

    async with Client(mcp_root_server) as client:
        await client.call_tool("prowler_list_finding_groups", {})

    assert mock_router.paths() == ["GET " + GROUPS_LATEST]


async def test_list_finding_groups_uses_the_dated_endpoint_with_a_date_range(
    mcp_root_server, mock_api_client, mock_router
):
    mock_router.add("GET", GROUPS, json=jsonapi_collection([]))

    async with Client(mcp_root_server) as client:
        await client.call_tool(
            "prowler_list_finding_groups",
            {"date_from": "2025-01-15", "date_to": "2025-01-16"},
        )

    params = mock_router.query_params("GET", GROUPS)
    assert params["filter[inserted_at__gte]"] == "2025-01-15"
    assert params["filter[inserted_at__lte]"] == "2025-01-16"


async def test_list_finding_groups_defaults_status_to_fail_only(
    mcp_root_server, mock_api_client, mock_router
):
    mock_router.add("GET", GROUPS_LATEST, json=jsonapi_collection([]))

    async with Client(mcp_root_server) as client:
        await client.call_tool("prowler_list_finding_groups", {})

    assert (
        mock_router.query_params("GET", GROUPS_LATEST)["filter[status__in]"] == "FAIL"
    )


async def test_list_finding_groups_with_explicit_empty_status_returns_all_statuses(
    mcp_root_server, mock_api_client, mock_router
):
    mock_router.add("GET", GROUPS_LATEST, json=jsonapi_collection([]))

    async with Client(mcp_root_server) as client:
        await client.call_tool("prowler_list_finding_groups", {"status": []})

    assert "filter[status__in]" not in mock_router.query_params("GET", GROUPS_LATEST)


async def test_list_finding_groups_excludes_fully_muted_groups_by_default(
    mcp_root_server, mock_api_client, mock_router
):
    mock_router.add("GET", GROUPS_LATEST, json=jsonapi_collection([]))

    async with Client(mcp_root_server) as client:
        await client.call_tool("prowler_list_finding_groups", {})

    assert (
        mock_router.query_params("GET", GROUPS_LATEST)["filter[include_muted]"]
        == "false"
    )


async def test_list_finding_groups_can_request_fully_muted_groups(
    mcp_root_server, mock_api_client, mock_router
):
    mock_router.add("GET", GROUPS_LATEST, json=jsonapi_collection([]))

    async with Client(mcp_root_server) as client:
        await client.call_tool("prowler_list_finding_groups", {"include_muted": True})

    assert (
        mock_router.query_params("GET", GROUPS_LATEST)["filter[include_muted]"]
        == "true"
    )


async def test_list_finding_groups_omits_sort_when_not_provided(
    mcp_root_server, mock_api_client, mock_router
):
    mock_router.add("GET", GROUPS_LATEST, json=jsonapi_collection([]))

    async with Client(mcp_root_server) as client:
        await client.call_tool("prowler_list_finding_groups", {})

    assert "sort" not in mock_router.query_params("GET", GROUPS_LATEST)


async def test_get_finding_group_details_includes_muted_groups_by_default(
    mcp_root_server, mock_api_client, mock_router
):
    mock_router.add(
        "GET",
        GROUPS_LATEST,
        json=jsonapi_collection(
            [
                jsonapi_resource(
                    "finding-groups", "s3_bucket_public_access", GROUP_ATTRIBUTES
                )
            ]
        ),
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_get_finding_group_details",
            {"check_id": "s3_bucket_public_access"},
        )

    params = mock_router.query_params("GET", GROUPS_LATEST)
    assert params["filter[include_muted]"] == "true"
    assert params["filter[check_id]"] == "s3_bucket_public_access"
    assert result.data["check_id"] == "s3_bucket_public_access"


async def test_get_finding_group_details_raises_a_named_error_when_the_check_has_no_group(
    mcp_root_server, mock_api_client, mock_router
):
    mock_router.add("GET", GROUPS_LATEST, json=jsonapi_collection([]))

    async with Client(mcp_root_server) as client:
        with pytest.raises(
            Exception, match="No finding group exists for check 'unknown_check'"
        ):
            await client.call_tool(
                "prowler_get_finding_group_details", {"check_id": "unknown_check"}
            )


async def test_get_finding_group_details_requires_a_non_blank_check_id(
    mcp_root_server, mock_api_client, mock_router
):
    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception):
            await client.call_tool(
                "prowler_get_finding_group_details", {"check_id": ""}
            )

    assert mock_router.paths() == []


async def test_list_finding_group_resources_excludes_muted_resources_by_default(
    mcp_root_server, mock_api_client, mock_router
):
    mock_router.add("GET", GROUP_RESOURCES_LATEST, json=jsonapi_collection([]))

    async with Client(mcp_root_server) as client:
        await client.call_tool(
            "prowler_list_finding_group_resources",
            {"check_id": "s3_bucket_public_access"},
        )

    params = mock_router.query_params("GET", GROUP_RESOURCES_LATEST)
    assert params["filter[muted]"] == "false"


async def test_list_finding_group_resources_include_muted_overrides_the_default_filter(
    mcp_root_server, mock_api_client, mock_router
):
    mock_router.add("GET", GROUP_RESOURCES_LATEST, json=jsonapi_collection([]))

    async with Client(mcp_root_server) as client:
        await client.call_tool(
            "prowler_list_finding_group_resources",
            {"check_id": "s3_bucket_public_access", "include_muted": True},
        )

    params = mock_router.query_params("GET", GROUP_RESOURCES_LATEST)
    assert "filter[muted]" not in params


async def test_list_finding_group_resources_explicit_muted_filter_wins_over_include_muted(
    mcp_root_server, mock_api_client, mock_router
):
    """An explicit `muted=True` is honoured even though `include_muted` was left
    at its default `False` -- the two are independent knobs."""
    mock_router.add("GET", GROUP_RESOURCES_LATEST, json=jsonapi_collection([]))

    async with Client(mcp_root_server) as client:
        await client.call_tool(
            "prowler_list_finding_group_resources",
            {"check_id": "s3_bucket_public_access", "muted": True},
        )

    params = mock_router.query_params("GET", GROUP_RESOURCES_LATEST)
    assert params["filter[muted]"] == "true"


async def test_list_finding_group_resources_url_escapes_the_check_id(
    mcp_root_server, mock_api_client, mock_router
):
    """The source `quote()`s a `/` in the check id to `%2F` so it survives as one
    path segment rather than splitting the URL; httpx decodes `.url.path` back
    to a literal `/`, which is exactly what proves the escaping worked -- an
    unescaped slash would have produced this same decoded path by accident, but
    a request for `check` with a *literal*, unescaped `/` would 404 against the
    API's routing rather than reaching this one static path.
    """
    decoded_path = "/api/v1/finding-groups/latest/check/with/slash/resources"
    mock_router.add("GET", decoded_path, json=jsonapi_collection([]))

    async with Client(mcp_root_server) as client:
        await client.call_tool(
            "prowler_list_finding_group_resources",
            {"check_id": "check/with/slash"},
        )

    assert mock_router.paths() == ["GET " + decoded_path]


async def test_list_finding_group_resources_rejects_a_page_size_below_one(
    mcp_root_server, mock_api_client, mock_router
):
    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception, match="page_size"):
            await client.call_tool(
                "prowler_list_finding_group_resources",
                {"check_id": "s3_bucket_public_access", "page_size": 0},
            )

    assert mock_router.paths() == []
