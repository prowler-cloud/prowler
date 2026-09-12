"""Tests for the cloud resources tools.

`list_resources`/`get_resources_overview` switch between the `/latest` and
dated endpoints based on whether a date range was given, and multi-value
filters travel as comma-separated strings once `build_filter_params` has run
-- both are easy to get backwards, so each gets a direct assertion on the
request that was actually made.
"""

import pytest
from fastmcp import Client

from tests.helpers.jsonapi import jsonapi_collection, jsonapi_document, jsonapi_resource

RESOURCES_LATEST = "/api/v1/resources/latest"
RESOURCES = "/api/v1/resources"
RESOURCE = "/api/v1/resources/res1"
METADATA_LATEST = "/api/v1/resources/metadata/latest"
EVENTS = "/api/v1/resources/res1/events"

RESOURCE_ATTRIBUTES = {
    "uid": "arn:aws:s3:::my-bucket",
    "name": "my-bucket",
    "region": "us-east-1",
    "service": "s3",
    "type": "AwsS3Bucket",
    "failed_findings_count": 2,
    "tags": {},
}


async def test_list_resources_defaults_to_the_latest_endpoint_without_dates(
    mcp_root_server, mock_api_client, mock_router
):
    mock_router.add("GET", RESOURCES_LATEST, json=jsonapi_collection([]))

    async with Client(mcp_root_server) as client:
        await client.call_tool("prowler_list_resources", {})

    assert mock_router.paths() == ["GET " + RESOURCES_LATEST]


async def test_list_resources_uses_the_dated_endpoint_when_a_date_range_is_given(
    mcp_root_server, mock_api_client, mock_router
):
    mock_router.add("GET", RESOURCES, json=jsonapi_collection([]))

    async with Client(mcp_root_server) as client:
        await client.call_tool(
            "prowler_list_resources",
            {"date_from": "2025-01-15", "date_to": "2025-01-16"},
        )

    params = mock_router.query_params("GET", RESOURCES)
    assert params["filter[updated_at__gte]"] == "2025-01-15"
    assert params["filter[updated_at__lte]"] == "2025-01-16"


async def test_list_resources_joins_multi_value_filters_with_commas(
    mcp_root_server, mock_api_client, mock_router
):
    mock_router.add("GET", RESOURCES_LATEST, json=jsonapi_collection([]))

    async with Client(mcp_root_server) as client:
        await client.call_tool(
            "prowler_list_resources",
            {"region": ["us-east-1", "eu-west-1"], "service": ["s3", "ec2"]},
        )

    params = mock_router.query_params("GET", RESOURCES_LATEST)
    assert params["filter[region__in]"] == "us-east-1,eu-west-1"
    assert params["filter[service__in]"] == "s3,ec2"


async def test_list_resources_omits_empty_list_filters(
    mcp_root_server, mock_api_client, mock_router
):
    mock_router.add("GET", RESOURCES_LATEST, json=jsonapi_collection([]))

    async with Client(mcp_root_server) as client:
        await client.call_tool("prowler_list_resources", {})

    params = mock_router.query_params("GET", RESOURCES_LATEST)
    assert "filter[region__in]" not in params
    assert "filter[provider_type__in]" not in params


async def test_list_resources_rejects_a_page_size_over_the_maximum(
    mcp_root_server, mock_api_client, mock_router
):
    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception, match="page_size"):
            await client.call_tool("prowler_list_resources", {"page_size": 1001})

    assert mock_router.paths() == []


async def test_get_resource_returns_full_detail(
    mcp_root_server, mock_api_client, mock_router
):
    mock_router.add(
        "GET",
        RESOURCE,
        json=jsonapi_document(
            jsonapi_resource(
                "resources",
                "res1",
                {
                    **RESOURCE_ATTRIBUTES,
                    "metadata": None,
                    "partition": "aws",
                    "inserted_at": "2025-01-01T00:00:00Z",
                    "updated_at": "2025-01-01T00:00:00Z",
                },
            )
        ),
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool("prowler_get_resource", {"resource_id": "res1"})

    assert result.data["uid"] == "arn:aws:s3:::my-bucket"
    assert result.data["partition"] == "aws"


async def test_get_resource_requires_a_non_blank_id(
    mcp_root_server, mock_api_client, mock_router
):
    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception):
            await client.call_tool("prowler_get_resource", {"resource_id": ""})

    assert mock_router.paths() == []


async def test_get_resources_overview_reports_the_total_and_metadata_sections(
    mcp_root_server, mock_api_client, mock_router
):
    mock_router.add(
        "GET",
        METADATA_LATEST,
        json=jsonapi_document(
            jsonapi_resource(
                "resources-metadata",
                "metadata",
                {"services": ["s3"], "regions": ["us-east-1"], "types": []},
            )
        ),
    )
    mock_router.add(
        "GET",
        RESOURCES_LATEST,
        json=jsonapi_document(data=[], meta={"pagination": {"count": 42}}),
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool("prowler_get_resources_overview", {})

    report = result.data["report"]
    assert "**Total Resources**: 42 resources" in report
    assert "## Services" in report
    assert "## Regions" in report
    # `types` was empty, so its section must be omitted entirely.
    assert "## Resource Types" not in report


async def test_get_resources_overview_formats_large_counts_with_thousands_separators(
    mcp_root_server, mock_api_client, mock_router
):
    mock_router.add(
        "GET",
        METADATA_LATEST,
        json=jsonapi_document(
            jsonapi_resource(
                "resources-metadata",
                "metadata",
                {"services": [], "regions": [], "types": []},
            )
        ),
    )
    mock_router.add(
        "GET",
        RESOURCES_LATEST,
        json=jsonapi_document(data=[], meta={"pagination": {"count": 1234567}}),
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool("prowler_get_resources_overview", {})

    assert "1,234,567 resources" in result.data["report"]


async def test_get_resource_events_sends_booleans_as_lowercase_strings(
    mcp_root_server, mock_api_client, mock_router
):
    mock_router.add("GET", EVENTS, json=jsonapi_document(data=[]))

    async with Client(mcp_root_server) as client:
        await client.call_tool(
            "prowler_get_resource_events",
            {"resource_id": "res1", "include_read_events": True},
        )

    params = mock_router.query_params("GET", EVENTS)
    assert params["include_read_events"] == "true"


async def test_get_resource_events_rejects_a_lookback_beyond_ninety_days(
    mcp_root_server, mock_api_client, mock_router
):
    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception):
            await client.call_tool(
                "prowler_get_resource_events",
                {"resource_id": "res1", "lookback_days": 91},
            )

    assert mock_router.paths() == []
