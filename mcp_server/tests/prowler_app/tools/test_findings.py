"""Tests for the security findings tools.

Reference for later branches. Drive tools through an in-memory MCP client by
default. Tool parameters are declared with pydantic ``Field(default=...)``, and
those defaults are only resolved by FastMCP's tool wrapper -- calling the method
directly leaves an omitted argument as a raw ``FieldInfo`` object, which is
truthy and silently produces nonsense filters. Call the method directly only when
passing every argument explicitly.

Everything here relies on ``mock_api_client`` patching the API client *in place*:
the tool instances captured that exact object when the package was imported, so a
freshly-constructed client would not reach them.
"""

import pytest
from fastmcp import Client

from tests.helpers.jsonapi import (
    jsonapi_collection,
    jsonapi_error,
    jsonapi_relationship_one,
    jsonapi_resource,
)

LATEST = "/api/v1/findings/latest"
HISTORICAL = "/api/v1/findings"

CHECK_METADATA = {
    "checkid": "s3_bucket_public_access",
    "checktitle": "Ensure S3 buckets block public access",
    "description": "Checks whether the bucket blocks public access.",
    "provider": "aws",
    "servicename": "s3",
    "resourcetype": "AwsS3Bucket",
    "risk": "Public buckets expose data to the internet.",
    "additionalurls": [],
    "categories": ["internet-exposed"],
}

FINDING_ATTRIBUTES = {
    "uid": "prowler-aws-s3_bucket_public_access-123456789012-us-east-1-my-bucket",
    "status": "FAIL",
    "severity": "high",
    "status_extended": "S3 bucket my-bucket is publicly accessible.",
    "delta": "new",
    "muted": False,
    "muted_reason": None,
    "check_metadata": CHECK_METADATA,
}


async def test_search_without_dates_queries_the_latest_scan_endpoint(
    mcp_root_server, mock_api_client, mock_router
):
    """With no date range the tool targets `/findings/latest`.

    That endpoint reads only the most recent completed scan, which is far cheaper
    than a historical query -- so picking the wrong one is a performance
    regression the response body alone would not reveal.
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
    assert mock_router.paths() == [f"GET {LATEST}"]


async def test_search_defaults_to_failed_findings_only(
    mcp_root_server, mock_api_client, mock_router
):
    """The default filter is FAIL, so an unqualified search surfaces real issues.

    Also pins the sort order and field selection, which together keep the
    response small and severity-first.
    """
    mock_router.add("GET", LATEST, json=jsonapi_collection([]))

    async with Client(mcp_root_server) as client:
        await client.call_tool("prowler_search_security_findings", {})

    params = mock_router.query_params("GET", LATEST)
    assert params["filter[status__in]"] == "FAIL"
    assert params["sort"] == "severity,-inserted_at"
    assert params["page[size]"] == "50"


async def test_search_with_dates_switches_to_the_historical_endpoint(
    mcp_root_server, mock_api_client, mock_router
):
    """A date range moves the query to `/findings` with an inserted_at window.

    Supplying only `date_from` auto-completes the other boundary, so the caller
    cannot accidentally request an unbounded historical scan.
    """
    mock_router.add("GET", HISTORICAL, json=jsonapi_collection([]))

    async with Client(mcp_root_server) as client:
        await client.call_tool(
            "prowler_search_security_findings", {"date_from": "2025-01-15"}
        )

    params = mock_router.query_params("GET", HISTORICAL)
    assert params["filter[inserted_at__gte]"] == "2025-01-15"
    assert params["filter[inserted_at__lte]"] == "2025-01-16"


async def test_search_rejects_a_date_range_wider_than_the_api_allows(
    mcp_root_server, mock_api_client, mock_router
):
    """The API caps historical queries at two days; reject before the round trip."""
    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception, match="Date range cannot exceed 2 days"):
            await client.call_tool(
                "prowler_search_security_findings",
                {"date_from": "2025-01-01", "date_to": "2025-01-10"},
            )

    assert mock_router.requests == []


async def test_search_encodes_list_filters_as_comma_separated_values(
    mcp_root_server, mock_api_client, mock_router
):
    """Multi-value filters reach the API as CSV, not as repeated query keys."""
    mock_router.add("GET", LATEST, json=jsonapi_collection([]))

    async with Client(mcp_root_server) as client:
        await client.call_tool(
            "prowler_search_security_findings",
            {"severity": ["critical", "high"], "service": ["s3", "ec2"]},
        )

    params = mock_router.query_params("GET", LATEST)
    assert params["filter[severity__in]"] == "critical,high"
    assert params["filter[service__in]"] == "s3,ec2"


@pytest.mark.parametrize(
    ("argument", "value", "expected_key", "expected_value"),
    [
        ("provider_type", ["aws", "gcp"], "filter[provider_type__in]", "aws,gcp"),
        ("provider_alias", "prod", "filter[provider_alias__icontains]", "prod"),
        ("region", ["us-east-1"], "filter[region__in]", "us-east-1"),
        ("resource_type", ["AwsS3Bucket"], "filter[resource_type__in]", "AwsS3Bucket"),
        (
            "check_id",
            ["s3_bucket_public_access"],
            "filter[check_id__in]",
            "s3_bucket_public_access",
        ),
        ("delta", ["new"], "filter[delta__in]", "new"),
        ("search", "bucket", "filter[search]", "bucket"),
    ],
)
async def test_search_maps_each_argument_onto_its_api_filter(
    mcp_root_server,
    mock_api_client,
    mock_router,
    argument,
    value,
    expected_key,
    expected_value,
):
    """Every search argument maps to a specific API filter key.

    A mistyped filter key is not an error the API reports -- it is simply ignored,
    so the tool returns unfiltered results while appearing to work. Pinning the
    exact key per argument is the only thing that catches that.
    """
    mock_router.add("GET", LATEST, json=jsonapi_collection([]))

    async with Client(mcp_root_server) as client:
        await client.call_tool("prowler_search_security_findings", {argument: value})

    assert mock_router.query_params("GET", LATEST)[expected_key] == expected_value


async def test_overview_can_be_scoped_to_a_provider(
    mcp_root_server, mock_api_client, mock_router
):
    """The aggregate report accepts the same provider filter as the search tool."""
    mock_router.add(
        "GET",
        "/api/v1/overviews/findings",
        json={
            "data": jsonapi_resource(
                "findings-overview",
                "overview",
                dict.fromkeys(
                    [
                        "total",
                        "fail",
                        "pass",
                        "muted",
                        "new",
                        "changed",
                        "fail_new",
                        "fail_changed",
                        "pass_new",
                        "pass_changed",
                        "muted_new",
                        "muted_changed",
                    ],
                    0,
                ),
            )
        },
    )

    async with Client(mcp_root_server) as client:
        await client.call_tool(
            "prowler_get_findings_overview", {"provider_type": ["aws"]}
        )

    params = mock_router.query_params("GET", "/api/v1/overviews/findings")
    assert params["filter[provider_type__in]"] == "aws"


async def test_search_normalises_a_string_muted_flag_to_a_boolean(
    mcp_root_server, mock_api_client, mock_router
):
    """`muted` accepts a string because some MCP clients send booleans as text.

    It still has to reach the API as a lowercase boolean, otherwise the filter is
    silently ignored and the agent gets muted findings it asked to exclude.
    """
    mock_router.add("GET", LATEST, json=jsonapi_collection([]))

    async with Client(mcp_root_server) as client:
        await client.call_tool("prowler_search_security_findings", {"muted": "true"})

    assert mock_router.query_params("GET", LATEST)["filter[muted]"] == "true"


async def test_search_rejects_an_out_of_range_page_size(
    mcp_root_server, mock_api_client, mock_router
):
    """Page size is validated locally, saving a round trip on an obvious mistake."""
    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception, match="Must be between 1 and 1000"):
            await client.call_tool(
                "prowler_search_security_findings", {"page_size": 5000}
            )

    assert mock_router.requests == []


async def test_get_finding_details_requests_its_relationships(
    mcp_root_server, mock_api_client, mock_router
):
    """Details are only useful with the scan and resources included.

    Dropping the `include` would leave `scan_id` and `resource_ids` empty and the
    agent unable to pivot from a finding to the resource it concerns.
    """
    attributes = {
        **FINDING_ATTRIBUTES,
        "inserted_at": "2025-01-15T10:00:00Z",
        "updated_at": "2025-01-15T10:00:00Z",
    }
    mock_router.add(
        "GET",
        f"{HISTORICAL}/f1",
        json={
            "data": jsonapi_resource(
                "findings",
                "f1",
                attributes,
                relationships={"scan": jsonapi_relationship_one("scans", "s1")},
            )
        },
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_get_finding_details", {"finding_id": "f1"}
        )

    assert result.data["scan_id"] == "s1"
    assert mock_router.query_params("GET", f"{HISTORICAL}/f1")["include"] == (
        "scan,resources"
    )


async def test_get_finding_details_surfaces_the_api_error_detail(
    mcp_root_server, mock_api_client, mock_router
):
    """A missing finding surfaces the API's message rather than an opaque failure."""
    mock_router.add(
        "GET", f"{HISTORICAL}/nope", status=404, json=jsonapi_error(404, "Not found.")
    )

    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception, match="Not found."):
            await client.call_tool(
                "prowler_get_finding_details", {"finding_id": "nope"}
            )


async def test_overview_renders_a_markdown_report_with_percentages(
    mcp_root_server, mock_api_client, mock_router
):
    """The overview returns prose, not a model, so the arithmetic is the contract.

    Percentages are derived here rather than by the API, which makes them the one
    part of this tool that can silently go wrong.
    """
    mock_router.add(
        "GET",
        "/api/v1/overviews/findings",
        json={
            "data": jsonapi_resource(
                "findings-overview",
                "overview",
                {
                    "total": 200,
                    "fail": 50,
                    "pass": 130,
                    "muted": 20,
                    "new": 10,
                    "changed": 4,
                    "fail_new": 6,
                    "fail_changed": 2,
                    "pass_new": 3,
                    "pass_changed": 1,
                    "muted_new": 1,
                    "muted_changed": 1,
                },
            )
        },
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool("prowler_get_findings_overview", {})

    report = result.data["report"]
    assert "**Total Findings**: 200" in report
    assert "**Failed Checks**: 50 (25.0%)" in report
    assert "**Unchanged**: 186" in report
