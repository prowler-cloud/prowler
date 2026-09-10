# Example: Prowler MCP Server model test patterns
# Source: mcp_server/tests/prowler_app/models/test_findings.py

from prowler_mcp_server.prowler_app.models.findings import (
    DetailedFinding,
    FindingsListResponse,
    SimplifiedFinding,
)

from tests.helpers.jsonapi import (
    jsonapi_collection,
    jsonapi_relationship_many,
    jsonapi_relationship_one,
    jsonapi_resource,
)

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

DETAILED_ATTRIBUTES = {
    **FINDING_ATTRIBUTES,
    "inserted_at": "2025-01-15T10:00:00Z",
    "updated_at": "2025-01-15T10:00:00Z",
}


def test_nested_attributes_are_flattened_onto_the_model():
    """Assert on the fields the model derives, not the ones it copies verbatim."""
    finding = SimplifiedFinding.from_api_response(
        jsonapi_resource("findings", "f1", FINDING_ATTRIBUTES)
    )

    assert finding.check_id == "s3_bucket_public_access"


def test_empty_fields_are_dropped_from_the_serialized_payload():
    """Assert on `model_dump()` too -- MinimalSerializerMixin drops empty values.

    A model may override that for fields whose empty form carries meaning, and
    that override is exactly the kind of thing a refactor breaks silently.
    """
    finding = SimplifiedFinding.from_api_response(
        jsonapi_resource("findings", "f1", FINDING_ATTRIBUTES)
    )

    assert "muted_reason" not in finding.model_dump()


def test_both_relationship_shapes_are_parsed():
    """To-one reduces to a single id, to-many to a list of ids."""
    resource = jsonapi_resource(
        "findings",
        "f1",
        attributes=DETAILED_ATTRIBUTES,
        relationships={
            "scan": jsonapi_relationship_one("scans", "s1"),
            "resources": jsonapi_relationship_many("resources", "r1", "r2"),
        },
    )

    finding = DetailedFinding.from_api_response(resource)

    assert finding.scan_id == "s1"
    assert finding.resource_ids == ["r1", "r2"]


def test_missing_relationships_are_tolerated():
    """Omit `relationships=` entirely to express absence.

    Pass an empty `jsonapi_relationship_many(...)` instead to express "present and
    empty" -- some models must distinguish the two.
    """
    finding = DetailedFinding.from_api_response(
        jsonapi_resource("findings", "f1", DETAILED_ATTRIBUTES)
    )

    assert finding.scan_id is None
    assert finding.resource_ids == []


def test_list_response_carries_pagination_metadata():
    """`jsonapi_collection` emits meta.pagination exactly as *ListResponse reads it."""
    response = jsonapi_collection(
        [jsonapi_resource("findings", "f1", FINDING_ATTRIBUTES)],
        page=2,
        pages=7,
        count=312,
    )

    result = FindingsListResponse.from_api_response(response)

    assert (result.current_page, result.total_num_pages, result.total_num_finding) == (
        2,
        7,
        312,
    )
