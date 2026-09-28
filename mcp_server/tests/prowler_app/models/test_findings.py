"""Tests for the security finding models.

Reference for later branches: build the API document with the ``jsonapi``
helpers, run it through ``from_api_response()``, then assert on both the model
and its ``model_dump()``. The dump is what the agent actually receives, and
``MinimalSerializerMixin`` makes the two differ.
"""

from prowler_mcp_server.prowler_app.models.findings import (
    DetailedFinding,
    FindingsListResponse,
    FindingsOverview,
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
    "additionalurls": ["https://docs.aws.amazon.com/s3/"],
    "categories": ["encryption", "internet-exposed"],
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
    "first_seen_at": "2025-01-10T09:00:00Z",
}


def test_simplified_finding_lifts_the_check_id_out_of_the_check_metadata():
    """`check_id` is nested under `check_metadata.checkid` in the API document.

    Flattening it is what lets an agent filter findings by check without being
    handed the whole metadata blob for every row in a list.
    """
    finding = SimplifiedFinding.from_api_response(
        jsonapi_resource("findings", "f1", FINDING_ATTRIBUTES)
    )

    assert finding.check_id == "s3_bucket_public_access"
    assert finding.severity == "high"
    assert finding.status == "FAIL"


def test_empty_finding_fields_are_dropped_from_the_serialized_payload():
    """Empty values are removed to keep the payload small for the model.

    `muted_reason` is None on an unmuted finding; emitting it would spend tokens
    on every row of every list response to say nothing.
    """
    finding = SimplifiedFinding.from_api_response(
        jsonapi_resource("findings", "f1", FINDING_ATTRIBUTES)
    )

    dumped = finding.model_dump()

    assert "muted_reason" not in dumped
    assert dumped["uid"] == FINDING_ATTRIBUTES["uid"]


def test_detailed_finding_parses_both_relationship_shapes():
    """`scan` is a to-one relationship and `resources` is to-many.

    They are read from the same `relationships` object but reduce to a single id
    and a list of ids respectively.
    """
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


def test_detailed_finding_tolerates_missing_relationships():
    """A document without relationships must not raise.

    `get_finding_details` requests `include=scan,resources`, but a finding whose
    scan has been pruned still has to render rather than fail the tool call.
    """
    finding = DetailedFinding.from_api_response(
        jsonapi_resource("findings", "f1", DETAILED_ATTRIBUTES)
    )

    assert finding.scan_id is None
    assert finding.resource_ids == []


def test_detailed_finding_flattens_the_nested_remediation_guidance():
    """Remediation is the payload an agent needs to actually fix the finding.

    The API nests it under `remediation.code.*` and `remediation.recommendation.text`;
    the model flattens both into one object.
    """
    attributes = {
        **DETAILED_ATTRIBUTES,
        "check_metadata": {
            **CHECK_METADATA,
            "remediation": {
                "code": {
                    "cli": "aws s3api put-public-access-block ...",
                    "terraform": 'resource "aws_s3_bucket_public_access_block" ...',
                    "nativeiac": "",
                    "other": "",
                },
                "recommendation": {"text": "Block all public access on the bucket."},
            },
        },
    }

    finding = DetailedFinding.from_api_response(
        jsonapi_resource("findings", "f1", attributes)
    )

    remediation = finding.check_metadata.remediation
    assert remediation.cli.startswith("aws s3api")
    assert remediation.recommendation == "Block all public access on the bucket."
    # Empty code snippets are dropped rather than shown as blank fields.
    assert "nativeiac" not in remediation.model_dump()


def test_check_metadata_without_remediation_is_left_unset():
    """Not every check ships remediation guidance; absence must not fabricate one."""
    finding = DetailedFinding.from_api_response(
        jsonapi_resource("findings", "f1", DETAILED_ATTRIBUTES)
    )

    assert finding.check_metadata.remediation is None
    assert "remediation" not in finding.check_metadata.model_dump()


def test_list_response_carries_the_api_pagination_metadata():
    """Pagination tells an agent whether it has seen everything it asked for."""
    response = jsonapi_collection(
        [jsonapi_resource("findings", "f1", FINDING_ATTRIBUTES)],
        page=2,
        pages=7,
        count=312,
    )

    result = FindingsListResponse.from_api_response(response)

    assert result.current_page == 2
    assert result.total_num_pages == 7
    assert result.total_num_finding == 312
    assert result.findings[0].check_id == "s3_bucket_public_access"


def test_overview_renames_the_pass_attribute_to_a_valid_identifier():
    """The API's `pass` count cannot keep its name -- `pass` is a Python keyword."""
    response = jsonapi_resource(
        "findings-overview",
        "overview",
        {
            "total": 100,
            "fail": 30,
            "pass": 60,
            "muted": 10,
            "new": 5,
            "changed": 3,
            "fail_new": 2,
            "fail_changed": 1,
            "pass_new": 2,
            "pass_changed": 1,
            "muted_new": 1,
            "muted_changed": 1,
        },
    )

    overview = FindingsOverview.from_api_response({"data": response})

    assert overview.passed == 60
    assert overview.fail == 30
    assert overview.total == 100
