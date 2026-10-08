"""Tests for the finding group models.

`_counter` uses `attributes.get(key) or 0`, which is meant to turn a missing
or `None` counter into `0` -- but the `or` also swallows an explicit `0`,
which is indistinguishable here from "not provided". The tests below pin that
behaviour rather than silently relying on it, so a future refactor sees this
as a decision, not an accident.
"""

from prowler_mcp_server.prowler_app.models.finding_groups import (
    DetailedFindingGroup,
    FindingGroupProviderInfo,
    FindingGroupResource,
    FindingGroupResourceInfo,
    FindingGroupResourcesListResponse,
    FindingGroupsListResponse,
    SimplifiedFindingGroup,
)
from tests.helpers.jsonapi import jsonapi_document, jsonapi_resource

GROUP_ATTRIBUTES = {
    "check_id": "s3_bucket_public_access",
    "check_title": "Ensure S3 buckets block public access",
    "severity": "high",
    "status": "FAIL",
    "muted": False,
    "impacted_providers": ["aws"],
    "resources_fail": 3,
    "resources_total": 10,
    "pass_count": 7,
    "fail_count": 3,
    "manual_count": 0,
    "muted_count": 0,
    "new_count": 1,
    "changed_count": 0,
    "first_seen_at": "2025-01-01T00:00:00Z",
    "last_seen_at": "2025-01-15T00:00:00Z",
    "failing_since": "2025-01-10T00:00:00Z",
}


def test_simplified_finding_group_reads_the_counters():
    group = SimplifiedFindingGroup.from_api_response(
        jsonapi_resource("finding-groups", "s3_bucket_public_access", GROUP_ATTRIBUTES)
    )

    assert group.check_id == "s3_bucket_public_access"
    assert group.resources_fail == 3
    assert group.resources_total == 10
    assert group.severity == "high"


def test_simplified_finding_group_falls_back_to_the_resource_id_for_check_id():
    """`check_id` is read from `attributes.check_id`, falling back to the JSON:API
    `id` -- both name the same check, but the fallback matters if a future
    endpoint stops repeating it in attributes."""
    group = SimplifiedFindingGroup.from_api_response(
        jsonapi_resource("finding-groups", "s3_bucket_public_access", {})
    )

    assert group.check_id == "s3_bucket_public_access"
    assert group.severity == "informational"
    assert group.status == "MANUAL"


def test_a_missing_counter_defaults_to_zero():
    group = SimplifiedFindingGroup.from_api_response(
        jsonapi_resource("finding-groups", "c1", {"check_id": "c1"})
    )

    assert group.resources_fail == 0
    assert group.fail_count == 0


def test_an_explicit_zero_counter_stays_zero():
    """Distinguishes 'genuinely counted, found none' from 'not provided' only in
    outcome -- both currently produce `0` because `_counter` uses `or 0`."""
    group = SimplifiedFindingGroup.from_api_response(
        jsonapi_resource(
            "finding-groups", "c1", {"check_id": "c1", "resources_fail": 0}
        )
    )

    assert group.resources_fail == 0


def test_detailed_finding_group_adds_the_full_counter_breakdown():
    attributes = {
        **GROUP_ATTRIBUTES,
        "check_description": "Blocks public access at the bucket level.",
        "pass_muted_count": 1,
        "new_fail_count": 1,
    }

    group = DetailedFindingGroup.from_api_response(
        jsonapi_resource("finding-groups", "s3_bucket_public_access", attributes)
    )

    assert group.check_description == "Blocks public access at the bucket level."
    assert group.pass_muted_count == 1
    assert group.new_fail_count == 1
    # Unset detailed counters still default to zero.
    assert group.changed_manual_muted_count == 0


def test_finding_groups_list_response_carries_pagination_metadata():
    response = jsonapi_document(
        data=[
            jsonapi_resource(
                "finding-groups", "s3_bucket_public_access", GROUP_ATTRIBUTES
            )
        ],
        meta={"pagination": {"page": 2, "pages": 4, "count": 87}},
    )

    result = FindingGroupsListResponse.from_api_response(response)

    assert result.current_page == 2
    assert result.total_num_pages == 4
    assert result.total_num_groups == 87
    assert result.groups[0].check_id == "s3_bucket_public_access"


def test_finding_groups_list_response_defaults_pagination_from_the_group_count():
    response = jsonapi_document(
        data=[
            jsonapi_resource("finding-groups", "c1", GROUP_ATTRIBUTES),
            jsonapi_resource("finding-groups", "c2", GROUP_ATTRIBUTES),
        ]
    )

    result = FindingGroupsListResponse.from_api_response(response)

    assert result.total_num_groups == 2
    assert result.total_num_pages == 1
    assert result.current_page == 1


def test_finding_group_resource_info_defaults_missing_fields_to_empty_strings():
    info = FindingGroupResourceInfo.from_api_response({})

    assert info.uid == ""
    assert info.resource_group is None


def test_finding_group_provider_info_reads_type_uid_and_alias():
    info = FindingGroupProviderInfo.from_api_response(
        {"type": "aws", "uid": "123456789012", "alias": "production"}
    )

    assert info.type == "aws"
    assert info.uid == "123456789012"
    assert info.alias == "production"


def test_finding_group_resource_builds_nested_resource_and_provider_from_null_data():
    """`attributes.get("resource") or {}` guards against an explicit `null`, not
    just a missing key -- both must produce an empty nested object rather than
    raising."""
    resource = FindingGroupResource.from_api_response(
        jsonapi_resource(
            "finding-group-resources",
            "row1",
            {
                "resource": None,
                "provider": None,
                "finding_id": "f1",
                "status": "FAIL",
                "severity": "high",
                "muted": False,
            },
        )
    )

    assert resource.resource.uid == ""
    assert resource.provider.uid == ""
    assert resource.finding_id == "f1"


def test_finding_group_resource_coerces_a_numeric_finding_id_to_a_string():
    resource = FindingGroupResource.from_api_response(
        jsonapi_resource(
            "finding-group-resources",
            "row1",
            {
                "resource": {
                    "uid": "r1",
                    "name": "n",
                    "service": "s3",
                    "region": "us-east-1",
                    "type": "AwsS3Bucket",
                },
                "provider": {"type": "aws", "uid": "123"},
                "finding_id": 42,
                "status": "FAIL",
                "severity": "high",
                "muted": False,
            },
        )
    )

    assert resource.finding_id == "42"
    assert isinstance(resource.finding_id, str)


def test_finding_group_resources_list_response_carries_pagination_metadata():
    response = jsonapi_document(
        data=[
            jsonapi_resource(
                "finding-group-resources",
                "row1",
                {
                    "resource": {
                        "uid": "r1",
                        "name": "n",
                        "service": "s3",
                        "region": "us-east-1",
                        "type": "AwsS3Bucket",
                    },
                    "provider": {"type": "aws", "uid": "123"},
                    "finding_id": "f1",
                    "status": "FAIL",
                    "severity": "high",
                    "muted": False,
                },
            )
        ],
        meta={"pagination": {"page": 1, "pages": 1, "count": 1}},
    )

    result = FindingGroupResourcesListResponse.from_api_response(response)

    assert result.total_num_resources == 1
    assert result.resources[0].resource.uid == "r1"
