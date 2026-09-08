"""Tests for the cloud resource models."""

from prowler_mcp_server.prowler_app.models.resources import (
    DetailedResource,
    ResourceEvent,
    ResourceEventsResponse,
    ResourcesListResponse,
    ResourcesMetadataResponse,
    SimplifiedResource,
)
from tests.helpers.jsonapi import (
    jsonapi_document,
    jsonapi_relationship_one,
    jsonapi_resource,
)

RESOURCE_ATTRIBUTES = {
    "uid": "arn:aws:s3:::my-bucket",
    "name": "my-bucket",
    "region": "us-east-1",
    "service": "s3",
    "type": "AwsS3Bucket",
    "failed_findings_count": 2,
    "tags": {"Environment": "production"},
}

DETAILED_ATTRIBUTES = {
    **RESOURCE_ATTRIBUTES,
    "metadata": '{"encryption": "AES256"}',
    "partition": "aws",
    "inserted_at": "2025-01-01T00:00:00Z",
    "updated_at": "2025-01-15T00:00:00Z",
}


def test_simplified_resource_reads_core_fields():
    resource = SimplifiedResource.from_api_response(
        jsonapi_resource("resources", "res1", RESOURCE_ATTRIBUTES)
    )

    assert resource.id == "res1"
    assert resource.uid == "arn:aws:s3:::my-bucket"
    assert resource.failed_findings_count == 2
    assert resource.tags == {"Environment": "production"}


def test_simplified_resource_extracts_provider_id_from_relationship():
    resource = SimplifiedResource.from_api_response(
        jsonapi_resource(
            "resources",
            "res1",
            attributes=RESOURCE_ATTRIBUTES,
            relationships={"provider": jsonapi_relationship_one("providers", "p1")},
        )
    )

    assert resource.provider_id == "p1"


def test_simplified_resource_tolerates_a_missing_provider_relationship():
    resource = SimplifiedResource.from_api_response(
        jsonapi_resource("resources", "res1", RESOURCE_ATTRIBUTES)
    )

    assert resource.provider_id is None


def test_detailed_resource_adds_configuration_and_temporal_fields():
    resource = DetailedResource.from_api_response(
        jsonapi_resource("resources", "res1", DETAILED_ATTRIBUTES)
    )

    assert resource.partition == "aws"
    assert resource.inserted_at == "2025-01-01T00:00:00Z"
    assert resource.updated_at == "2025-01-15T00:00:00Z"


def test_detailed_resource_extracts_provider_id_from_relationship():
    resource = DetailedResource.from_api_response(
        jsonapi_resource(
            "resources",
            "res1",
            attributes=DETAILED_ATTRIBUTES,
            relationships={"provider": jsonapi_relationship_one("providers", "p1")},
        )
    )

    assert resource.provider_id == "p1"


def test_detailed_resource_parses_finding_ids_from_relationship():
    resource = DetailedResource.from_api_response(
        jsonapi_resource(
            "resources",
            "res1",
            attributes=DETAILED_ATTRIBUTES,
            relationships={
                "findings": {
                    "data": [
                        {"type": "findings", "id": "f1"},
                        {"type": "findings", "id": "f2"},
                    ]
                }
            },
        )
    )

    assert resource.finding_ids == ["f1", "f2"]


def test_detailed_resource_reports_no_findings_as_none_not_empty_list():
    """The source builds `finding_ids` only `if findings_data`, so an empty or
    absent relationship both collapse to `None` rather than `[]`."""
    resource = DetailedResource.from_api_response(
        jsonapi_resource("resources", "res1", DETAILED_ATTRIBUTES)
    )

    assert resource.finding_ids is None


def test_resources_list_response_carries_pagination_metadata():
    response = jsonapi_document(
        data=[jsonapi_resource("resources", "res1", RESOURCE_ATTRIBUTES)],
        meta={"pagination": {"page": 3, "pages": 9, "count": 421}},
    )

    result = ResourcesListResponse.from_api_response(response)

    assert result.current_page == 3
    assert result.total_num_pages == 9
    assert result.total_num_resources == 421
    assert result.resources[0].uid == "arn:aws:s3:::my-bucket"


def test_resources_metadata_response_reads_services_regions_and_types():
    response = jsonapi_document(
        jsonapi_resource(
            "resources-metadata",
            "metadata",
            {
                "services": ["s3", "ec2"],
                "regions": ["us-east-1"],
                "types": ["AwsS3Bucket"],
            },
        )
    )

    metadata = ResourcesMetadataResponse.from_api_response(response)

    assert metadata.services == ["s3", "ec2"]
    assert metadata.regions == ["us-east-1"]
    assert metadata.types == ["AwsS3Bucket"]


def test_resources_metadata_response_tolerates_missing_fields():
    response = jsonapi_document(jsonapi_resource("resources-metadata", "metadata", {}))

    metadata = ResourcesMetadataResponse.from_api_response(response)

    assert metadata.services is None
    assert metadata.regions is None
    assert metadata.types is None


def test_resource_event_reads_all_attributes_directly():
    event = ResourceEvent.from_api_response(
        jsonapi_resource(
            "resource-events",
            "ev1",
            {
                "event_time": "2025-01-01T00:00:00Z",
                "event_name": "PutBucketPolicy",
                "event_source": "s3.amazonaws.com",
                "actor": "arn:aws:iam::123456789012:user/alice",
            },
        )
    )

    assert event.id == "ev1"
    assert event.event_name == "PutBucketPolicy"
    assert event.actor == "arn:aws:iam::123456789012:user/alice"


def test_resource_events_response_counts_the_events_it_parsed():
    response = jsonapi_document(
        data=[
            jsonapi_resource(
                "resource-events",
                "ev1",
                {
                    "event_time": "2025-01-01T00:00:00Z",
                    "event_name": "PutBucketPolicy",
                    "event_source": "s3.amazonaws.com",
                    "actor": "alice",
                },
            )
        ]
    )

    result = ResourceEventsResponse.from_api_response(response)

    assert result.total_events == 1
    assert result.events[0].event_name == "PutBucketPolicy"


def test_resource_events_response_tolerates_a_missing_data_key():
    result = ResourceEventsResponse.from_api_response({})

    assert result.events == []
    assert result.total_events == 0
