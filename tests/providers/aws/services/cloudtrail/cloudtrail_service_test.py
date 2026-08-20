from unittest.mock import patch

import botocore
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
    Cloudtrail,
    Event_Selector,
    Trail,
    data_event_resource_types,
    trail_data_event_coverage,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_SOUTH_2,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call

MEMORY_RESOURCE_TYPE = "AWS::BedrockAgentCore::Memory"
RUNTIME_RESOURCE_TYPE = "AWS::BedrockAgentCore::Runtime"
MEMORY_SELECTOR = {
    "Name": "AgentCore Memory data events",
    "FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Data"]},
        {"Field": "resources.type", "Equals": [MEMORY_RESOURCE_TYPE]},
    ],
}


def _access_denied(operation_name):
    return botocore.exceptions.ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "not authorized",
            }
        },
        operation_name,
    )


def _create_trail(region, trail_name, bucket_name, start_logging=True):
    cloudtrail = client("cloudtrail", region_name=region)
    s3 = client("s3", region_name=region)
    if region == AWS_REGION_US_EAST_1:
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": region},
        )
    cloudtrail.create_trail(
        Name=trail_name, S3BucketName=bucket_name, IsMultiRegionTrail=False
    )
    if start_logging:
        cloudtrail.start_logging(Name=trail_name)


class Test_Cloudtrail_Service:
    # Test Cloudtrail Service
    @mock_aws
    def test_service(self):
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        cloudtrail = Cloudtrail(aws_provider)
        assert cloudtrail.service == "cloudtrail"

    # Test Cloudtrail client
    @mock_aws
    def test_client(self):
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        cloudtrail = Cloudtrail(aws_provider)
        for regional_client in cloudtrail.regional_clients.values():
            assert regional_client.__class__.__name__ == "CloudTrail"

    # Test Cloudtrail session
    @mock_aws
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        cloudtrail = Cloudtrail(aws_provider)
        assert cloudtrail.session.__class__.__name__ == "Session"

    # Test Cloudtrail Session
    @mock_aws
    def test_audited_account(self):
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        cloudtrail = Cloudtrail(aws_provider)
        assert cloudtrail.audited_account == AWS_ACCOUNT_NUMBER

    @mock_aws
    def test_describe_trails(self):
        # USA
        cloudtrail_client_us_east_1 = client(
            "cloudtrail", region_name=AWS_REGION_US_EAST_1
        )
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us,
            S3BucketName=bucket_name_us,
            IsMultiRegionTrail=False,
            TagsList=[
                {"Key": "test", "Value": "test"},
            ],
        )

        # IRELAND
        cloudtrail_client_eu_west_1 = client(
            "cloudtrail", region_name=AWS_REGION_EU_WEST_1
        )
        s3_client_eu_west_1 = client("s3", region_name=AWS_REGION_EU_WEST_1)
        trail_name_eu = "trail_test_eu"
        bucket_name_eu = "bucket_test_eu"
        s3_client_eu_west_1.create_bucket(
            Bucket=bucket_name_eu,
            CreateBucketConfiguration={"LocationConstraint": AWS_REGION_EU_WEST_1},
        )
        cloudtrail_client_eu_west_1.create_trail(
            Name=trail_name_eu,
            S3BucketName=bucket_name_eu,
            IsMultiRegionTrail=False,
            TagsList=[
                {"Key": "test", "Value": "test"},
            ],
        )
        # SPAIN
        cloudtrail_client_eu_south_2 = client(
            "cloudtrail", region_name=AWS_REGION_EU_SOUTH_2
        )
        s3_client_eu_south_2 = client("s3", region_name=AWS_REGION_EU_SOUTH_2)
        trail_name_sp = "trail_test_sp"
        bucket_name_sp = "bucket_test_sp"
        s3_client_eu_south_2.create_bucket(
            Bucket=bucket_name_sp,
            CreateBucketConfiguration={"LocationConstraint": AWS_REGION_EU_SOUTH_2},
        )
        cloudtrail_client_eu_south_2.create_trail(
            Name=trail_name_sp,
            S3BucketName=bucket_name_sp,
            IsMultiRegionTrail=True,
            TagsList=[
                {"Key": "test", "Value": "test"},
            ],
        )

        # We are not going to include AWS_REGION_EU_SOUTH_2 in the audited
        # regions, but that trail is regional so it'll appear
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        cloudtrail = Cloudtrail(aws_provider)
        assert len(cloudtrail.trails) == 3
        for trail in cloudtrail.trails.values():
            if trail.name == trail_name_us:
                assert not trail.is_multiregion
                assert trail.home_region == AWS_REGION_US_EAST_1
                assert trail.region == AWS_REGION_US_EAST_1
                assert not trail.is_logging
                assert not trail.log_file_validation_enabled
                assert not trail.latest_cloudwatch_delivery_time
                assert trail.s3_bucket == bucket_name_us
                assert trail.tags == [
                    {"Key": "test", "Value": "test"},
                ]
            if trail.name == trail_name_eu:
                assert not trail.is_multiregion
                assert trail.home_region == AWS_REGION_EU_WEST_1
                assert trail.region == AWS_REGION_EU_WEST_1
                assert not trail.is_logging
                assert not trail.log_file_validation_enabled
                assert not trail.latest_cloudwatch_delivery_time
                assert trail.s3_bucket == bucket_name_eu
                assert trail.tags == [
                    {"Key": "test", "Value": "test"},
                ]
            if trail.name == trail_name_sp:
                assert trail.is_multiregion
                assert trail.home_region == AWS_REGION_EU_SOUTH_2
                # The region is the first audited region since the trail home region is not audited
                assert (
                    trail.region == AWS_REGION_US_EAST_1
                    or trail.region == AWS_REGION_EU_WEST_1
                )
                assert not trail.is_logging
                assert not trail.log_file_validation_enabled
                assert not trail.latest_cloudwatch_delivery_time
                assert trail.s3_bucket == bucket_name_sp
                # No tags since the trail region is not audited and the tags are retrieved from the regional endpoint
                assert trail.tags == []

    @mock_aws
    def test_status_trails(self):
        cloudtrail_client_us_east_1 = client(
            "cloudtrail", region_name=AWS_REGION_US_EAST_1
        )
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        cloudtrail_client_eu_west_1 = client(
            "cloudtrail", region_name=AWS_REGION_EU_WEST_1
        )
        s3_client_eu_west_1 = client("s3", region_name=AWS_REGION_EU_WEST_1)
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        trail_name_eu = "trail_test_eu"
        bucket_name_eu = "bucket_test_eu"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        s3_client_eu_west_1.create_bucket(
            Bucket=bucket_name_eu,
            CreateBucketConfiguration={"LocationConstraint": AWS_REGION_EU_WEST_1},
        )
        cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us,
            S3BucketName=bucket_name_us,
            IsMultiRegionTrail=False,
            EnableLogFileValidation=True,
        )
        cloudtrail_client_us_east_1.start_logging(Name=trail_name_us)
        cloudtrail_client_eu_west_1.create_trail(
            Name=trail_name_eu, S3BucketName=bucket_name_eu, IsMultiRegionTrail=False
        )
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        cloudtrail = Cloudtrail(aws_provider)
        assert len(cloudtrail.trails) == len(aws_provider.identity.audited_regions)
        for trail in cloudtrail.trails.values():
            if trail.name:
                if trail.name == trail_name_us:
                    assert not trail.is_multiregion
                    assert trail.home_region == AWS_REGION_US_EAST_1
                    assert trail.region == AWS_REGION_US_EAST_1
                    assert trail.is_logging
                    assert trail.log_file_validation_enabled
                    assert not trail.latest_cloudwatch_delivery_time
                    assert trail.s3_bucket == bucket_name_us

    @mock_aws
    def test_get_classic_event_selectors(self):
        cloudtrail_client_us_east_1 = client(
            "cloudtrail", region_name=AWS_REGION_US_EAST_1
        )
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us,
            S3BucketName=bucket_name_us,
            IsMultiRegionTrail=False,
            EnableLogFileValidation=True,
        )
        cloudtrail_client_us_east_1.start_logging(Name=trail_name_us)
        data_events_response = cloudtrail_client_us_east_1.put_event_selectors(
            TrailName=trail_name_us,
            EventSelectors=[
                {
                    "ReadWriteType": "All",
                    "IncludeManagementEvents": True,
                    "DataResources": [
                        {"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::*/*"]}
                    ],
                }
            ],
        )["EventSelectors"]
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        cloudtrail = Cloudtrail(aws_provider)
        assert len(cloudtrail.trails) == len(aws_provider.identity.audited_regions)
        for trail in cloudtrail.trails.values():
            if trail.name:
                if trail.name == trail_name_us:
                    assert not trail.is_multiregion
                    assert trail.home_region == AWS_REGION_US_EAST_1
                    assert trail.region == AWS_REGION_US_EAST_1
                    assert trail.is_logging
                    assert trail.log_file_validation_enabled
                    assert not trail.latest_cloudwatch_delivery_time
                    assert trail.s3_bucket == bucket_name_us
                    assert (
                        trail.data_events[0].event_selector == data_events_response[0]
                    )
                    assert not trail.data_events[0].is_advanced

    @mock_aws
    def test_get_advanced_event_selectors(self):
        cloudtrail_client_us_east_1 = client(
            "cloudtrail", region_name=AWS_REGION_US_EAST_1
        )
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us,
            S3BucketName=bucket_name_us,
            IsMultiRegionTrail=False,
            EnableLogFileValidation=True,
        )
        cloudtrail_client_us_east_1.start_logging(Name=trail_name_us)
        data_events_response = cloudtrail_client_us_east_1.put_event_selectors(
            TrailName=trail_name_us,
            AdvancedEventSelectors=[
                {
                    "Name": "test",
                    "FieldSelectors": [
                        {"Field": "eventCategory", "Equals": ["Data"]},
                        {"Field": "resources.type", "Equals": ["AWS::S3::Object"]},
                    ],
                },
            ],
        )["AdvancedEventSelectors"]
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        cloudtrail = Cloudtrail(aws_provider)
        assert len(cloudtrail.trails) == len(aws_provider.identity.audited_regions)
        for trail in cloudtrail.trails.values():
            if trail.name:
                if trail.name == trail_name_us:
                    assert not trail.is_multiregion
                    assert trail.home_region == AWS_REGION_US_EAST_1
                    assert trail.region == AWS_REGION_US_EAST_1
                    assert trail.is_logging
                    assert trail.log_file_validation_enabled
                    assert not trail.latest_cloudwatch_delivery_time
                    assert trail.s3_bucket == bucket_name_us
                    assert (
                        trail.data_events[0].event_selector == data_events_response[0]
                    )
                    assert trail.data_events[0].is_advanced

    @mock_aws
    def test_lookup_events(self):
        cloudtrail_client_us_east_1 = client(
            "cloudtrail", region_name=AWS_REGION_US_EAST_1
        )
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us,
            S3BucketName=bucket_name_us,
            IsMultiRegionTrail=False,
            EnableLogFileValidation=True,
        )
        cloudtrail_client_us_east_1.start_logging(Name=trail_name_us)
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        cloudtrail = Cloudtrail(aws_provider)
        assert len(cloudtrail.trails) == len(aws_provider.identity.audited_regions)

    @mock_aws
    def test_get_event_selectors_error_is_recorded_per_trail(self):
        """One trail's denied GetEventSelectors must not answer for the others.

        An empty ``data_events`` reads as "this trail selects no data events", so a failed
        read is recorded on the trail it failed for, and the remaining trails are still
        collected.
        """
        _create_trail(AWS_REGION_US_EAST_1, "trail_denied", "bucket_denied")
        _create_trail(AWS_REGION_US_EAST_1, "trail_readable", "bucket_readable")
        client("cloudtrail", region_name=AWS_REGION_US_EAST_1).put_event_selectors(
            TrailName="trail_readable", AdvancedEventSelectors=[MEMORY_SELECTOR]
        )

        def mock_make_api_call(self, operation_name, kwarg):
            if operation_name == "GetEventSelectors" and "trail_denied" in kwarg.get(
                "TrailName", ""
            ):
                raise _access_denied(operation_name)
            return make_api_call(self, operation_name, kwarg)

        with patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call):
            cloudtrail = Cloudtrail(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))

        trails = {trail.name: trail for trail in cloudtrail.trails.values()}
        assert trails["trail_denied"].event_selectors_error == "ClientError"
        assert trails["trail_denied"].data_events == []
        assert trails["trail_readable"].event_selectors_error is None
        assert len(trails["trail_readable"].data_events) == 1
        selector = trails["trail_readable"].data_events[0]
        assert selector.is_advanced
        assert selector.event_selector["FieldSelectors"] == [
            {"Field": "eventCategory", "Equals": ["Data"]},
            {"Field": "resources.type", "Equals": [MEMORY_RESOURCE_TYPE]},
        ]

    @mock_aws
    def test_get_trail_status_error_is_recorded_per_trail(self):
        """A denied GetTrailStatus is recorded, not left as is_logging False."""
        _create_trail(AWS_REGION_US_EAST_1, "trail_denied", "bucket_denied")
        _create_trail(AWS_REGION_US_EAST_1, "trail_readable", "bucket_readable")

        def mock_make_api_call(self, operation_name, kwarg):
            if operation_name == "GetTrailStatus" and "trail_denied" in kwarg.get(
                "Name", ""
            ):
                raise _access_denied(operation_name)
            return make_api_call(self, operation_name, kwarg)

        with patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call):
            cloudtrail = Cloudtrail(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))

        trails = {trail.name: trail for trail in cloudtrail.trails.values()}
        assert trails["trail_denied"].status_error == "ClientError"
        assert trails["trail_denied"].is_logging is False
        assert trails["trail_readable"].status_error is None
        assert trails["trail_readable"].is_logging is True

    @mock_aws
    def test_get_trail_status_without_is_logging_is_recorded(self):
        """A response missing IsLogging is unknown, not not-logging."""
        _create_trail(AWS_REGION_US_EAST_1, "trail_test", "bucket_test")

        def mock_make_api_call(self, operation_name, kwarg):
            if operation_name == "GetTrailStatus":
                return {"LatestDeliveryError": ""}
            return make_api_call(self, operation_name, kwarg)

        with patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call):
            cloudtrail = Cloudtrail(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))

        trails = {trail.name: trail for trail in cloudtrail.trails.values()}
        assert trails["trail_test"].status_error == "KeyError"
        assert trails["trail_test"].is_logging is False

    @mock_aws
    def test_list_tags_for_resource(self):
        tag = "test-tag"
        cloudtrail_client_us_east_1 = client(
            "cloudtrail", region_name=AWS_REGION_US_EAST_1
        )
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us,
            S3BucketName=bucket_name_us,
            IsMultiRegionTrail=False,
            EnableLogFileValidation=True,
            TagsList=[
                {"Key": "test", "Value": tag},
            ],
        )
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        cloudtrail = Cloudtrail(aws_provider)
        assert len(cloudtrail.trails) == len(aws_provider.identity.audited_regions)
        for trail in cloudtrail.trails.values():
            if trail.name:
                if trail.name == trail_name_us:
                    assert trail.tags == [{"Key": "test", "Value": tag}]


class Test_data_event_resource_types:
    def test_data_selector_covers_its_resource_type(self):
        assert data_event_resource_types(MEMORY_SELECTOR) == (
            {MEMORY_RESOURCE_TYPE},
            set(),
        )

    def test_several_resource_types_in_one_selector(self):
        assert data_event_resource_types(
            {
                "FieldSelectors": [
                    {"Field": "eventCategory", "Equals": ["Data"]},
                    {
                        "Field": "resources.type",
                        "Equals": [MEMORY_RESOURCE_TYPE, RUNTIME_RESOURCE_TYPE],
                    },
                ]
            }
        ) == ({MEMORY_RESOURCE_TYPE, RUNTIME_RESOURCE_TYPE}, set())

    def test_management_selector_covers_no_data_events(self):
        assert data_event_resource_types(
            {
                "FieldSelectors": [
                    {"Field": "eventCategory", "Equals": ["Management"]},
                    {"Field": "resources.type", "Equals": [MEMORY_RESOURCE_TYPE]},
                ]
            }
        ) == (set(), set())

    def test_selector_without_event_category_covers_nothing(self):
        assert data_event_resource_types(
            {
                "FieldSelectors": [
                    {"Field": "resources.type", "Equals": [MEMORY_RESOURCE_TYPE]}
                ]
            }
        ) == (set(), set())

    def test_selector_without_field_selectors_covers_nothing(self):
        assert data_event_resource_types({"Name": "empty"}) == (set(), set())

    def test_event_name_filter_narrows_coverage(self):
        assert data_event_resource_types(
            {
                "FieldSelectors": [
                    {"Field": "eventCategory", "Equals": ["Data"]},
                    {"Field": "resources.type", "Equals": [MEMORY_RESOURCE_TYPE]},
                    {"Field": "eventName", "Equals": ["ListEvents"]},
                ]
            }
        ) == (set(), {MEMORY_RESOURCE_TYPE})

    def test_read_only_filter_narrows_coverage(self):
        assert data_event_resource_types(
            {
                "FieldSelectors": [
                    {"Field": "eventCategory", "Equals": ["Data"]},
                    {"Field": "resources.type", "Equals": [MEMORY_RESOURCE_TYPE]},
                    {"Field": "readOnly", "Equals": ["true"]},
                ]
            }
        ) == (set(), {MEMORY_RESOURCE_TYPE})

    def test_resource_arn_filter_narrows_coverage(self):
        assert data_event_resource_types(
            {
                "FieldSelectors": [
                    {"Field": "eventCategory", "Equals": ["Data"]},
                    {"Field": "resources.type", "Equals": [MEMORY_RESOURCE_TYPE]},
                    {
                        "Field": "resources.ARN",
                        "StartsWith": [
                            "arn:aws:bedrock-agentcore:us-east-1:1:memory/x"
                        ],
                    },
                ]
            }
        ) == (set(), {MEMORY_RESOURCE_TYPE})

    def test_field_selector_without_a_field_narrows_coverage(self):
        """An unrecognizable filter has an unknown effect, not no effect."""
        assert data_event_resource_types(
            {
                "FieldSelectors": [
                    {"Field": "eventCategory", "Equals": ["Data"]},
                    {"Field": "resources.type", "Equals": [MEMORY_RESOURCE_TYPE]},
                    {"Equals": ["something"]},
                ]
            }
        ) == (set(), {MEMORY_RESOURCE_TYPE})


class Test_trail_data_event_coverage:
    def test_only_requested_resource_types_are_reported(self):
        trail = Trail(
            region=AWS_REGION_US_EAST_1,
            name="trail_test",
            data_events=[
                Event_Selector(is_advanced=True, event_selector=MEMORY_SELECTOR),
                Event_Selector(
                    is_advanced=True,
                    event_selector={
                        "FieldSelectors": [
                            {"Field": "eventCategory", "Equals": ["Data"]},
                            {"Field": "resources.type", "Equals": ["AWS::S3::Object"]},
                        ]
                    },
                ),
            ],
        )

        assert trail_data_event_coverage(
            trail, frozenset({MEMORY_RESOURCE_TYPE, RUNTIME_RESOURCE_TYPE})
        ) == ({MEMORY_RESOURCE_TYPE}, set())

    def test_classic_selectors_are_not_credited(self):
        """Basic event selectors carry only DynamoDB, Lambda and S3 resource types."""
        trail = Trail(
            region=AWS_REGION_US_EAST_1,
            name="trail_test",
            data_events=[
                Event_Selector(
                    is_advanced=False,
                    event_selector={
                        "ReadWriteType": "All",
                        "IncludeManagementEvents": True,
                        "DataResources": [
                            {
                                "Type": MEMORY_RESOURCE_TYPE,
                                "Values": ["arn:aws:bedrock-agentcore"],
                            }
                        ],
                    },
                )
            ],
        )

        assert trail_data_event_coverage(trail, frozenset({MEMORY_RESOURCE_TYPE})) == (
            set(),
            set(),
        )

    def test_complete_coverage_is_not_also_reported_as_narrowed(self):
        narrowed_selector = {
            "FieldSelectors": [
                {"Field": "eventCategory", "Equals": ["Data"]},
                {"Field": "resources.type", "Equals": [MEMORY_RESOURCE_TYPE]},
                {"Field": "readOnly", "Equals": ["true"]},
            ]
        }
        trail = Trail(
            region=AWS_REGION_US_EAST_1,
            name="trail_test",
            data_events=[
                Event_Selector(is_advanced=True, event_selector=narrowed_selector),
                Event_Selector(is_advanced=True, event_selector=MEMORY_SELECTOR),
            ],
        )

        assert trail_data_event_coverage(trail, frozenset({MEMORY_RESOURCE_TYPE})) == (
            {MEMORY_RESOURCE_TYPE},
            set(),
        )

    def test_narrowed_coverage_of_one_type_and_complete_of_another(self):
        trail = Trail(
            region=AWS_REGION_US_EAST_1,
            name="trail_test",
            data_events=[
                Event_Selector(is_advanced=True, event_selector=MEMORY_SELECTOR),
                Event_Selector(
                    is_advanced=True,
                    event_selector={
                        "FieldSelectors": [
                            {"Field": "eventCategory", "Equals": ["Data"]},
                            {
                                "Field": "resources.type",
                                "Equals": [RUNTIME_RESOURCE_TYPE],
                            },
                            {"Field": "eventName", "Equals": ["InvokeAgentRuntime"]},
                        ]
                    },
                ),
            ],
        )

        assert trail_data_event_coverage(
            trail, frozenset({MEMORY_RESOURCE_TYPE, RUNTIME_RESOURCE_TYPE})
        ) == ({MEMORY_RESOURCE_TYPE}, {RUNTIME_RESOURCE_TYPE})
