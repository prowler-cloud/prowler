from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.cloudtrail.cloudtrail_service import Cloudtrail
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)


class Test_Cloudtrail_Service:
    # Test Cloudtrail Service
    @mock_aws
    def test_service(self):
        audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        cloudtrail = Cloudtrail(audit_info)
        assert cloudtrail.service == "cloudtrail"

    # Test Cloudtrail client
    @mock_aws
    def test_client(self):
        audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        cloudtrail = Cloudtrail(audit_info)
        for regional_client in cloudtrail.regional_clients.values():
            assert regional_client.__class__.__name__ == "CloudTrail"

    # Test Cloudtrail session
    @mock_aws
    def test__get_session__(self):
        audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        cloudtrail = Cloudtrail(audit_info)
        assert cloudtrail.session.__class__.__name__ == "Session"

    # Test Cloudtrail Session
    @mock_aws
    def test_audited_account(self):
        audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        cloudtrail = Cloudtrail(audit_info)
        assert cloudtrail.audited_account == AWS_ACCOUNT_NUMBER

    @mock_aws
    @mock_aws
    def test_describe_trails(self):
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
            TagsList=[
                {"Key": "test", "Value": "test"},
            ],
        )
        cloudtrail_client_eu_west_1.create_trail(
            Name=trail_name_eu,
            S3BucketName=bucket_name_eu,
            IsMultiRegionTrail=False,
            TagsList=[
                {"Key": "test", "Value": "test"},
            ],
        )
        audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        cloudtrail = Cloudtrail(audit_info)
        assert len(cloudtrail.trails) == 2
        for trail in cloudtrail.trails:
            if trail.name:
                assert trail.name == trail_name_us or trail.name == trail_name_eu
                assert not trail.is_multiregion
                assert (
                    trail.home_region == AWS_REGION_US_EAST_1
                    or trail.home_region == AWS_REGION_EU_WEST_1
                )
                assert (
                    trail.region == AWS_REGION_US_EAST_1
                    or trail.region == AWS_REGION_EU_WEST_1
                )
                assert not trail.is_logging
                assert not trail.log_file_validation_enabled
                assert not trail.latest_cloudwatch_delivery_time
                assert (
                    trail.s3_bucket == bucket_name_eu
                    or trail.s3_bucket == bucket_name_us
                )
                assert trail.tags == [
                    {"Key": "test", "Value": "test"},
                ]

    @mock_aws
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
        audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        cloudtrail = Cloudtrail(audit_info)
        assert len(cloudtrail.trails) == len(audit_info.audited_regions)
        for trail in cloudtrail.trails:
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
        audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        cloudtrail = Cloudtrail(audit_info)
        assert len(cloudtrail.trails) == len(audit_info.audited_regions)
        for trail in cloudtrail.trails:
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
        audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        cloudtrail = Cloudtrail(audit_info)
        assert len(cloudtrail.trails) == len(audit_info.audited_regions)
        for trail in cloudtrail.trails:
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
