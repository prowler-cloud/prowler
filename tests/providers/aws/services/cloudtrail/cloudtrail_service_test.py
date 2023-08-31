from boto3 import client, session
from moto import mock_cloudtrail, mock_s3

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.cloudtrail.cloudtrail_service import Cloudtrail
from prowler.providers.common.models import Audit_Metadata

AWS_ACCOUNT_NUMBER = "123456789012"


class Test_Cloudtrail_Service:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=["eu-west-1", "us-east-1"],
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )
        return audit_info

    # Test Cloudtrail Service
    @mock_cloudtrail
    def test_service(self):
        audit_info = self.set_mocked_audit_info()
        cloudtrail = Cloudtrail(audit_info)
        assert cloudtrail.service == "cloudtrail"

    # Test Cloudtrail client
    @mock_cloudtrail
    def test_client(self):
        audit_info = self.set_mocked_audit_info()
        cloudtrail = Cloudtrail(audit_info)
        for regional_client in cloudtrail.regional_clients.values():
            assert regional_client.__class__.__name__ == "CloudTrail"

    # Test Cloudtrail session
    @mock_cloudtrail
    def test__get_session__(self):
        audit_info = self.set_mocked_audit_info()
        cloudtrail = Cloudtrail(audit_info)
        assert cloudtrail.session.__class__.__name__ == "Session"

    # Test Cloudtrail Session
    @mock_cloudtrail
    def test_audited_account(self):
        audit_info = self.set_mocked_audit_info()
        cloudtrail = Cloudtrail(audit_info)
        assert cloudtrail.audited_account == AWS_ACCOUNT_NUMBER

    @mock_cloudtrail
    @mock_s3
    def test_describe_trails(self):
        cloudtrail_client_us_east_1 = client("cloudtrail", region_name="us-east-1")
        s3_client_us_east_1 = client("s3", region_name="us-east-1")
        cloudtrail_client_eu_west_1 = client("cloudtrail", region_name="eu-west-1")
        s3_client_eu_west_1 = client("s3", region_name="eu-west-1")
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        trail_name_eu = "trail_test_eu"
        bucket_name_eu = "bucket_test_eu"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        s3_client_eu_west_1.create_bucket(
            Bucket=bucket_name_eu,
            CreateBucketConfiguration={"LocationConstraint": "eu-west-1"},
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
        audit_info = self.set_mocked_audit_info()
        cloudtrail = Cloudtrail(audit_info)
        assert len(cloudtrail.trails) == 2
        for trail in cloudtrail.trails:
            if trail.name:
                assert trail.name == trail_name_us or trail.name == trail_name_eu
                assert not trail.is_multiregion
                assert (
                    trail.home_region == "us-east-1" or trail.home_region == "eu-west-1"
                )
                assert trail.region == "us-east-1" or trail.region == "eu-west-1"
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

    @mock_cloudtrail
    @mock_s3
    def test_status_trails(self):
        cloudtrail_client_us_east_1 = client("cloudtrail", region_name="us-east-1")
        s3_client_us_east_1 = client("s3", region_name="us-east-1")
        cloudtrail_client_eu_west_1 = client("cloudtrail", region_name="eu-west-1")
        s3_client_eu_west_1 = client("s3", region_name="eu-west-1")
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        trail_name_eu = "trail_test_eu"
        bucket_name_eu = "bucket_test_eu"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        s3_client_eu_west_1.create_bucket(
            Bucket=bucket_name_eu,
            CreateBucketConfiguration={"LocationConstraint": "eu-west-1"},
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
        audit_info = self.set_mocked_audit_info()
        cloudtrail = Cloudtrail(audit_info)
        assert len(cloudtrail.trails) == len(audit_info.audited_regions)
        for trail in cloudtrail.trails:
            if trail.name:
                if trail.name == trail_name_us:
                    assert not trail.is_multiregion
                    assert trail.home_region == "us-east-1"
                    assert trail.region == "us-east-1"
                    assert trail.is_logging
                    assert trail.log_file_validation_enabled
                    assert not trail.latest_cloudwatch_delivery_time
                    assert trail.s3_bucket == bucket_name_us

    @mock_cloudtrail
    @mock_s3
    def test_get_classic_event_selectors(self):
        cloudtrail_client_us_east_1 = client("cloudtrail", region_name="us-east-1")
        s3_client_us_east_1 = client("s3", region_name="us-east-1")
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
        audit_info = self.set_mocked_audit_info()
        cloudtrail = Cloudtrail(audit_info)
        assert len(cloudtrail.trails) == len(audit_info.audited_regions)
        for trail in cloudtrail.trails:
            if trail.name:
                if trail.name == trail_name_us:
                    assert not trail.is_multiregion
                    assert trail.home_region == "us-east-1"
                    assert trail.region == "us-east-1"
                    assert trail.is_logging
                    assert trail.log_file_validation_enabled
                    assert not trail.latest_cloudwatch_delivery_time
                    assert trail.s3_bucket == bucket_name_us
                    assert (
                        trail.data_events[0].event_selector == data_events_response[0]
                    )
                    assert not trail.data_events[0].is_advanced

    @mock_cloudtrail
    @mock_s3
    def test_get_advanced_event_selectors(self):
        cloudtrail_client_us_east_1 = client("cloudtrail", region_name="us-east-1")
        s3_client_us_east_1 = client("s3", region_name="us-east-1")
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
        audit_info = self.set_mocked_audit_info()
        cloudtrail = Cloudtrail(audit_info)
        assert len(cloudtrail.trails) == len(audit_info.audited_regions)
        for trail in cloudtrail.trails:
            if trail.name:
                if trail.name == trail_name_us:
                    assert not trail.is_multiregion
                    assert trail.home_region == "us-east-1"
                    assert trail.region == "us-east-1"
                    assert trail.is_logging
                    assert trail.log_file_validation_enabled
                    assert not trail.latest_cloudwatch_delivery_time
                    assert trail.s3_bucket == bucket_name_us
                    assert (
                        trail.data_events[0].event_selector == data_events_response[0]
                    )
                    assert trail.data_events[0].is_advanced
