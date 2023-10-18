from re import search
from unittest import mock

from boto3 import client, session
from moto import mock_cloudtrail, mock_s3

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"


class Test_cloudtrail_s3_dataevents_read_enabled:
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
            audited_regions=[AWS_REGION],
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

    @mock_cloudtrail
    @mock_s3
    def test_trail_without_data_events(self):
        cloudtrail_client_us_east_1 = client("cloudtrail", region_name=AWS_REGION)
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION)
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=False
        )

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_read_enabled.cloudtrail_s3_dataevents_read_enabled.cloudtrail_client",
                new=Cloudtrail(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_read_enabled.cloudtrail_s3_dataevents_read_enabled import (
                    cloudtrail_s3_dataevents_read_enabled,
                )

                check = cloudtrail_s3_dataevents_read_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert search(
                    "No CloudTrail trails have a data event to record all S3 object-level API operations.",
                    result[0].status_extended,
                )
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert (
                    result[0].resource_arn == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
                )
                assert result[0].resource_tags == []
                assert result[0].region == AWS_REGION

    def test_trail_without_data_events_ignoring(self):

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        current_audit_info = self.set_mocked_audit_info()
        current_audit_info.ignore_unused_services = True

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_read_enabled.cloudtrail_s3_dataevents_read_enabled.cloudtrail_client",
                new=Cloudtrail(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_read_enabled.cloudtrail_s3_dataevents_read_enabled import (
                    cloudtrail_s3_dataevents_read_enabled,
                )

                check = cloudtrail_s3_dataevents_read_enabled()
                result = check.execute()

                assert len(result) == 0

    @mock_cloudtrail
    @mock_s3
    def test_trail_without_s3_data_events(self):
        cloudtrail_client_us_east_1 = client("cloudtrail", region_name=AWS_REGION)
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION)
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=False
        )
        _ = cloudtrail_client_us_east_1.put_event_selectors(
            TrailName=trail_name_us,
            EventSelectors=[
                {
                    "ReadWriteType": "All",
                    "IncludeManagementEvents": True,
                    "DataResources": [
                        {"Type": "AWS::Lambda::Function", "Values": ["arn:aws:lambda"]}
                    ],
                }
            ],
        )["EventSelectors"]

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_read_enabled.cloudtrail_s3_dataevents_read_enabled.cloudtrail_client",
                new=Cloudtrail(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_read_enabled.cloudtrail_s3_dataevents_read_enabled import (
                    cloudtrail_s3_dataevents_read_enabled,
                )

                check = cloudtrail_s3_dataevents_read_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert search(
                    "No CloudTrail trails have a data event to record all S3 object-level API operations.",
                    result[0].status_extended,
                )
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert (
                    result[0].resource_arn == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
                )
                assert result[0].resource_tags == []
                assert result[0].region == AWS_REGION

    @mock_cloudtrail
    @mock_s3
    def test_trail_with_s3_classic_data_events(self):
        cloudtrail_client_us_east_1 = client("cloudtrail", region_name=AWS_REGION)
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION)
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        trail_us = cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=False
        )
        _ = cloudtrail_client_us_east_1.put_event_selectors(
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

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_read_enabled.cloudtrail_s3_dataevents_read_enabled.cloudtrail_client",
                new=Cloudtrail(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_read_enabled.cloudtrail_s3_dataevents_read_enabled import (
                    cloudtrail_s3_dataevents_read_enabled,
                )

                check = cloudtrail_s3_dataevents_read_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert search(
                    "has a classic data event selector to record all S3 object-level API operations.",
                    result[0].status_extended,
                )
                assert result[0].resource_id == trail_name_us
                assert result[0].resource_arn == trail_us["TrailARN"]
                assert result[0].resource_tags == []
                assert result[0].region == AWS_REGION

    @mock_cloudtrail
    @mock_s3
    def test_trail_with_s3_advanced_data_events(self):
        cloudtrail_client_us_east_1 = client("cloudtrail", region_name=AWS_REGION)
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION)
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        trail_us = cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=False
        )
        _ = cloudtrail_client_us_east_1.put_event_selectors(
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

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_read_enabled.cloudtrail_s3_dataevents_read_enabled.cloudtrail_client",
                new=Cloudtrail(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_read_enabled.cloudtrail_s3_dataevents_read_enabled import (
                    cloudtrail_s3_dataevents_read_enabled,
                )

                check = cloudtrail_s3_dataevents_read_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert search(
                    "has an advanced data event selector to record all S3 object-level API operations.",
                    result[0].status_extended,
                )
                assert result[0].resource_id == trail_name_us
                assert result[0].resource_arn == trail_us["TrailARN"]
                assert result[0].resource_tags == []
                assert result[0].region == AWS_REGION

    @mock_cloudtrail
    @mock_s3
    def test_trail_with_s3_three_colons(self):
        cloudtrail_client_us_east_1 = client("cloudtrail", region_name=AWS_REGION)
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION)
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        trail_us = cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=False
        )
        _ = cloudtrail_client_us_east_1.put_event_selectors(
            TrailName=trail_name_us,
            EventSelectors=[
                {
                    "ReadWriteType": "All",
                    "IncludeManagementEvents": True,
                    "DataResources": [
                        {
                            "Type": "AWS::DynamoDB::Table",
                            "Values": ["arn:aws:dynamodb"],
                        },
                        {"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::"]},
                        {"Type": "AWS::Lambda::Function", "Values": ["arn:aws:lambda"]},
                    ],
                    "ExcludeManagementEventSources": [],
                }
            ],
        )["EventSelectors"]

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_read_enabled.cloudtrail_s3_dataevents_read_enabled.cloudtrail_client",
                new=Cloudtrail(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_read_enabled.cloudtrail_s3_dataevents_read_enabled import (
                    cloudtrail_s3_dataevents_read_enabled,
                )

                check = cloudtrail_s3_dataevents_read_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert search(
                    "has a classic data event selector to record all S3 object-level API operations.",
                    result[0].status_extended,
                )
                assert result[0].resource_id == trail_name_us
                assert result[0].resource_arn == trail_us["TrailARN"]
                assert result[0].resource_tags == []
                assert result[0].region == AWS_REGION
