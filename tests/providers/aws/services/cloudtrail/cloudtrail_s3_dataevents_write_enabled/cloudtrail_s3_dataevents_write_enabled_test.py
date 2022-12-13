from re import search
from unittest import mock

from boto3 import client
from moto import mock_cloudtrail, mock_s3


class Test_cloudtrail_s3_dataevents_write_enabled:
    @mock_cloudtrail
    @mock_s3
    def test_trail_without_data_events(self):
        cloudtrail_client_us_east_1 = client("cloudtrail", region_name="us-east-1")
        s3_client_us_east_1 = client("s3", region_name="us-east-1")
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=False
        )

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_write_enabled.cloudtrail_s3_dataevents_write_enabled.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_write_enabled.cloudtrail_s3_dataevents_write_enabled import (
                cloudtrail_s3_dataevents_write_enabled,
            )

            check = cloudtrail_s3_dataevents_write_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "No CloudTrail trails have a data event to record all S3 object-level API operations.",
                result[0].status_extended,
            )
            assert result[0].resource_id == "No trails"
            assert result[0].resource_arn == "No trails"

    @mock_cloudtrail
    @mock_s3
    def test_trail_without_s3_data_events(self):
        cloudtrail_client_us_east_1 = client("cloudtrail", region_name="us-east-1")
        s3_client_us_east_1 = client("s3", region_name="us-east-1")
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
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_write_enabled.cloudtrail_s3_dataevents_write_enabled.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_write_enabled.cloudtrail_s3_dataevents_write_enabled import (
                cloudtrail_s3_dataevents_write_enabled,
            )

            check = cloudtrail_s3_dataevents_write_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "No CloudTrail trails have a data event to record all S3 object-level API operations.",
                result[0].status_extended,
            )
            assert result[0].resource_id == "No trails"
            assert result[0].resource_arn == "No trails"

    @mock_cloudtrail
    @mock_s3
    def test_trail_with_s3_data_events(self):
        cloudtrail_client_us_east_1 = client("cloudtrail", region_name="us-east-1")
        s3_client_us_east_1 = client("s3", region_name="us-east-1")
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
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_write_enabled.cloudtrail_s3_dataevents_write_enabled.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudtrail.cloudtrail_s3_dataevents_write_enabled.cloudtrail_s3_dataevents_write_enabled import (
                cloudtrail_s3_dataevents_write_enabled,
            )

            check = cloudtrail_s3_dataevents_write_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "have a data event to record all S3 object-level API operations.",
                result[0].status_extended,
            )
            assert result[0].resource_id == trail_name_us
            assert result[0].resource_arn == trail_us["TrailARN"]
