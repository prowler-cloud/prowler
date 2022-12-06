from re import search
from unittest import mock

from boto3 import client
from moto import mock_cloudtrail, mock_s3


class Test_cloudtrail_logs_s3_bucket_access_logging_enabled:
    @mock_cloudtrail
    @mock_s3
    def test_bucket_not_logging(self):
        cloudtrail_client_us_east_1 = client("cloudtrail", region_name="us-east-1")
        s3_client_us_east_1 = client("s3", region_name="us-east-1")
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        trail_us = cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=False
        )

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ):
            with mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_logs_s3_bucket_access_logging_enabled.s3_client",
                new=S3(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_logs_s3_bucket_access_logging_enabled import (
                    cloudtrail_logs_s3_bucket_access_logging_enabled,
                )

                check = cloudtrail_logs_s3_bucket_access_logging_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert search(
                    "S3 bucket access logging is not enabled for bucket",
                    result[0].status_extended,
                )
                assert result[0].resource_id == trail_name_us
                assert result[0].resource_arn == trail_us["TrailARN"]

    @mock_cloudtrail
    @mock_s3
    def test_bucket_logging(self):
        cloudtrail_client_us_east_1 = client("cloudtrail", region_name="us-east-1")
        s3_client_us_east_1 = client("s3", region_name="us-east-1")
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        logging_bucket = "logging"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name_us,
        )
        s3_client_us_east_1.create_bucket(
            Bucket=logging_bucket,
        )
        trail_us = cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=False
        )
        s3_client_us_east_1.put_bucket_acl(
            Bucket=logging_bucket,
            GrantWrite="uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
            GrantReadACP="uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
        )
        s3_client_us_east_1.put_bucket_logging(
            Bucket=bucket_name_us,
            BucketLoggingStatus={
                "LoggingEnabled": {
                    "TargetBucket": logging_bucket,
                    "TargetPrefix": logging_bucket,
                }
            },
        )

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ):
            with mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_logs_s3_bucket_access_logging_enabled.s3_client",
                new=S3(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_logs_s3_bucket_access_logging_enabled import (
                    cloudtrail_logs_s3_bucket_access_logging_enabled,
                )

                check = cloudtrail_logs_s3_bucket_access_logging_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert search(
                    "S3 bucket access logging is enabled for bucket",
                    result[0].status_extended,
                )
                assert result[0].resource_id == trail_name_us
                assert result[0].resource_arn == trail_us["TrailARN"]
