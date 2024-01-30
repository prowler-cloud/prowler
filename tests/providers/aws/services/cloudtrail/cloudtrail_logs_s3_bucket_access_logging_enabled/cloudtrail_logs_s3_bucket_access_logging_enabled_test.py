from re import search
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)


class Test_cloudtrail_logs_s3_bucket_access_logging_enabled:
    @mock_aws
    @mock_aws
    def test_no_trails(self):
        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=set_mocked_aws_audit_info([AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_client",
            new=Cloudtrail(
                set_mocked_aws_audit_info([AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1])
            ),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_logs_s3_bucket_access_logging_enabled.s3_client",
            new=S3(
                set_mocked_aws_audit_info([AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1])
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_logs_s3_bucket_access_logging_enabled import (
                cloudtrail_logs_s3_bucket_access_logging_enabled,
            )

            check = cloudtrail_logs_s3_bucket_access_logging_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    @mock_aws
    def test_bucket_not_logging(self):
        cloudtrail_client_us_east_1 = client(
            "cloudtrail", region_name=AWS_REGION_US_EAST_1
        )
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        trail_us = cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=False
        )

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=set_mocked_aws_audit_info([AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_client",
            new=Cloudtrail(
                set_mocked_aws_audit_info([AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1])
            ),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_logs_s3_bucket_access_logging_enabled.s3_client",
            new=S3(
                set_mocked_aws_audit_info([AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1])
            ),
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
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    @mock_aws
    def test_bucket_logging(self):
        cloudtrail_client_us_east_1 = client(
            "cloudtrail", region_name=AWS_REGION_US_EAST_1
        )
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
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

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=set_mocked_aws_audit_info([AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_client",
            new=Cloudtrail(
                set_mocked_aws_audit_info([AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1])
            ),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_logs_s3_bucket_access_logging_enabled.s3_client",
            new=S3(
                set_mocked_aws_audit_info([AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1])
            ),
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
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    @mock_aws
    def test_bucket_cross_account(self):
        cloudtrail_client_us_east_1 = client(
            "cloudtrail", region_name=AWS_REGION_US_EAST_1
        )
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        trail_us = cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=False
        )

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=set_mocked_aws_audit_info([AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_client",
            new=Cloudtrail(
                set_mocked_aws_audit_info([AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1])
            ),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_logs_s3_bucket_access_logging_enabled.s3_client",
            new=S3(
                set_mocked_aws_audit_info([AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1])
            ),
        ) as s3_client:
            # Test Check
            from prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_logs_s3_bucket_access_logging_enabled import (
                cloudtrail_logs_s3_bucket_access_logging_enabled,
            )

            # Empty s3 buckets to simulate the bucket is in another account
            s3_client.buckets = []

            check = cloudtrail_logs_s3_bucket_access_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "INFO"
            assert search(
                "in another account out of Prowler's permissions scope, please check it manually",
                result[0].status_extended,
            )
            assert result[0].resource_id == trail_name_us
            assert result[0].resource_arn == trail_us["TrailARN"]
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1
