from re import search
from unittest import mock

from boto3 import client, session
from moto import mock_cloudtrail, mock_s3

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata

AWS_ACCOUNT_NUMBER = "123456789012"


class Test_cloudtrail_logs_s3_bucket_access_logging_enabled:
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
            audited_regions=["us-east-1", "eu-west-1"],
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
    def test_bucket_not_logging(self):
        cloudtrail_client_us_east_1 = client("cloudtrail", region_name="us-east-1")
        s3_client_us_east_1 = client("s3", region_name="us-east-1")
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
            new=self.set_mocked_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_client",
            new=Cloudtrail(self.set_mocked_audit_info()),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_logs_s3_bucket_access_logging_enabled.s3_client",
            new=S3(self.set_mocked_audit_info()),
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

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=self.set_mocked_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_client",
            new=Cloudtrail(self.set_mocked_audit_info()),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_logs_s3_bucket_access_logging_enabled.s3_client",
            new=S3(self.set_mocked_audit_info()),
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

    @mock_cloudtrail
    @mock_s3
    def test_bucket_cross_account(self):
        cloudtrail_client_us_east_1 = client("cloudtrail", region_name="us-east-1")
        s3_client_us_east_1 = client("s3", region_name="us-east-1")
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
            new=self.set_mocked_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_client",
            new=Cloudtrail(self.set_mocked_audit_info()),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_logs_s3_bucket_access_logging_enabled.s3_client",
            new=S3(self.set_mocked_audit_info()),
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
            assert result[0].status == "FAIL"
            assert search(
                "in another account out of Prowler's permissions scope, please check it manually",
                result[0].status_extended,
            )
            assert result[0].resource_id == trail_name_us
            assert result[0].resource_arn == trail_us["TrailARN"]
