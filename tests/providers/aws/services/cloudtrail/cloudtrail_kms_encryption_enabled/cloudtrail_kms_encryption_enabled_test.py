from re import search
from unittest import mock

from boto3 import client, session
from moto import mock_cloudtrail, mock_kms, mock_s3

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata

AWS_ACCOUNT_NUMBER = "123456789012"


class Test_cloudtrail_kms_encryption_enabled:
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
    def test_trail_no_kms(self):
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

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=self.set_mocked_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_kms_encryption_enabled.cloudtrail_kms_encryption_enabled.cloudtrail_client",
            new=Cloudtrail(self.set_mocked_audit_info()),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudtrail.cloudtrail_kms_encryption_enabled.cloudtrail_kms_encryption_enabled import (
                cloudtrail_kms_encryption_enabled,
            )

            check = cloudtrail_kms_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "has encryption disabled",
                result[0].status_extended,
            )
            assert result[0].resource_id == trail_name_us
            assert result[0].resource_arn == trail_us["TrailARN"]

    @mock_cloudtrail
    @mock_s3
    @mock_kms
    def test_trail_kms(self):
        cloudtrail_client_us_east_1 = client("cloudtrail", region_name="us-east-1")
        s3_client_us_east_1 = client("s3", region_name="us-east-1")
        kms_client = client("kms", region_name="us-east-1")
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        key_arn = kms_client.create_key()["KeyMetadata"]["Arn"]
        trail_us = cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us,
            S3BucketName=bucket_name_us,
            IsMultiRegionTrail=False,
            KmsKeyId=key_arn,
        )

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=self.set_mocked_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_kms_encryption_enabled.cloudtrail_kms_encryption_enabled.cloudtrail_client",
            new=Cloudtrail(self.set_mocked_audit_info()),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudtrail.cloudtrail_kms_encryption_enabled.cloudtrail_kms_encryption_enabled import (
                cloudtrail_kms_encryption_enabled,
            )

            check = cloudtrail_kms_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "has encryption enabled",
                result[0].status_extended,
            )
            assert result[0].resource_id == trail_name_us
            assert result[0].resource_arn == trail_us["TrailARN"]
