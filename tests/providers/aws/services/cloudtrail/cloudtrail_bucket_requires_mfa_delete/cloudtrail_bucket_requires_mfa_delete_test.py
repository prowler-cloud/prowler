from unittest import mock
from unittest.mock import patch

import botocore
from boto3 import client, session
from moto import mock_cloudtrail, mock_iam, mock_s3

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.cloudtrail.cloudtrail_service import Cloudtrail
from prowler.providers.aws.services.s3.s3_service import S3

AWS_ACCOUNT_NUMBER = 123456789012
AWS_ACCOUNT_NUMBER_2 = 123456789013

# Mocking Backup Calls
make_api_call = botocore.client.BaseClient._make_api_call


class Test_cloudtrail_bucket_requires_mfa_delete:
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
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
        )
        return audit_info

    def set_mocked_audit_info_cross(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER_2,
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
        )
        return audit_info

    @mock_cloudtrail
    def test_no_trails(self):
        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_bucket_requires_mfa_delete.cloudtrail_bucket_requires_mfa_delete.cloudtrail_client",
                new=Cloudtrail(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudtrail.cloudtrail_bucket_requires_mfa_delete.cloudtrail_bucket_requires_mfa_delete import (
                    cloudtrail_bucket_requires_mfa_delete,
                )

                check = cloudtrail_bucket_requires_mfa_delete()
                result = check.execute()
                assert len(result) == 0

    @mock_cloudtrail
    @mock_s3
    def test_trails_with_no_mfa_bucket(self):
        current_audit_info = self.set_mocked_audit_info()

        cloudtrail_client_us_east_1 = client("cloudtrail", region_name="us-east-1")
        s3_client_us_east_1 = client("s3", region_name="us-east-1")
        trail_name_us = "trail_test_us_with_no_mfa_bucket"
        bucket_name_us = "bucket_test_us_with_no_mfa"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        trail_us = cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=False
        )
        cloudtrail_client_us_east_1.start_logging(Name=trail_name_us)
        cloudtrail_client_us_east_1.get_trail_status(Name=trail_name_us)

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_bucket_requires_mfa_delete.cloudtrail_bucket_requires_mfa_delete.cloudtrail_client",
                new=Cloudtrail(current_audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.cloudtrail.cloudtrail_bucket_requires_mfa_delete.cloudtrail_bucket_requires_mfa_delete.s3_client",
                    new=S3(current_audit_info),
                ):
                    # Test Check
                    from prowler.providers.aws.services.cloudtrail.cloudtrail_bucket_requires_mfa_delete.cloudtrail_bucket_requires_mfa_delete import (
                        cloudtrail_bucket_requires_mfa_delete,
                    )

                    check = cloudtrail_bucket_requires_mfa_delete()
                    result = check.execute()
                    assert len(result) == 1
                    assert result[0].status == "FAIL"
                    assert (
                        result[0].status_extended
                        == f"Trail {trail_name_us} bucket ({bucket_name_us}) has not MFA delete enabled"
                    )
                    assert result[0].resource_id == trail_name_us
                    assert result[0].region == "us-east-1"
                    assert result[0].resource_arn == trail_us["TrailARN"]

    # Create an MFA device is not supported for moto, so we mock the call:
    def mock_make_api_call_getbucketversioning_mfadelete_enabled(
        self, operation_name, kwarg
    ):
        """
        Mock unsoportted AWS API call
        """
        if operation_name == "GetBucketVersioning":
            return {"MFADelete": "Enabled", "Status": "Enabled"}
        return make_api_call(self, operation_name, kwarg)

    @mock_cloudtrail
    @mock_s3
    @mock_iam
    # Patch with mock_make_api_call_getbucketversioning_mfadelete_enabled:
    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_getbucketversioning_mfadelete_enabled,
    )
    def test_trails_with_mfa_bucket(self):
        current_audit_info = self.set_mocked_audit_info()

        cloudtrail_client_us_east_1 = client("cloudtrail", region_name="us-east-1")
        s3_client_us_east_1 = client("s3", region_name="us-east-1")
        trail_name_us = "trail_test_us_with_mfa_bucket"
        bucket_name_us = "bucket_test_us_with_mfa"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        trail_us = cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=False
        )
        cloudtrail_client_us_east_1.start_logging(Name=trail_name_us)
        cloudtrail_client_us_east_1.get_trail_status(Name=trail_name_us)

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_bucket_requires_mfa_delete.cloudtrail_bucket_requires_mfa_delete.cloudtrail_client",
                new=Cloudtrail(current_audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.cloudtrail.cloudtrail_bucket_requires_mfa_delete.cloudtrail_bucket_requires_mfa_delete.s3_client",
                    new=S3(current_audit_info),
                ):
                    # Test Check
                    from prowler.providers.aws.services.cloudtrail.cloudtrail_bucket_requires_mfa_delete.cloudtrail_bucket_requires_mfa_delete import (
                        cloudtrail_bucket_requires_mfa_delete,
                    )

                    check = cloudtrail_bucket_requires_mfa_delete()
                    result = check.execute()
                    assert len(result) == 1
                    assert result[0].status == "PASS"
                    assert (
                        result[0].status_extended
                        == f"Trail {trail_name_us} bucket ({bucket_name_us}) has MFA delete enabled"
                    )
                    assert result[0].resource_id == trail_name_us
                    assert result[0].region == "us-east-1"
                    assert result[0].resource_arn == trail_us["TrailARN"]

    @mock_cloudtrail
    @mock_s3
    def test_trails_with_no_mfa_bucket_cross(self):
        current_audit_info = self.set_mocked_audit_info()

        cloudtrail_client_us_east_1 = client("cloudtrail", region_name="us-east-1")
        s3_client_us_east_1 = client("s3", region_name="us-east-1")
        trail_name_us = "trail_test_us_with_no_mfa_bucket"
        bucket_name_us = "bucket_test_us_with_no_mfa"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        trail_us = cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=False
        )
        cloudtrail_client_us_east_1.start_logging(Name=trail_name_us)
        cloudtrail_client_us_east_1.get_trail_status(Name=trail_name_us)

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_bucket_requires_mfa_delete.cloudtrail_bucket_requires_mfa_delete.cloudtrail_client",
                new=Cloudtrail(current_audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.cloudtrail.cloudtrail_bucket_requires_mfa_delete.cloudtrail_bucket_requires_mfa_delete.s3_client",
                    new=S3(current_audit_info),
                ) as s3_client:
                    # Test Check
                    from prowler.providers.aws.services.cloudtrail.cloudtrail_bucket_requires_mfa_delete.cloudtrail_bucket_requires_mfa_delete import (
                        cloudtrail_bucket_requires_mfa_delete,
                    )

                    # Empty s3 buckets to simulate the bucket is in another account
                    s3_client.buckets = []

                    check = cloudtrail_bucket_requires_mfa_delete()
                    result = check.execute()
                    assert len(result) == 1
                    assert result[0].status == "PASS"
                    assert (
                        result[0].status_extended
                        == f"Trail {trail_name_us} bucket ({bucket_name_us}) is a cross-account bucket in another account out of Prowler's permissions scope, please check it manually"
                    )
                    assert result[0].resource_id == trail_name_us
                    assert result[0].region == "us-east-1"
                    assert result[0].resource_arn == trail_us["TrailARN"]


    @mock_cloudtrail
    @mock_s3
    @mock_iam
    # Patch with mock_make_api_call_getbucketversioning_mfadelete_enabled:
    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_getbucketversioning_mfadelete_enabled,
    )
    def test_trails_with_mfa_bucket_cross(self):
        current_audit_info = self.set_mocked_audit_info()

        cloudtrail_client_us_east_1 = client("cloudtrail", region_name="us-east-1")
        s3_client_us_east_1 = client("s3", region_name="us-east-1")
        trail_name_us = "trail_test_us_with_mfa_bucket"
        bucket_name_us = "bucket_test_us_with_mfa"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        trail_us = cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=False
        )
        cloudtrail_client_us_east_1.start_logging(Name=trail_name_us)
        cloudtrail_client_us_east_1.get_trail_status(Name=trail_name_us)

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_bucket_requires_mfa_delete.cloudtrail_bucket_requires_mfa_delete.cloudtrail_client",
                new=Cloudtrail(current_audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.cloudtrail.cloudtrail_bucket_requires_mfa_delete.cloudtrail_bucket_requires_mfa_delete.s3_client",
                    new=S3(current_audit_info),
                ) as s3_client:
                    # Test Check
                    from prowler.providers.aws.services.cloudtrail.cloudtrail_bucket_requires_mfa_delete.cloudtrail_bucket_requires_mfa_delete import (
                        cloudtrail_bucket_requires_mfa_delete,
                    )

                    # Empty s3 buckets to simulate the bucket is in another account
                    s3_client.buckets = []

                    check = cloudtrail_bucket_requires_mfa_delete()
                    result = check.execute()
                    assert len(result) == 1
                    assert result[0].status == "PASS"
                    assert (
                        result[0].status_extended
                        == f"Trail {trail_name_us} bucket ({bucket_name_us}) is a cross-account bucket in another account out of Prowler's permissions scope, please check it manually"
                    )
                    assert result[0].resource_id == trail_name_us
                    assert result[0].region == "us-east-1"
                    assert result[0].resource_arn == trail_us["TrailARN"]