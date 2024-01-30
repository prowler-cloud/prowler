from unittest import mock
from unittest.mock import patch

import botocore
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.cloudtrail.cloudtrail_service import Cloudtrail
from prowler.providers.aws.services.s3.s3_service import S3
from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)

# Mocking Backup Calls
make_api_call = botocore.client.BaseClient._make_api_call


class Test_cloudtrail_bucket_requires_mfa_delete:
    @mock_aws
    def test_no_trails(self):
        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
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

    @mock_aws
    @mock_aws
    def test_trails_with_no_mfa_bucket(self):
        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        cloudtrail_client_us_east_1 = client(
            "cloudtrail", region_name=AWS_REGION_US_EAST_1
        )
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
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
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_bucket_requires_mfa_delete.cloudtrail_bucket_requires_mfa_delete.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ), mock.patch(
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
                == f"Trail {trail_name_us} bucket ({bucket_name_us}) does not have MFA delete enabled."
            )
            assert result[0].resource_id == trail_name_us
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_arn == trail_us["TrailARN"]
            assert result[0].resource_tags == []

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

    @mock_aws
    @mock_aws
    @mock_aws
    # Patch with mock_make_api_call_getbucketversioning_mfadelete_enabled:
    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_getbucketversioning_mfadelete_enabled,
    )
    def test_trails_with_mfa_bucket(self):
        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        cloudtrail_client_us_east_1 = client(
            "cloudtrail", region_name=AWS_REGION_US_EAST_1
        )
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
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
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_bucket_requires_mfa_delete.cloudtrail_bucket_requires_mfa_delete.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ), mock.patch(
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
                == f"Trail {trail_name_us} bucket ({bucket_name_us}) has MFA delete enabled."
            )
            assert result[0].resource_id == trail_name_us
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_arn == trail_us["TrailARN"]
            assert result[0].resource_tags == []

    @mock_aws
    @mock_aws
    def test_trails_with_no_mfa_bucket_cross(self):
        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        cloudtrail_client_us_east_1 = client(
            "cloudtrail", region_name=AWS_REGION_US_EAST_1
        )
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
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
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_bucket_requires_mfa_delete.cloudtrail_bucket_requires_mfa_delete.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ), mock.patch(
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
            assert result[0].status == "INFO"
            assert (
                result[0].status_extended
                == f"Trail {trail_name_us} bucket ({bucket_name_us}) is a cross-account bucket in another account out of Prowler's permissions scope, please check it manually."
            )
            assert result[0].resource_id == trail_name_us
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_arn == trail_us["TrailARN"]
            assert result[0].resource_tags == []

    @mock_aws
    @mock_aws
    @mock_aws
    # Patch with mock_make_api_call_getbucketversioning_mfadelete_enabled:
    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_getbucketversioning_mfadelete_enabled,
    )
    def test_trails_with_mfa_bucket_cross(self):
        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        cloudtrail_client_us_east_1 = client(
            "cloudtrail", region_name=AWS_REGION_US_EAST_1
        )
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
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
        ), mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_bucket_requires_mfa_delete.cloudtrail_bucket_requires_mfa_delete.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ), mock.patch(
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
            assert result[0].status == "INFO"
            assert (
                result[0].status_extended
                == f"Trail {trail_name_us} bucket ({bucket_name_us}) is a cross-account bucket in another account out of Prowler's permissions scope, please check it manually."
            )
            assert result[0].resource_id == trail_name_us
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_arn == trail_us["TrailARN"]
            assert result[0].resource_tags == []
