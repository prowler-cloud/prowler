from re import search
from unittest import mock

from boto3 import client
from moto import mock_cloudtrail, mock_s3


class Test_cloudtrail_logs_s3_bucket_is_not_publicly_accessible:
    @mock_cloudtrail
    @mock_s3
    def test_trail_bucket_no_acl(self):
        cloudtrail_client = client("cloudtrail", region_name="us-east-1")
        s3_client = client("s3", region_name="us-east-1")
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client.create_bucket(Bucket=bucket_name_us)
        trail_us = cloudtrail_client.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=False
        )
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_is_not_publicly_accessible.cloudtrail_logs_s3_bucket_is_not_publicly_accessible.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ):
            with mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_access_logging_enabled.cloudtrail_logs_s3_bucket_access_logging_enabled.s3_client",
                new=S3(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_is_not_publicly_accessible.cloudtrail_logs_s3_bucket_is_not_publicly_accessible import (
                    cloudtrail_logs_s3_bucket_is_not_publicly_accessible,
                )

                check = cloudtrail_logs_s3_bucket_is_not_publicly_accessible()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert result[0].resource_id == trail_name_us
                assert result[0].resource_arn == trail_us["TrailARN"]
                assert search(
                    result[0].status_extended,
                    f"S3 Bucket {bucket_name_us} from single region trail {trail_name_us} is not publicly accessible",
                )

    @mock_cloudtrail
    @mock_s3
    def test_trail_bucket_public_acl(self):
        s3_client = client("s3", region_name="us-east-1")
        bucket_name_us = "bucket_test_us"
        s3_client.create_bucket(Bucket=bucket_name_us)
        s3_client.put_bucket_acl(
            AccessControlPolicy={
                "Grants": [
                    {
                        "Grantee": {
                            "DisplayName": "test",
                            "EmailAddress": "",
                            "ID": "test_ID",
                            "Type": "Group",
                            "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                        },
                        "Permission": "READ",
                    },
                ],
                "Owner": {"DisplayName": "test", "ID": "test_id"},
            },
            Bucket=bucket_name_us,
        )

        trail_name_us = "trail_test_us"
        cloudtrail_client = client("cloudtrail", region_name="us-east-1")
        trail_us = cloudtrail_client.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=False
        )

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_is_not_publicly_accessible.cloudtrail_logs_s3_bucket_is_not_publicly_accessible.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ):
            with mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_is_not_publicly_accessible.cloudtrail_logs_s3_bucket_is_not_publicly_accessible.s3_client",
                new=S3(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_is_not_publicly_accessible.cloudtrail_logs_s3_bucket_is_not_publicly_accessible import (
                    cloudtrail_logs_s3_bucket_is_not_publicly_accessible,
                )

                check = cloudtrail_logs_s3_bucket_is_not_publicly_accessible()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert result[0].resource_id == trail_name_us
                assert result[0].resource_arn == trail_us["TrailARN"]
                assert search(
                    result[0].status_extended,
                    f"S3 Bucket {bucket_name_us} from single region trail {trail_name_us} is publicly accessible",
                )

    @mock_cloudtrail
    @mock_s3
    def test_trail_bucket_not_public_acl(self):
        cloudtrail_client = client("cloudtrail", region_name="us-east-1")
        s3_client = client("s3", region_name="us-east-1")
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client.create_bucket(Bucket=bucket_name_us)
        trail_us = cloudtrail_client.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=False
        )

        s3_client.put_bucket_acl(
            AccessControlPolicy={
                "Grants": [
                    {
                        "Grantee": {
                            "DisplayName": "test",
                            "EmailAddress": "",
                            "ID": "test_ID",
                            "Type": "CanonicalUser",
                            "URI": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                        },
                        "Permission": "READ",
                    },
                ],
                "Owner": {"DisplayName": "test", "ID": "test_id"},
            },
            Bucket=bucket_name_us,
        )
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_is_not_publicly_accessible.cloudtrail_logs_s3_bucket_is_not_publicly_accessible.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ):
            with mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_is_not_publicly_accessible.cloudtrail_logs_s3_bucket_is_not_publicly_accessible.s3_client",
                new=S3(current_audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_is_not_publicly_accessible.cloudtrail_logs_s3_bucket_is_not_publicly_accessible import (
                    cloudtrail_logs_s3_bucket_is_not_publicly_accessible,
                )

                check = cloudtrail_logs_s3_bucket_is_not_publicly_accessible()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert result[0].resource_id == trail_name_us
                assert result[0].resource_arn == trail_us["TrailARN"]
                assert search(
                    result[0].status_extended,
                    f"S3 Bucket {bucket_name_us} from single region trail {trail_name_us} is not publicly accessible",
                )

    @mock_cloudtrail
    @mock_s3
    def test_trail_bucket_cross_account(self):
        cloudtrail_client = client("cloudtrail", region_name="us-east-1")
        s3_client = client("s3", region_name="us-east-1")
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client.create_bucket(Bucket=bucket_name_us)
        trail_us = cloudtrail_client.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=False
        )

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_is_not_publicly_accessible.cloudtrail_logs_s3_bucket_is_not_publicly_accessible.cloudtrail_client",
            new=Cloudtrail(current_audit_info),
        ):
            with mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_is_not_publicly_accessible.cloudtrail_logs_s3_bucket_is_not_publicly_accessible.s3_client",
                new=S3(current_audit_info),
            ) as s3_client:
                # Test Check
                from prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_is_not_publicly_accessible.cloudtrail_logs_s3_bucket_is_not_publicly_accessible import (
                    cloudtrail_logs_s3_bucket_is_not_publicly_accessible,
                )

                # Empty s3 buckets to simulate the bucket is in another account
                s3_client.buckets = []

                check = cloudtrail_logs_s3_bucket_is_not_publicly_accessible()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert result[0].resource_id == trail_name_us
                assert result[0].resource_arn == trail_us["TrailARN"]
                assert search(
                    "is a cross-account bucket in another account out of Prowler's permissions scope",
                    result[0].status_extended,
                )
