from re import search
from unittest import mock

from boto3 import client
from moto import mock_s3


class Test_s3_bucket_object_versioning:
    @mock_s3
    def test_bucket_no_object_versioning(self):
        s3_client_us_east_1 = client("s3", region_name="us-east-1")
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.s3.s3_service import S3

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.s3.s3_bucket_object_versioning.s3_bucket_object_versioning.s3_client",
            new=S3(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.s3.s3_bucket_object_versioning.s3_bucket_object_versioning import (
                s3_bucket_object_versioning,
            )

            check = s3_bucket_object_versioning()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "versioning disabled",
                result[0].status_extended,
            )
            assert result[0].resource_id == bucket_name_us
            assert (
                result[0].resource_arn
                == f"arn:{current_audit_info.audited_partition}:s3:::{bucket_name_us}"
            )
            assert result[0].region == "us-east-1"

    @mock_s3
    def test_bucket_object_versioning_enabled(self):
        s3_client_us_east_1 = client("s3", region_name="us-east-1")
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name_us, ObjectOwnership="BucketOwnerEnforced"
        )
        s3_client_us_east_1.put_bucket_versioning(
            Bucket=bucket_name_us,
            VersioningConfiguration={"Status": "Enabled"},
        )
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.s3.s3_service import S3

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.s3.s3_bucket_object_versioning.s3_bucket_object_versioning.s3_client",
            new=S3(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.s3.s3_bucket_object_versioning.s3_bucket_object_versioning import (
                s3_bucket_object_versioning,
            )

            check = s3_bucket_object_versioning()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "versioning enabled",
                result[0].status_extended,
            )
            assert result[0].resource_id == bucket_name_us
            assert (
                result[0].resource_arn
                == f"arn:{current_audit_info.audited_partition}:s3:::{bucket_name_us}"
            )
            assert result[0].region == "us-east-1"
