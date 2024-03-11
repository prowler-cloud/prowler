from re import search
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)


class Test_s3_bucket_object_versioning:
    @mock_aws
    def test_bucket_no_object_versioning(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)

        from prowler.providers.aws.services.s3.s3_service import S3

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_object_versioning.s3_bucket_object_versioning.s3_client",
                new=S3(audit_info),
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
                    == f"arn:{audit_info.identity.partition}:s3:::{bucket_name_us}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_object_versioning_enabled(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name_us, ObjectOwnership="BucketOwnerEnforced"
        )
        s3_client_us_east_1.put_bucket_versioning(
            Bucket=bucket_name_us,
            VersioningConfiguration={"Status": "Enabled"},
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_object_versioning.s3_bucket_object_versioning.s3_client",
                new=S3(audit_info),
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
                    == f"arn:{audit_info.identity.partition}:s3:::{bucket_name_us}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1
