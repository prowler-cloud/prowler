from re import search
from unittest import mock

from boto3 import client
from moto import mock_s3

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)


class Test_s3_bucket_default_encryption:
    @mock_s3
    def test_bucket_no_encryption(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)

        from prowler.providers.aws.services.s3.s3_service import S3

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_default_encryption.s3_bucket_default_encryption.s3_client",
                new=S3(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_default_encryption.s3_bucket_default_encryption import (
                    s3_bucket_default_encryption,
                )

                check = s3_bucket_default_encryption()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert search(
                    "Server Side Encryption is not configured",
                    result[0].status_extended,
                )
                assert result[0].resource_id == bucket_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:{audit_info.audited_partition}:s3:::{bucket_name_us}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1

    @mock_s3
    def test_bucket_kms_encryption(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name_us, ObjectOwnership="BucketOwnerEnforced"
        )
        sse_config = {
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms",
                        "KMSMasterKeyID": "12345678",
                    }
                }
            ]
        }

        s3_client_us_east_1.put_bucket_encryption(
            Bucket=bucket_name_us, ServerSideEncryptionConfiguration=sse_config
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_default_encryption.s3_bucket_default_encryption.s3_client",
                new=S3(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_default_encryption.s3_bucket_default_encryption import (
                    s3_bucket_default_encryption,
                )

                check = s3_bucket_default_encryption()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert search(
                    "has Server Side Encryption",
                    result[0].status_extended,
                )
                assert result[0].resource_id == bucket_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:{audit_info.audited_partition}:s3:::{bucket_name_us}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1
