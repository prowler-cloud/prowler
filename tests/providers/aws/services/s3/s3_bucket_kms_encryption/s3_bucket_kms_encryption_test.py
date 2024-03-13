from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_s3_bucket_kms_encryption:
    @mock_aws
    def test_no_buckets(self):
        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_bucket_kms_encryption.s3_bucket_kms_encryption.s3_client",
            new=S3(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.s3.s3_bucket_kms_encryption.s3_bucket_kms_encryption import (
                s3_bucket_kms_encryption,
            )

            check = s3_bucket_kms_encryption()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_bucket_no_encryption(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_bucket_kms_encryption.s3_bucket_kms_encryption.s3_client",
            new=S3(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.s3.s3_bucket_kms_encryption.s3_bucket_kms_encryption import (
                s3_bucket_kms_encryption,
            )

            check = s3_bucket_kms_encryption()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Server Side Encryption is not configured with kms for S3 Bucket {bucket_name_us}."
            )
            assert result[0].resource_id == bucket_name_us
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
            )
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_no_kms_encryption(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name_us, ObjectOwnership="BucketOwnerEnforced"
        )
        sse_config = {
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256",
                    }
                }
            ]
        }

        s3_client_us_east_1.put_bucket_encryption(
            Bucket=bucket_name_us, ServerSideEncryptionConfiguration=sse_config
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_bucket_kms_encryption.s3_bucket_kms_encryption.s3_client",
            new=S3(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.s3.s3_bucket_kms_encryption.s3_bucket_kms_encryption import (
                s3_bucket_kms_encryption,
            )

            check = s3_bucket_kms_encryption()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Server Side Encryption is not configured with kms for S3 Bucket {bucket_name_us}."
            )
            assert result[0].resource_id == bucket_name_us
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
            )
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_kms_encryption(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name_us, ObjectOwnership="BucketOwnerEnforced"
        )
        kms_encryption = "aws:kms"
        sse_config = {
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": f"{kms_encryption}",
                        "KMSMasterKeyID": "12345678",
                    }
                }
            ]
        }

        s3_client_us_east_1.put_bucket_encryption(
            Bucket=bucket_name_us, ServerSideEncryptionConfiguration=sse_config
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_kms_encryption.s3_bucket_kms_encryption.s3_client",
                new=S3(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_kms_encryption.s3_bucket_kms_encryption import (
                    s3_bucket_kms_encryption,
                )

                check = s3_bucket_kms_encryption()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"S3 Bucket {bucket_name_us} has Server Side Encryption with {kms_encryption}."
                )
                assert result[0].resource_id == bucket_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                )
                assert result[0].resource_tags == []
                assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_kms_dsse_encryption(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name_us, ObjectOwnership="BucketOwnerEnforced"
        )
        kms_encryption = "aws:kms:dsse"
        sse_config = {
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": f"{kms_encryption}",
                        "KMSMasterKeyID": "12345678",
                    }
                }
            ]
        }

        s3_client_us_east_1.put_bucket_encryption(
            Bucket=bucket_name_us, ServerSideEncryptionConfiguration=sse_config
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_kms_encryption.s3_bucket_kms_encryption.s3_client",
                new=S3(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_kms_encryption.s3_bucket_kms_encryption import (
                    s3_bucket_kms_encryption,
                )

                check = s3_bucket_kms_encryption()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"S3 Bucket {bucket_name_us} has Server Side Encryption with {kms_encryption}."
                )
                assert result[0].resource_id == bucket_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                )
                assert result[0].resource_tags == []
                assert result[0].region == AWS_REGION_US_EAST_1
