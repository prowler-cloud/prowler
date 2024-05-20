from re import search
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_s3_bucket_object_lock:
    @mock_aws
    def test_no_buckets(self):
        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_object_lock.s3_bucket_object_lock.s3_client",
                new=S3(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_object_lock.s3_bucket_object_lock import (
                    s3_bucket_object_lock,
                )

                check = s3_bucket_object_lock()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_bucket_no_object_lock(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_object_lock.s3_bucket_object_lock.s3_client",
                new=S3(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_object_lock.s3_bucket_object_lock import (
                    s3_bucket_object_lock,
                )

                check = s3_bucket_object_lock()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert search(
                    "Object Lock disabled",
                    result[0].status_extended,
                )
                assert result[0].resource_id == bucket_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_tags == []

    @mock_aws
    def test_bucket_object_lock_enabled(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name_us,
            ObjectOwnership="BucketOwnerEnforced",
            ObjectLockEnabledForBucket=True,
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_object_lock.s3_bucket_object_lock.s3_client",
                new=S3(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_object_lock.s3_bucket_object_lock import (
                    s3_bucket_object_lock,
                )

                check = s3_bucket_object_lock()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert search(
                    "Object Lock enabled",
                    result[0].status_extended,
                )
                assert result[0].resource_id == bucket_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_tags == []
