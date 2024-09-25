import json
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_s3_bucket_cross_account_access:
    @mock_aws
    def test_no_buckets(self):
        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_cross_account_access.s3_bucket_cross_account_access.s3_client",
                new=S3(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_cross_account_access.s3_bucket_cross_account_access import (
                    s3_bucket_cross_account_access,
                )

                check = s3_bucket_cross_account_access()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_bucket_no_policy(self):
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client.create_bucket(Bucket=bucket_name_us)

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_cross_account_access.s3_bucket_cross_account_access.s3_client",
                new=S3(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_cross_account_access.s3_bucket_cross_account_access import (
                    s3_bucket_cross_account_access,
                )

                check = s3_bucket_cross_account_access()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"S3 Bucket {bucket_name_us} does not have a bucket policy."
                )
                assert result[0].resource_id == bucket_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_policy_allow_delete(self):
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        delete_bucket_policy = "s3:DeleteBucketPolicy"
        bucket_name_us = "bucket_test_us"
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": delete_bucket_policy,
                    "Resource": "arn:aws:s3:::*",
                }
            ],
        }
        s3_client.create_bucket(Bucket=bucket_name_us)
        s3_client.put_bucket_policy(
            Bucket=bucket_name_us,
            Policy=json.dumps(policy),
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_cross_account_access.s3_bucket_cross_account_access.s3_client",
                new=S3(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_cross_account_access.s3_bucket_cross_account_access import (
                    s3_bucket_cross_account_access,
                )

                check = s3_bucket_cross_account_access()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"S3 Bucket {bucket_name_us} has a bucket policy allowing cross account access."
                )
                assert result[0].resource_id == bucket_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_policy_allow_multiple_other_accounts(self):
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        put_encryption_configuration = "s3:PutEncryptionConfiguration"
        put_bucket_policy = "s3:PutBucketPolicy"
        bucket_name_us = "bucket_test_us"
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::*:root"},
                    "Action": [
                        put_encryption_configuration,
                        put_bucket_policy,
                    ],
                    "Resource": "arn:aws:s3:::*",
                }
            ],
        }
        s3_client.create_bucket(Bucket=bucket_name_us)
        s3_client.put_bucket_policy(
            Bucket=bucket_name_us,
            Policy=json.dumps(policy),
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_cross_account_access.s3_bucket_cross_account_access.s3_client",
                new=S3(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_cross_account_access.s3_bucket_cross_account_access import (
                    s3_bucket_cross_account_access,
                )

                check = s3_bucket_cross_account_access()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"S3 Bucket {bucket_name_us} has a bucket policy allowing cross account access."
                )
                assert result[0].resource_id == bucket_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_policy_allow_same_account(self):
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        delete_bucket_policy = "s3:DeleteBucketPolicy"
        bucket_name_us = "bucket_test_us"
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"},
                    "Action": delete_bucket_policy,
                    "Resource": "arn:aws:s3:::*",
                }
            ],
        }
        s3_client.create_bucket(Bucket=bucket_name_us)
        s3_client.put_bucket_policy(
            Bucket=bucket_name_us,
            Policy=json.dumps(policy),
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_cross_account_access.s3_bucket_cross_account_access.s3_client",
                new=S3(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_cross_account_access.s3_bucket_cross_account_access import (
                    s3_bucket_cross_account_access,
                )

                check = s3_bucket_cross_account_access()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"S3 Bucket {bucket_name_us} has a bucket policy but it does not allow cross account access."
                )
                assert result[0].resource_id == bucket_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1
