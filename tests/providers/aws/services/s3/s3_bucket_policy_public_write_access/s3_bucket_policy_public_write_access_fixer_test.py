from json import dumps, loads
from unittest import mock

import pytest
from boto3 import client
from botocore.client import BaseClient
from botocore.exceptions import ClientError
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

_orig_make_api_call = BaseClient._make_api_call


def mock_make_api_call_block_public_policy(self, operation_name, kwarg):
    """Reject public bucket policies like S3 does with BlockPublicPolicy enabled, since moto does not enforce it"""
    if operation_name == "PutBucketPolicy" and '"Principal": "*"' in kwarg[
        "Policy"
    ].replace('"Effect": "Deny", "Principal": "*"', ""):
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
            operation_name,
        )
    return _orig_make_api_call(self, operation_name, kwarg)


class Test_s3_bucket_policy_public_write_access_fixer:
    @mock_aws
    def test_bucket_public_write_policy(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name_us, ObjectOwnership="BucketOwnerEnforced"
        )
        public_write_policy = '{"Version": "2012-10-17","Id": "PutObjPolicy","Statement": [{"Sid": "PublicWritePolicy","Effect": "Allow","Principal": "*","Action": "s3:PutObject","Resource": "arn:aws:s3:::bucket_test_us/*"}]}'
        s3_client_us_east_1.put_bucket_policy(
            Bucket=bucket_name_us,
            Policy=public_write_policy,
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_policy_public_write_access.s3_bucket_policy_public_write_access_fixer.s3_client",
                new=S3(aws_provider),
            ),
        ):
            # Test Fixer
            from prowler.providers.aws.services.s3.s3_bucket_policy_public_write_access.s3_bucket_policy_public_write_access_fixer import (
                fixer,
            )

            assert fixer(bucket_name_us, AWS_REGION_US_EAST_1)
            with pytest.raises(s3_client_us_east_1.exceptions.ClientError) as error:
                s3_client_us_east_1.get_bucket_policy(Bucket=bucket_name_us)
            assert error.value.response["Error"]["Code"] == "NoSuchBucketPolicy"

    @mock_aws
    def test_bucket_public_write_policy_error(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name_us, ObjectOwnership="BucketOwnerEnforced"
        )
        public_write_policy = '{"Version": "2012-10-17","Id": "PutObjPolicy","Statement": [{"Sid": "PublicWritePolicy","Effect": "Allow","Principal": "*","Action": "s3:PutObject","Resource": "arn:aws:s3:::bucket_test_us/*"}]}'
        s3_client_us_east_1.put_bucket_policy(
            Bucket=bucket_name_us,
            Policy=public_write_policy,
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_policy_public_write_access.s3_bucket_policy_public_write_access_fixer.s3_client",
                new=S3(aws_provider),
            ),
        ):
            # Test Fixer
            from prowler.providers.aws.services.s3.s3_bucket_policy_public_write_access.s3_bucket_policy_public_write_access_fixer import (
                fixer,
            )

            assert not fixer("bucket_name_non_existing", AWS_REGION_US_EAST_1)

    @mock_aws
    def test_bucket_public_write_policy_keeps_non_public_statements(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name_us, ObjectOwnership="BucketOwnerEnforced"
        )
        cloudfront_statement = {
            "Sid": "AllowCloudFrontRead",
            "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket_name_us}/*",
            "Condition": {"StringEquals": {"AWS:SourceAccount": AWS_ACCOUNT_NUMBER}},
        }
        deny_statement = {
            "Sid": "DenyInsecureTransport",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [
                f"arn:aws:s3:::{bucket_name_us}",
                f"arn:aws:s3:::{bucket_name_us}/*",
            ],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        }
        s3_client_us_east_1.put_bucket_policy(
            Bucket=bucket_name_us,
            Policy=dumps(
                {
                    "Version": "2012-10-17",
                    "Id": "PutObjPolicy",
                    "Statement": [
                        {
                            "Sid": "PublicWritePolicy",
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "s3:PutObject",
                            "Resource": f"arn:aws:s3:::{bucket_name_us}/*",
                        },
                        cloudfront_statement,
                        deny_statement,
                    ],
                }
            ),
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_policy_public_write_access.s3_bucket_policy_public_write_access_fixer.s3_client",
                new=S3(aws_provider),
            ),
        ):
            # Test Fixer
            from prowler.providers.aws.services.s3.s3_bucket_policy_public_write_access.s3_bucket_policy_public_write_access_fixer import (
                fixer,
            )

            assert fixer(bucket_name_us, AWS_REGION_US_EAST_1)

            policy = loads(
                s3_client_us_east_1.get_bucket_policy(Bucket=bucket_name_us)["Policy"]
            )
            assert policy["Id"] == "PutObjPolicy"
            assert policy["Statement"] == [cloudfront_statement, deny_statement]

    @mock_aws
    def test_bucket_public_write_policy_block_public_policy(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name_us, ObjectOwnership="BucketOwnerEnforced"
        )
        deny_statement = {
            "Sid": "DenyInsecureTransport",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": f"arn:aws:s3:::{bucket_name_us}/*",
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        }
        s3_client_us_east_1.put_bucket_policy(
            Bucket=bucket_name_us,
            Policy=dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "PublicRead",
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "s3:GetObject",
                            "Resource": f"arn:aws:s3:::{bucket_name_us}/*",
                        },
                        {
                            "Sid": "PublicWritePolicy",
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "s3:PutObject",
                            "Resource": f"arn:aws:s3:::{bucket_name_us}/*",
                        },
                        deny_statement,
                    ],
                }
            ),
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_policy_public_write_access.s3_bucket_policy_public_write_access_fixer.s3_client",
                new=S3(aws_provider),
            ),
            mock.patch(
                "botocore.client.BaseClient._make_api_call",
                new=mock_make_api_call_block_public_policy,
            ),
        ):
            # Test Fixer
            from prowler.providers.aws.services.s3.s3_bucket_policy_public_write_access.s3_bucket_policy_public_write_access_fixer import (
                fixer,
            )

            assert fixer(bucket_name_us, AWS_REGION_US_EAST_1)

            policy = loads(
                s3_client_us_east_1.get_bucket_policy(Bucket=bucket_name_us)["Policy"]
            )
            assert policy["Statement"] == [deny_statement]
