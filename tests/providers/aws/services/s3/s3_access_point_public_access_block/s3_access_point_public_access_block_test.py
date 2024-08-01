from unittest import mock
from unittest.mock import patch

import botocore
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

# Original botocore _make_api_call function
orig = botocore.client.BaseClient._make_api_call


# Mocked botocore _make_api_call function
def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListAccessPoints":
        return {
            "AccessPointList": [
                {
                    "Name": "test-access-point",
                    "Bucket": "test-bucket",
                }
            ]
        }

    return orig(self, operation_name, kwarg)


class Test_s3_access_point_public_access_block:
    @mock_aws
    def test_no_access_points(self):
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_access_point_public_access_block.s3_access_point_public_access_block.s3_client",
            new=S3(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_access_point_public_access_block.s3_access_point_public_access_block.s3control_client",
            new=S3Control(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.s3.s3_access_point_public_access_block.s3_access_point_public_access_block import (
                s3_access_point_public_access_block,
            )

            check = s3_access_point_public_access_block()
            result = check.execute()

            assert len(result) == 0

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @mock_aws
    def test_access_points_with_public_access_block(self):
        # Generate S3 Client
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)

        # Generate Bucket
        s3_client_us_east_1.create_bucket(
            Bucket="test-bucket", ObjectOwnership="BucketOwnerEnforced"
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
            Bucket="test-bucket", ServerSideEncryptionConfiguration=sse_config
        )

        # Generate S3Control Client
        s3control_client = client("s3control", region_name=AWS_REGION_US_EAST_1)

        s3control_client.create_access_point(
            AccountId=AWS_ACCOUNT_NUMBER,
            Name="test-access-point",
            Bucket="test-bucket",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_access_point_public_access_block.s3_access_point_public_access_block.s3_client",
            new=S3(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_access_point_public_access_block.s3_access_point_public_access_block.s3control_client",
            new=S3Control(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.s3.s3_access_point_public_access_block.s3_access_point_public_access_block import (
                s3_access_point_public_access_block,
            )

            check = s3_access_point_public_access_block()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"All Access Points in account {AWS_ACCOUNT_NUMBER} have Public Access Block enabled."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:s3:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:account"
            )
            assert result[0].region == AWS_REGION_US_EAST_1

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @mock_aws
    def test_access_points_without_public_access_block(self):
        # Generate S3 Client
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)

        # Generate Bucket
        s3_client_us_east_1.create_bucket(
            Bucket="test-bucket", ObjectOwnership="BucketOwnerEnforced"
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
            Bucket="test-bucket", ServerSideEncryptionConfiguration=sse_config
        )

        # Generate S3Control Client
        s3control_client = client("s3control", region_name=AWS_REGION_US_EAST_1)
        s3control_client.create_access_point(
            AccountId=AWS_ACCOUNT_NUMBER,
            Name="test-access-point",
            Bucket="test-bucket",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_access_point_public_access_block.s3_access_point_public_access_block.s3_client",
            new=S3(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_access_point_public_access_block.s3_access_point_public_access_block.s3control_client",
            new=S3Control(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.s3.s3_access_point_public_access_block.s3_access_point_public_access_block import (
                s3_access_point_public_access_block,
            )

            check = s3_access_point_public_access_block()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Account {AWS_ACCOUNT_NUMBER} has at least one Access Point where Public Access Block is disabled."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:s3:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:account"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
