from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_s3_account_level_public_access_blocks:
    @mock_aws
    def test_bucket_account_public_block(self):
        # Generate S3Control Client
        s3control_client = client("s3control", region_name=AWS_REGION_US_EAST_1)
        s3control_client.put_public_access_block(
            AccountId=AWS_ACCOUNT_NUMBER,
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
            "prowler.providers.aws.services.s3.s3_account_level_public_access_blocks.s3_account_level_public_access_blocks.s3_client",
            new=S3(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_account_level_public_access_blocks.s3_account_level_public_access_blocks.s3control_client",
            new=S3Control(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.s3.s3_account_level_public_access_blocks.s3_account_level_public_access_blocks import (
                s3_account_level_public_access_blocks,
            )

            check = s3_account_level_public_access_blocks()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Block Public Access is configured for the account {AWS_ACCOUNT_NUMBER}."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:s3:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:account"
            )
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_without_account_public_block(self):
        # Generate S3Control Client
        s3control_client = client("s3control", region_name=AWS_REGION_US_EAST_1)
        s3control_client.put_public_access_block(
            AccountId=AWS_ACCOUNT_NUMBER,
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
            "prowler.providers.aws.services.s3.s3_account_level_public_access_blocks.s3_account_level_public_access_blocks.s3_client",
            new=S3(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_account_level_public_access_blocks.s3_account_level_public_access_blocks.s3control_client",
            new=S3Control(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.s3.s3_account_level_public_access_blocks.s3_account_level_public_access_blocks import (
                s3_account_level_public_access_blocks,
            )

            check = s3_account_level_public_access_blocks()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Block Public Access is not configured for the account {AWS_ACCOUNT_NUMBER}."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:s3:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:account"
            )
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_without_account_public_block_ignoring(self):
        # Generate S3Control Client
        s3control_client = client("s3control", region_name=AWS_REGION_US_EAST_1)
        s3control_client.put_public_access_block(
            AccountId=AWS_ACCOUNT_NUMBER,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        aws_provider._scan_unused_services = False

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_account_level_public_access_blocks.s3_account_level_public_access_blocks.s3_client",
            new=S3(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_account_level_public_access_blocks.s3_account_level_public_access_blocks.s3control_client",
            new=S3Control(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.s3.s3_account_level_public_access_blocks.s3_account_level_public_access_blocks import (
                s3_account_level_public_access_blocks,
            )

            check = s3_account_level_public_access_blocks()
            result = check.execute()

            assert len(result) == 0
