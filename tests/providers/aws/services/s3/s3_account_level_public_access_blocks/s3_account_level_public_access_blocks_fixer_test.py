from unittest import mock

from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_s3_account_level_public_access_block_fixer:
    @mock_aws
    def test_bucket_account_public_block_fixer(self):
        from prowler.providers.aws.services.s3.s3_service import S3Control

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_account_level_public_access_blocks.s3_account_level_public_access_blocks_fixer.s3control_client",
            new=S3Control(aws_provider),
        ):
            from prowler.providers.aws.services.s3.s3_account_level_public_access_blocks.s3_account_level_public_access_blocks_fixer import (
                fixer,
            )

            # By default, the account has not public access blocked
            assert fixer(resource_id=AWS_ACCOUNT_NUMBER)
