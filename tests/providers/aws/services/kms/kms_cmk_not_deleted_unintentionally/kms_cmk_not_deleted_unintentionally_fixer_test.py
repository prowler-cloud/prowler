from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_kms_cmk_not_deleted_unintentionally_fixer:
    @mock_aws
    def test_kms_cmk_deleted_unintentionally(self):
        from prowler.providers.aws.services.kms.kms_service import KMS

        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = kms_client.create_key()["KeyMetadata"]
        kms_client.schedule_key_deletion(KeyId=key["KeyId"])

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_cmk_not_deleted_unintentionally.kms_cmk_not_deleted_unintentionally_fixer.kms_client",
            new=KMS(aws_provider),
        ):
            from prowler.providers.aws.services.kms.kms_cmk_not_deleted_unintentionally.kms_cmk_not_deleted_unintentionally_fixer import (
                fixer,
            )

            assert fixer(key["KeyId"], AWS_REGION_US_EAST_1)

    @mock_aws
    def test_kms_cmk_enabled(self):
        from prowler.providers.aws.services.kms.kms_service import KMS

        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = kms_client.create_key()["KeyMetadata"]
        kms_client.enable_key(KeyId=key["KeyId"])

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_cmk_not_deleted_unintentionally.kms_cmk_not_deleted_unintentionally_fixer.kms_client",
            new=KMS(aws_provider),
        ):
            from prowler.providers.aws.services.kms.kms_cmk_not_deleted_unintentionally.kms_cmk_not_deleted_unintentionally_fixer import (
                fixer,
            )

            assert fixer(key["KeyId"], AWS_REGION_US_EAST_1)

    @mock_aws
    def test_kms_cmk_deleted_unintentionally_error(self):
        from prowler.providers.aws.services.kms.kms_service import KMS

        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = kms_client.create_key()["KeyMetadata"]
        kms_client.schedule_key_deletion(KeyId=key["KeyId"])

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_cmk_not_deleted_unintentionally.kms_cmk_not_deleted_unintentionally_fixer.kms_client",
            new=KMS(aws_provider),
        ):
            from prowler.providers.aws.services.kms.kms_cmk_not_deleted_unintentionally.kms_cmk_not_deleted_unintentionally_fixer import (
                fixer,
            )

            assert not fixer("KeyIdNonExisting", AWS_REGION_US_EAST_1)
