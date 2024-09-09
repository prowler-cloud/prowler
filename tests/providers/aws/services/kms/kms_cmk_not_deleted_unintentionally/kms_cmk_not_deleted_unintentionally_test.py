from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_kms_cmk_not_deleted_unintentionally:
    @mock_aws
    def test_kms_no_keys(self):
        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_cmk_not_deleted_unintentionally.kms_cmk_not_deleted_unintentionally.kms_client",
            new=KMS(aws_provider),
        ):
            from prowler.providers.aws.services.kms.kms_cmk_not_deleted_unintentionally.kms_cmk_not_deleted_unintentionally import (
                kms_cmk_not_deleted_unintentionally,
            )

            check = kms_cmk_not_deleted_unintentionally()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_kms_cmk_disabled_key(self):
        from prowler.providers.aws.services.kms.kms_service import KMS

        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = kms_client.create_key()["KeyMetadata"]
        kms_client.disable_key(KeyId=key["KeyId"])

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1], scan_unused_services=False
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_cmk_not_deleted_unintentionally.kms_cmk_not_deleted_unintentionally.kms_client",
            new=KMS(aws_provider),
        ):
            from prowler.providers.aws.services.kms.kms_cmk_not_deleted_unintentionally.kms_cmk_not_deleted_unintentionally import (
                kms_cmk_not_deleted_unintentionally,
            )

            check = kms_cmk_not_deleted_unintentionally()
            result = check.execute()

            assert len(result) == 0

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
            "prowler.providers.aws.services.kms.kms_cmk_not_deleted_unintentionally.kms_cmk_not_deleted_unintentionally.kms_client",
            new=KMS(aws_provider),
        ):
            from prowler.providers.aws.services.kms.kms_cmk_not_deleted_unintentionally.kms_cmk_not_deleted_unintentionally import (
                kms_cmk_not_deleted_unintentionally,
            )

            check = kms_cmk_not_deleted_unintentionally()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"KMS CMK {key['KeyId']} is scheduled for deletion, revert it if it was unintentionally."
            )
            assert result[0].resource_id == key["KeyId"]
            assert result[0].resource_arn == key["Arn"]

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
            "prowler.providers.aws.services.kms.kms_cmk_not_deleted_unintentionally.kms_cmk_not_deleted_unintentionally.kms_client",
            new=KMS(aws_provider),
        ):
            from prowler.providers.aws.services.kms.kms_cmk_not_deleted_unintentionally.kms_cmk_not_deleted_unintentionally import (
                kms_cmk_not_deleted_unintentionally,
            )

            check = kms_cmk_not_deleted_unintentionally()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"KMS CMK {key['KeyId']} is not scheduled for deletion."
            )
            assert result[0].resource_id == key["KeyId"]
            assert result[0].resource_arn == key["Arn"]

    @mock_aws
    def test_kms_cmk_disabled_with_flag_unused(self):
        from prowler.providers.aws.services.kms.kms_service import KMS

        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = kms_client.create_key()["KeyMetadata"]
        kms_client.disable_key(KeyId=key["KeyId"])

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1], scan_unused_services=True
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_cmk_not_deleted_unintentionally.kms_cmk_not_deleted_unintentionally.kms_client",
            new=KMS(aws_provider),
        ):
            from prowler.providers.aws.services.kms.kms_cmk_not_deleted_unintentionally.kms_cmk_not_deleted_unintentionally import (
                kms_cmk_not_deleted_unintentionally,
            )

            check = kms_cmk_not_deleted_unintentionally()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"KMS CMK {key['KeyId']} is not scheduled for deletion."
            )
            assert result[0].resource_id == key["KeyId"]
            assert result[0].resource_arn == key["Arn"]
