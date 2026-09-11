from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_kms_cmk_not_deleted_unintentionally:
    @mock_aws
    def test_kms_no_keys(self):
        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.kms.kms_cmk_not_deleted_unintentionally.kms_cmk_not_deleted_unintentionally.kms_client",
                new=KMS(aws_provider),
            ),
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.kms.kms_cmk_not_deleted_unintentionally.kms_cmk_not_deleted_unintentionally.kms_client",
                new=KMS(aws_provider),
            ),
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.kms.kms_cmk_not_deleted_unintentionally.kms_cmk_not_deleted_unintentionally.kms_client",
                new=KMS(aws_provider),
            ),
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.kms.kms_cmk_not_deleted_unintentionally.kms_cmk_not_deleted_unintentionally.kms_client",
                new=KMS(aws_provider),
            ),
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.kms.kms_cmk_not_deleted_unintentionally.kms_cmk_not_deleted_unintentionally.kms_client",
                new=KMS(aws_provider),
            ),
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
    def test_kms_cmk_not_deleted_unintentionally_scan_error(self):
        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        kms = KMS(aws_provider)
        kms.keys = []
        kms.keys_scan_errors = {AWS_REGION_US_EAST_1: "AccessDeniedException"}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.kms.kms_cmk_not_deleted_unintentionally.kms_cmk_not_deleted_unintentionally.kms_client",
                new=kms,
            ),
        ):
            from prowler.providers.aws.services.kms.kms_cmk_not_deleted_unintentionally.kms_cmk_not_deleted_unintentionally import (
                kms_cmk_not_deleted_unintentionally,
            )

            check = kms_cmk_not_deleted_unintentionally()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                result[0].status_extended
                == f"KMS keys could not be listed in region {AWS_REGION_US_EAST_1} (AccessDeniedException); verify manually that customer-managed keys are not unintentionally scheduled for deletion."
            )
            assert result[0].resource_id == "key/unknown"
            assert (
                result[0].resource_arn
                == f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:key/unknown"
            )

    @mock_aws
    def test_kms_cmk_not_deleted_unintentionally_describe_error(self):
        from prowler.providers.aws.services.kms.kms_service import KMS, Key

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        kms = KMS(aws_provider)
        key_id = "test-key-id"
        key_arn = f"arn:aws:kms:{AWS_REGION_US_EAST_1}:123456789012:key/{key_id}"
        kms.keys = [
            Key(
                id=key_id,
                arn=key_arn,
                region=AWS_REGION_US_EAST_1,
                detail_retrieved=False,
                describe_error="AccessDeniedException",
            )
        ]
        kms.keys_scan_errors = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.kms.kms_cmk_not_deleted_unintentionally.kms_cmk_not_deleted_unintentionally.kms_client",
                new=kms,
            ),
        ):
            from prowler.providers.aws.services.kms.kms_cmk_not_deleted_unintentionally.kms_cmk_not_deleted_unintentionally import (
                kms_cmk_not_deleted_unintentionally,
            )

            check = kms_cmk_not_deleted_unintentionally()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                result[0].status_extended
                == f"KMS key {key_id} details could not be retrieved (AccessDeniedException); verify manually that customer-managed keys are not unintentionally scheduled for deletion."
            )
            assert result[0].resource_id == key_id
            assert result[0].resource_arn == key_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].region == AWS_REGION_US_EAST_1
