# Example: AWS KMS Key Rotation Test
# Source: tests/providers/aws/services/kms/kms_cmk_rotation_enabled/

from unittest import mock

import pytest
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_kms_cmk_rotation_enabled:
    @mock_aws
    def test_kms_no_key(self):
        """Test when no KMS keys exist."""
        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.kms.kms_cmk_rotation_enabled.kms_cmk_rotation_enabled.kms_client",
                new=KMS(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.kms.kms_cmk_rotation_enabled.kms_cmk_rotation_enabled import (
                kms_cmk_rotation_enabled,
            )

            check = kms_cmk_rotation_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_kms_cmk_rotation_enabled(self):
        """Test PASS: KMS key with rotation enabled."""
        # Create mocked AWS resources using boto3
        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = kms_client.create_key()["KeyMetadata"]
        kms_client.enable_key_rotation(KeyId=key["KeyId"])

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.kms.kms_cmk_rotation_enabled.kms_cmk_rotation_enabled.kms_client",
                new=KMS(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.kms.kms_cmk_rotation_enabled.kms_cmk_rotation_enabled import (
                kms_cmk_rotation_enabled,
            )

            check = kms_cmk_rotation_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == key["KeyId"]
            assert result[0].resource_arn == key["Arn"]

    @mock_aws
    def test_kms_cmk_rotation_disabled(self):
        """Test FAIL: KMS key without rotation enabled."""
        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = kms_client.create_key()["KeyMetadata"]
        # Note: rotation NOT enabled

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.kms.kms_cmk_rotation_enabled.kms_cmk_rotation_enabled.kms_client",
                new=KMS(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.kms.kms_cmk_rotation_enabled.kms_cmk_rotation_enabled import (
                kms_cmk_rotation_enabled,
            )

            check = kms_cmk_rotation_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == key["KeyId"]

    @pytest.mark.parametrize(
        "no_of_keys_created,expected_no_of_passes",
        [
            (5, 3),
            (7, 5),
            (10, 8),
        ],
    )
    @mock_aws
    def test_kms_rotation_parametrized(
        self, no_of_keys_created: int, expected_no_of_passes: int
    ) -> None:
        """Parametrized test demonstrating multiple scenarios."""
        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)

        for i in range(no_of_keys_created):
            key = kms_client.create_key()["KeyMetadata"]
            if i not in [2, 4]:  # Skip enabling rotation for some keys
                kms_client.enable_key_rotation(KeyId=key["KeyId"])

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.kms.kms_cmk_rotation_enabled.kms_cmk_rotation_enabled.kms_client",
                new=KMS(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.kms.kms_cmk_rotation_enabled.kms_cmk_rotation_enabled import (
                kms_cmk_rotation_enabled,
            )

            check = kms_cmk_rotation_enabled()
            result = check.execute()

            assert len(result) == no_of_keys_created
            statuses = [r.status for r in result]
            assert statuses.count("PASS") == expected_no_of_passes
