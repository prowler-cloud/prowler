from typing import Any, List
from unittest import mock

from boto3 import client
from moto import mock_aws
import pytest

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_kms_cmk_rotation_enabled:
    @mock_aws
    def test_kms_no_key(self):
        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_cmk_rotation_enabled.kms_cmk_rotation_enabled.kms_client",
            new=KMS(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.kms.kms_cmk_rotation_enabled.kms_cmk_rotation_enabled import (
                kms_cmk_rotation_enabled,
            )

            check = kms_cmk_rotation_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_kms_cmk_rotation_enabled(self):
        # Generate KMS Client
        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        # Creaty KMS key with rotation
        key = kms_client.create_key()["KeyMetadata"]
        kms_client.enable_key_rotation(KeyId=key["KeyId"])

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_cmk_rotation_enabled.kms_cmk_rotation_enabled.kms_client",
            new=KMS(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.kms.kms_cmk_rotation_enabled.kms_cmk_rotation_enabled import (
                kms_cmk_rotation_enabled,
            )

            check = kms_cmk_rotation_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"KMS CMK {key['KeyId']} has automatic rotation enabled."
            )
            assert result[0].resource_id == key["KeyId"]
            assert result[0].resource_arn == key["Arn"]

    @pytest.mark.parametrize(
        "no_of_keys_created,expected_no_of_passes",
        [
            (5, 3),
            (7, 5),
            (10, 8),
        ]
    )
    @mock_aws
    def test_kms_cmk_rotation_enabled_when_get_key_rotation_status_fails_on_2_keys_out_of_x_keys(
        self, no_of_keys_created: int, expected_no_of_passes: int
    ) -> None:
        # Generate KMS Client
        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        kms_client.__dict__["region"] = AWS_REGION_US_EAST_1
        # Creaty KMS key with rotation
        for i in range(no_of_keys_created):
            key = kms_client.create_key()["KeyMetadata"]
            if i not in [2, 4]:
                kms_client.enable_key_rotation(KeyId=key["KeyId"])

        orig_get_key_rotation_status = kms_client.get_key_rotation_status

        def mock_get_key_rotation_status(KeyId: str, count: List[int] = [0]) -> Any:
            if count[0] in [2, 4]:
                count[0] += 1
                raise Exception("FakeClientError")
            else:
                count[0] += 1
                return orig_get_key_rotation_status(KeyId=KeyId)

        kms_client.get_key_rotation_status = mock_get_key_rotation_status

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
            return_value={AWS_REGION_US_EAST_1: kms_client},
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_cmk_rotation_enabled.kms_cmk_rotation_enabled.kms_client",
            new=KMS(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.kms.kms_cmk_rotation_enabled.kms_cmk_rotation_enabled import (
                kms_cmk_rotation_enabled,
            )

            check = kms_cmk_rotation_enabled()
            result = check.execute()

            assert len(result) == no_of_keys_created
            statuses = [r.status for r in result]
            assert statuses.count("PASS") == expected_no_of_passes

    @mock_aws
    def test_kms_cmk_rotation_disabled(self):
        # Generate KMS Client
        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        # Creaty KMS key without rotation
        key = kms_client.create_key()["KeyMetadata"]

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_cmk_rotation_enabled.kms_cmk_rotation_enabled.kms_client",
            new=KMS(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.kms.kms_cmk_rotation_enabled.kms_cmk_rotation_enabled import (
                kms_cmk_rotation_enabled,
            )

            check = kms_cmk_rotation_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"KMS CMK {key['KeyId']} has automatic rotation disabled."
            )
            assert result[0].resource_id == key["KeyId"]
            assert result[0].resource_arn == key["Arn"]
