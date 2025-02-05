from typing import Any, List
from unittest import mock

from boto3 import client
from moto import mock_aws
import pytest

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_kms_cmk_are_used:
    @mock_aws
    def test_kms_no_keys(self):
        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_cmk_are_used.kms_cmk_are_used.kms_client",
            new=KMS(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.kms.kms_cmk_are_used.kms_cmk_are_used import (
                kms_cmk_are_used,
            )

            check = kms_cmk_are_used()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_kms_cmk_are_used(self):
        # Generate KMS Client
        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        # Create enabled KMS key
        key = kms_client.create_key()["KeyMetadata"]

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_cmk_are_used.kms_cmk_are_used.kms_client",
            new=KMS(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.kms.kms_cmk_are_used.kms_cmk_are_used import (
                kms_cmk_are_used,
            )

            check = kms_cmk_are_used()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == f"KMS CMK {key['KeyId']} is being used."
            assert result[0].resource_id == key["KeyId"]
            assert result[0].resource_arn == key["Arn"]

    @pytest.mark.parametrize(
            "no_of_keys_created,expected_no_of_results",
            [
                (5, 3),
                (7, 5),
                (10, 8),
            ]
    )
    @mock_aws
    def test_kms_cmk_are_used_when_describe_key_fails_on_2_keys_out_of_x_keys(
        self, no_of_keys_created: int, expected_no_of_results: int
    ) -> None:
        # Generate KMS Client
        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        kms_client.__dict__["region"] = AWS_REGION_US_EAST_1
        # Create enabled KMS key
        for i in range(no_of_keys_created):
            kms_client.create_key(
                Tags=[
                    {"TagKey": "test", "TagValue": f"test{i}"},
                ],
            )

        orig_describe_key = kms_client.describe_key
        def mock_describe_key(KeyId: str, count: List[int] = [0]) -> Any:
            if count[0] in [2, 4]: 
                count[0] += 1
                raise Exception("FakeClientError")
            else:
                count[0] += 1
                return orig_describe_key(KeyId=KeyId)

        kms_client.describe_key = mock_describe_key

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
            return_value={AWS_REGION_US_EAST_1: kms_client},
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_cmk_are_used.kms_cmk_are_used.kms_client",
            new=KMS(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.kms.kms_cmk_are_used.kms_cmk_are_used import (
                kms_cmk_are_used,
            )

            check = kms_cmk_are_used()
            result = check.execute()

            assert len(result) == expected_no_of_results

    @mock_aws
    def test_kms_key_with_deletion(self):
        # Generate KMS Client
        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        # Creaty KMS key with deletion
        key = kms_client.create_key()["KeyMetadata"]
        kms_client.schedule_key_deletion(KeyId=key["KeyId"])

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_cmk_are_used.kms_cmk_are_used.kms_client",
            new=KMS(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.kms.kms_cmk_are_used.kms_cmk_are_used import (
                kms_cmk_are_used,
            )

            check = kms_cmk_are_used()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"KMS CMK {key['KeyId']} is not being used but it has scheduled deletion."
            )
            assert result[0].resource_id == key["KeyId"]
            assert result[0].resource_arn == key["Arn"]

    @mock_aws
    def test_kms_disabled_key(self):
        # Generate KMS Client
        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        # Creaty KMS key with deletion
        key = kms_client.create_key()["KeyMetadata"]
        kms_client.disable_key(KeyId=key["KeyId"])

        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_cmk_are_used.kms_cmk_are_used.kms_client",
            new=KMS(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.kms.kms_cmk_are_used.kms_cmk_are_used import (
                kms_cmk_are_used,
            )

            check = kms_cmk_are_used()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"KMS CMK {key['KeyId']} is not being used."
            )
            assert result[0].resource_id == key["KeyId"]
            assert result[0].resource_arn == key["Arn"]
