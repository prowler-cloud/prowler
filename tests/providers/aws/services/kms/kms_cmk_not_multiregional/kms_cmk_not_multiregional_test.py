from typing import Any, List
from unittest import mock
from boto3 import client
from moto import mock_aws
import pytest

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_kms_cmk_not_multiregional:
    @mock_aws
    def test_kms_no_keys(self) -> None:
        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_cmk_not_multiregional.kms_cmk_not_multiregional.kms_client",
            new=KMS(aws_provider),
        ):
            from prowler.providers.aws.services.kms.kms_cmk_not_multiregional.kms_cmk_not_multiregional import (
                kms_cmk_not_multiregional,
            )

            check = kms_cmk_not_multiregional()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_kms_cmk_disabled_key(self) -> None:
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
            "prowler.providers.aws.services.kms.kms_cmk_not_multiregional.kms_cmk_not_multiregional.kms_client",
            new=KMS(aws_provider),
        ):
            from prowler.providers.aws.services.kms.kms_cmk_not_multiregional.kms_cmk_not_multiregional import (
                kms_cmk_not_multiregional,
            )

            check = kms_cmk_not_multiregional()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_kms_cmk_is_multi_regional(self) -> None:

        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = kms_client.create_key(MultiRegion=True)["KeyMetadata"]

        # The Prowler service import MUST be made within the decorated
        # code not to make real API calls to the AWS service.
        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1], scan_unused_services=False
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_cmk_not_multiregional.kms_cmk_not_multiregional.kms_client",
            new=KMS(aws_provider),
        ):
            from prowler.providers.aws.services.kms.kms_cmk_not_multiregional.kms_cmk_not_multiregional import (
                kms_cmk_not_multiregional,
            )

            check = kms_cmk_not_multiregional()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"KMS CMK {key['KeyId']} is a multi-region key."
            )
            assert result[0].resource_id == key["KeyId"]
            assert result[0].resource_arn == key["Arn"]

    @mock_aws
    def test_kms_cmk_is_single_regional(self) -> None:

        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        key = kms_client.create_key(MultiRegion=False)["KeyMetadata"]

        # The Prowler service import MUST be made within the decorated
        # code not to make real API calls to the AWS service.
        from prowler.providers.aws.services.kms.kms_service import KMS

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1], scan_unused_services=False
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_cmk_not_multiregional.kms_cmk_not_multiregional.kms_client",
            new=KMS(aws_provider),
        ):
            from prowler.providers.aws.services.kms.kms_cmk_not_multiregional.kms_cmk_not_multiregional import (
                kms_cmk_not_multiregional,
            )

            check = kms_cmk_not_multiregional()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"KMS CMK {key['KeyId']} is a single-region key."
            )
            assert result[0].resource_id == key["KeyId"]
            assert result[0].resource_arn == key["Arn"]
