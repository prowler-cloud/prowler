from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_kms_cmk_rotation_enabled_fixer:
    @mock_aws
    def test_kms_cmk_rotation_enabled_fixer(self):
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
            "prowler.providers.aws.services.kms.kms_cmk_rotation_enabled.kms_cmk_rotation_enabled_fixer.kms_client",
            new=KMS(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.kms.kms_cmk_rotation_enabled.kms_cmk_rotation_enabled_fixer import (
                fixer,
            )

            assert fixer(resource_id=key["KeyId"], region=AWS_REGION_US_EAST_1)
