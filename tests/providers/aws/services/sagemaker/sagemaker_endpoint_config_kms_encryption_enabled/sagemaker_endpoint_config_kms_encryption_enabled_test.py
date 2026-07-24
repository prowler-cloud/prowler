from unittest import mock
from uuid import uuid4

from prowler.providers.aws.services.sagemaker.sagemaker_service import EndpointConfig
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

test_endpoint_config = "test-endpoint-config"
endpoint_config_arn = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:endpoint-config/{test_endpoint_config}"
kms_key = str(uuid4())


class Test_sagemaker_endpoint_config_kms_encryption_enabled:
    def test_no_endpoint_configs(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.endpoint_configs = {}

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_endpoint_config_kms_encryption_enabled.sagemaker_endpoint_config_kms_encryption_enabled.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_endpoint_config_kms_encryption_enabled.sagemaker_endpoint_config_kms_encryption_enabled import (
                sagemaker_endpoint_config_kms_encryption_enabled,
            )

            check = sagemaker_endpoint_config_kms_encryption_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_endpoint_config_with_kms_key(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.endpoint_configs = {}
        sagemaker_client.endpoint_configs[endpoint_config_arn] = EndpointConfig(
            name=test_endpoint_config,
            arn=endpoint_config_arn,
            region=AWS_REGION_EU_WEST_1,
            kms_key_id=kms_key,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_endpoint_config_kms_encryption_enabled.sagemaker_endpoint_config_kms_encryption_enabled.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_endpoint_config_kms_encryption_enabled.sagemaker_endpoint_config_kms_encryption_enabled import (
                sagemaker_endpoint_config_kms_encryption_enabled,
            )

            check = sagemaker_endpoint_config_kms_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Sagemaker Endpoint Config {test_endpoint_config} has KMS encryption enabled."
            )
            assert result[0].resource_id == test_endpoint_config
            assert result[0].resource_arn == endpoint_config_arn

    def test_endpoint_config_no_kms_key(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.endpoint_configs = {}
        sagemaker_client.endpoint_configs[endpoint_config_arn] = EndpointConfig(
            name=test_endpoint_config,
            arn=endpoint_config_arn,
            region=AWS_REGION_EU_WEST_1,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_endpoint_config_kms_encryption_enabled.sagemaker_endpoint_config_kms_encryption_enabled.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_endpoint_config_kms_encryption_enabled.sagemaker_endpoint_config_kms_encryption_enabled import (
                sagemaker_endpoint_config_kms_encryption_enabled,
            )

            check = sagemaker_endpoint_config_kms_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Sagemaker Endpoint Config {test_endpoint_config} does not have KMS encryption enabled."
            )
            assert result[0].resource_id == test_endpoint_config
            assert result[0].resource_arn == endpoint_config_arn
