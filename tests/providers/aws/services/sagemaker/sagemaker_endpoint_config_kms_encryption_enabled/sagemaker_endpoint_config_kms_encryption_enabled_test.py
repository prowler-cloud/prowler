from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_sagemaker_endpoint_config_kms_encryption_enabled:
    @mock_aws
    def test_no_endpoint_configs(self):
        from prowler.providers.aws.services.sagemaker.sagemaker_service import SageMaker

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_endpoint_config_kms_encryption_enabled.sagemaker_endpoint_config_kms_encryption_enabled.sagemaker_client",
                new=SageMaker(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_endpoint_config_kms_encryption_enabled.sagemaker_endpoint_config_kms_encryption_enabled import (
                sagemaker_endpoint_config_kms_encryption_enabled,
            )

            check = sagemaker_endpoint_config_kms_encryption_enabled()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_endpoint_config_without_kms(self):
        sagemaker_client = client("sagemaker", region_name=AWS_REGION_EU_WEST_1)
        endpoint_config_name = "endpoint-config-no-kms"
        model_name = "model-v1"
        sagemaker_client.create_model(ModelName=model_name)
        endpoint_config = sagemaker_client.create_endpoint_config(
            EndpointConfigName=endpoint_config_name,
            ProductionVariants=[
                {
                    "VariantName": "AllTraffic",
                    "ModelName": model_name,
                    "InitialInstanceCount": 1,
                    "InstanceType": "ml.m5.large",
                    "InitialVariantWeight": 1.0,
                }
            ],
        )

        from prowler.providers.aws.services.sagemaker.sagemaker_service import SageMaker

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_endpoint_config_kms_encryption_enabled.sagemaker_endpoint_config_kms_encryption_enabled.sagemaker_client",
                new=SageMaker(aws_provider),
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
                == f"Sagemaker Endpoint Config {endpoint_config_name} does not have data encryption enabled with a KMS key."
            )
            assert result[0].resource_id == endpoint_config_name
            assert result[0].resource_arn == endpoint_config["EndpointConfigArn"]

    @mock_aws
    def test_endpoint_config_with_kms(self):
        kms_client = client("kms", region_name=AWS_REGION_EU_WEST_1)
        key = kms_client.create_key()["KeyMetadata"]["KeyId"]

        sagemaker_client = client("sagemaker", region_name=AWS_REGION_EU_WEST_1)
        endpoint_config_name = "endpoint-config-with-kms"
        model_name = "model-v1"
        sagemaker_client.create_model(ModelName=model_name)
        endpoint_config = sagemaker_client.create_endpoint_config(
            EndpointConfigName=endpoint_config_name,
            KmsKeyId=key,
            ProductionVariants=[
                {
                    "VariantName": "AllTraffic",
                    "ModelName": model_name,
                    "InitialInstanceCount": 1,
                    "InstanceType": "ml.m5.large",
                    "InitialVariantWeight": 1.0,
                }
            ],
        )

        from prowler.providers.aws.services.sagemaker.sagemaker_service import SageMaker

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_endpoint_config_kms_encryption_enabled.sagemaker_endpoint_config_kms_encryption_enabled.sagemaker_client",
                new=SageMaker(aws_provider),
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
                == f"Sagemaker Endpoint Config {endpoint_config_name} has data encryption enabled with KMS key."
            )
            assert result[0].resource_id == endpoint_config_name
            assert result[0].resource_arn == endpoint_config["EndpointConfigArn"]
