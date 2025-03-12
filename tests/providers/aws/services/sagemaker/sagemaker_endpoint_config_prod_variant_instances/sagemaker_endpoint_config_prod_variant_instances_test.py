from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_sagemaker_endpoint_config_prod_variant_instances:
    @mock_aws
    def test_no_endpoint_configs(self):

        from prowler.providers.aws.services.sagemaker.sagemaker_service import SageMaker

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.sagemaker.sagemaker_endpoint_config_prod_variant_instances.sagemaker_endpoint_config_prod_variant_instances.sagemaker_client",
            new=SageMaker(aws_provider),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_endpoint_config_prod_variant_instances.sagemaker_endpoint_config_prod_variant_instances import (
                sagemaker_endpoint_config_prod_variant_instances,
            )

            check = sagemaker_endpoint_config_prod_variant_instances()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_endpoint_config_non_compliant_prod_variant(self):
        sagemaker_client = client("sagemaker", region_name=AWS_REGION_EU_WEST_1)
        endpoint_config_name = "endpoint-config-test"
        prod_variant_name = "Variant1"
        prod_variant_name2 = "Variant2"
        model_name = "mi-modelo-v1"
        model_name2 = "mi-modelo-v2"
        sagemaker_client.create_model(ModelName=model_name)
        sagemaker_client.create_model(ModelName=model_name2)
        endpoint_config = sagemaker_client.create_endpoint_config(
            EndpointConfigName=endpoint_config_name,
            ProductionVariants=[
                {
                    "VariantName": prod_variant_name,
                    "ModelName": "mi-modelo-v1",
                    "InitialInstanceCount": 1,
                    "InstanceType": "ml.m5.large",
                    "InitialVariantWeight": 0.6,
                },
                {
                    "VariantName": prod_variant_name2,
                    "ModelName": "mi-modelo-v2",
                    "InitialInstanceCount": 2,
                    "InstanceType": "ml.m5.large",
                    "InitialVariantWeight": 0.4,
                },
            ],
        )

        from prowler.providers.aws.services.sagemaker.sagemaker_service import SageMaker

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.sagemaker.sagemaker_endpoint_config_prod_variant_instances.sagemaker_endpoint_config_prod_variant_instances.sagemaker_client",
            new=SageMaker(aws_provider),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_endpoint_config_prod_variant_instances.sagemaker_endpoint_config_prod_variant_instances import (
                sagemaker_endpoint_config_prod_variant_instances,
            )

            check = sagemaker_endpoint_config_prod_variant_instances()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Sagemaker Endpoint Config {endpoint_config_name}'s production variants {prod_variant_name} with less than two initial instance."
            )
            assert result[0].resource_id == endpoint_config_name
            assert result[0].resource_arn == endpoint_config["EndpointConfigArn"]

    @mock_aws
    def test_endpoint_config_compliant_prod_variants(self):
        sagemaker_client = client("sagemaker", region_name=AWS_REGION_EU_WEST_1)
        endpoint_config_name = "endpoint-config-test"
        prod_variant_name = "Variant1"
        prod_variant_name2 = "Variant2"
        model_name = "mi-modelo-v1"
        model_name2 = "mi-modelo-v2"
        sagemaker_client.create_model(ModelName=model_name)
        sagemaker_client.create_model(ModelName=model_name2)
        endpoint_config = sagemaker_client.create_endpoint_config(
            EndpointConfigName=endpoint_config_name,
            ProductionVariants=[
                {
                    "VariantName": prod_variant_name,
                    "ModelName": "mi-modelo-v1",
                    "InitialInstanceCount": 2,
                    "InstanceType": "ml.m5.large",
                    "InitialVariantWeight": 0.6,
                },
                {
                    "VariantName": prod_variant_name2,
                    "ModelName": "mi-modelo-v2",
                    "InitialInstanceCount": 2,
                    "InstanceType": "ml.m5.large",
                    "InitialVariantWeight": 0.4,
                },
            ],
        )

        from prowler.providers.aws.services.sagemaker.sagemaker_service import SageMaker

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.sagemaker.sagemaker_endpoint_config_prod_variant_instances.sagemaker_endpoint_config_prod_variant_instances.sagemaker_client",
            new=SageMaker(aws_provider),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_endpoint_config_prod_variant_instances.sagemaker_endpoint_config_prod_variant_instances import (
                sagemaker_endpoint_config_prod_variant_instances,
            )

            check = sagemaker_endpoint_config_prod_variant_instances()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Sagemaker Endpoint Config {endpoint_config_name} has all production variants with more than one initial instance."
            )
            assert result[0].resource_id == endpoint_config_name
            assert result[0].resource_arn == endpoint_config["EndpointConfigArn"]
