from unittest import mock

from prowler.providers.aws.services.sagemaker.sagemaker_service import ModelRegistry
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

registry_arn = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:model-registry/unknown"


class Test_sagemaker_models_registry_in_use:
    def test_no_registries(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_model_registries = []

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_models_registry_in_use.sagemaker_models_registry_in_use.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_models_registry_in_use.sagemaker_models_registry_in_use import (
                sagemaker_models_registry_in_use,
            )

            check = sagemaker_models_registry_in_use()
            result = check.execute()
            assert len(result) == 0

    def test_registry_no_groups(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_model_registries = [
            ModelRegistry(
                name="SageMaker Model Registry",
                arn=registry_arn,
                region=AWS_REGION_EU_WEST_1,
                has_groups=False,
                has_approved_packages=False,
            )
        ]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_models_registry_in_use.sagemaker_models_registry_in_use.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_models_registry_in_use.sagemaker_models_registry_in_use import (
                sagemaker_models_registry_in_use,
            )

            check = sagemaker_models_registry_in_use()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SageMaker Model Registry in region {AWS_REGION_EU_WEST_1} has no Model Package Groups."
            )
            assert result[0].resource_id == "SageMaker Model Registry"
            assert result[0].resource_arn == registry_arn
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_registry_groups_no_approved_packages(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_model_registries = [
            ModelRegistry(
                name="SageMaker Model Registry",
                arn=registry_arn,
                region=AWS_REGION_EU_WEST_1,
                has_groups=True,
                has_approved_packages=False,
            )
        ]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_models_registry_in_use.sagemaker_models_registry_in_use.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_models_registry_in_use.sagemaker_models_registry_in_use import (
                sagemaker_models_registry_in_use,
            )

            check = sagemaker_models_registry_in_use()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"SageMaker Model Registry in region {AWS_REGION_EU_WEST_1} has Model Package Groups but no approved model packages."
            )
            assert result[0].resource_id == "SageMaker Model Registry"
            assert result[0].resource_arn == registry_arn
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_registry_with_approved_packages(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_model_registries = [
            ModelRegistry(
                name="SageMaker Model Registry",
                arn=registry_arn,
                region=AWS_REGION_EU_WEST_1,
                has_groups=True,
                has_approved_packages=True,
            )
        ]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_models_registry_in_use.sagemaker_models_registry_in_use.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_models_registry_in_use.sagemaker_models_registry_in_use import (
                sagemaker_models_registry_in_use,
            )

            check = sagemaker_models_registry_in_use()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"SageMaker Model Registry in region {AWS_REGION_EU_WEST_1} has at least one approved model package."
            )
            assert result[0].resource_id == "SageMaker Model Registry"
            assert result[0].resource_arn == registry_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
