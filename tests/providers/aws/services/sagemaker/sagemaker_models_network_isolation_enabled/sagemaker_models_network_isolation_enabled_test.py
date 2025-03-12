from unittest import mock
from uuid import uuid4

from prowler.providers.aws.services.sagemaker.sagemaker_service import Model
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

test_notebook_instance = "test-notebook-instance"
notebook_instance_arn = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:notebook-instance/{test_notebook_instance}"
subnet_id = "subnet-" + str(uuid4())


class Test_sagemaker_models_network_isolation_enabled:
    def test_no_models(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_models = []

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.sagemaker.sagemaker_models_network_isolation_enabled.sagemaker_models_network_isolation_enabled.sagemaker_client",
            sagemaker_client,
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_models_network_isolation_enabled.sagemaker_models_network_isolation_enabled import (
                sagemaker_models_network_isolation_enabled,
            )

            check = sagemaker_models_network_isolation_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_instance_network_isolation_enabled(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_models = []
        sagemaker_client.sagemaker_models.append(
            Model(
                name=test_notebook_instance,
                arn=notebook_instance_arn,
                region=AWS_REGION_EU_WEST_1,
                network_isolation=True,
            )
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.sagemaker.sagemaker_models_network_isolation_enabled.sagemaker_models_network_isolation_enabled.sagemaker_client",
            sagemaker_client,
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_models_network_isolation_enabled.sagemaker_models_network_isolation_enabled import (
                sagemaker_models_network_isolation_enabled,
            )

            check = sagemaker_models_network_isolation_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Sagemaker notebook instance {test_notebook_instance} has network isolation enabled."
            )
            assert result[0].resource_id == test_notebook_instance
            assert result[0].resource_arn == notebook_instance_arn

    def test_instance_network_isolation_disabled(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_models = []
        sagemaker_client.sagemaker_models.append(
            Model(
                name=test_notebook_instance,
                arn=notebook_instance_arn,
                region=AWS_REGION_EU_WEST_1,
                network_isolation=False,
            )
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.sagemaker.sagemaker_models_network_isolation_enabled.sagemaker_models_network_isolation_enabled.sagemaker_client",
            sagemaker_client,
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_models_network_isolation_enabled.sagemaker_models_network_isolation_enabled import (
                sagemaker_models_network_isolation_enabled,
            )

            check = sagemaker_models_network_isolation_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Sagemaker notebook instance {test_notebook_instance} has network isolation disabled."
            )
            assert result[0].resource_id == test_notebook_instance
            assert result[0].resource_arn == notebook_instance_arn
