from unittest import mock
from uuid import uuid4

from prowler.providers.aws.services.sagemaker.sagemaker_service import NotebookInstance
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

test_notebook_instance = "test-notebook-instance"
notebook_instance_arn = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:notebook-instance/{test_notebook_instance}"
subnet_id = "subnet-" + str(uuid4())


class Test_sagemaker_notebook_instance_vpc_settings_configured:
    def test_no_instances(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_notebook_instances = []

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.sagemaker.sagemaker_notebook_instance_vpc_settings_configured.sagemaker_notebook_instance_vpc_settings_configured.sagemaker_client",
            sagemaker_client,
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_notebook_instance_vpc_settings_configured.sagemaker_notebook_instance_vpc_settings_configured import (
                sagemaker_notebook_instance_vpc_settings_configured,
            )

            check = sagemaker_notebook_instance_vpc_settings_configured()
            result = check.execute()
            assert len(result) == 0

    def test_instance_vpc_settings_configured(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_notebook_instances = []
        sagemaker_client.sagemaker_notebook_instances.append(
            NotebookInstance(
                name=test_notebook_instance,
                arn=notebook_instance_arn,
                region=AWS_REGION_EU_WEST_1,
                subnet_id=subnet_id,
            )
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.sagemaker.sagemaker_notebook_instance_vpc_settings_configured.sagemaker_notebook_instance_vpc_settings_configured.sagemaker_client",
            sagemaker_client,
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_notebook_instance_vpc_settings_configured.sagemaker_notebook_instance_vpc_settings_configured import (
                sagemaker_notebook_instance_vpc_settings_configured,
            )

            check = sagemaker_notebook_instance_vpc_settings_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Sagemaker notebook instance {test_notebook_instance} is in a VPC."
            )
            assert result[0].resource_id == test_notebook_instance
            assert result[0].resource_arn == notebook_instance_arn

    def test_instance_vpc_settings_not_configured(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_notebook_instances = []
        sagemaker_client.sagemaker_notebook_instances.append(
            NotebookInstance(
                name=test_notebook_instance,
                arn=notebook_instance_arn,
                region=AWS_REGION_EU_WEST_1,
                root_access=True,
            )
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.sagemaker.sagemaker_notebook_instance_vpc_settings_configured.sagemaker_notebook_instance_vpc_settings_configured.sagemaker_client",
            sagemaker_client,
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_notebook_instance_vpc_settings_configured.sagemaker_notebook_instance_vpc_settings_configured import (
                sagemaker_notebook_instance_vpc_settings_configured,
            )

            check = sagemaker_notebook_instance_vpc_settings_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Sagemaker notebook instance {test_notebook_instance} has VPC settings disabled."
            )
            assert result[0].resource_id == test_notebook_instance
            assert result[0].resource_arn == notebook_instance_arn
