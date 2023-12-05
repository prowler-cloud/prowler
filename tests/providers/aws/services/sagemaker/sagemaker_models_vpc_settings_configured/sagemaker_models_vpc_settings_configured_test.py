from re import search
from unittest import mock
from uuid import uuid4

from prowler.providers.aws.services.sagemaker.sagemaker_service import Model
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
)

test_notebook_instance = "test-notebook-instance"
notebook_instance_arn = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:notebook-instance/{test_notebook_instance}"
subnet_id = "subnet-" + str(uuid4())


class Test_sagemaker_models_vpc_settings_configured:
    def test_no_models(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_models = []
        with mock.patch(
            "prowler.providers.aws.services.sagemaker.sagemaker_service.SageMaker",
            sagemaker_client,
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_models_vpc_settings_configured.sagemaker_models_vpc_settings_configured import (
                sagemaker_models_vpc_settings_configured,
            )

            check = sagemaker_models_vpc_settings_configured()
            result = check.execute()
            assert len(result) == 0

    def test_instance_vpc_settings_configured(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_models = []
        sagemaker_client.sagemaker_models.append(
            Model(
                name=test_notebook_instance,
                arn=notebook_instance_arn,
                region=AWS_REGION_EU_WEST_1,
                vpc_config_subnets=[subnet_id],
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.sagemaker.sagemaker_service.SageMaker",
            sagemaker_client,
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_models_vpc_settings_configured.sagemaker_models_vpc_settings_configured import (
                sagemaker_models_vpc_settings_configured,
            )

            check = sagemaker_models_vpc_settings_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search("has VPC settings enabled", result[0].status_extended)
            assert result[0].resource_id == test_notebook_instance
            assert result[0].resource_arn == notebook_instance_arn

    def test_instance_vpc_settings_not_configured(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_models = []
        sagemaker_client.sagemaker_models.append(
            Model(
                name=test_notebook_instance,
                arn=notebook_instance_arn,
                region=AWS_REGION_EU_WEST_1,
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.sagemaker.sagemaker_service.SageMaker",
            sagemaker_client,
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_models_vpc_settings_configured.sagemaker_models_vpc_settings_configured import (
                sagemaker_models_vpc_settings_configured,
            )

            check = sagemaker_models_vpc_settings_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search("has VPC settings disabled", result[0].status_extended)
            assert result[0].resource_id == test_notebook_instance
            assert result[0].resource_arn == notebook_instance_arn
