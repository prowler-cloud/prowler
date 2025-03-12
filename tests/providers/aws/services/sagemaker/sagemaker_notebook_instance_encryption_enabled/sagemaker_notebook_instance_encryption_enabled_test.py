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
kms_key = str(uuid4())


class Test_sagemaker_notebook_instance_encryption_enabled:
    def test_no_instances(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_notebook_instances = []

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.sagemaker.sagemaker_notebook_instance_encryption_enabled.sagemaker_notebook_instance_encryption_enabled.sagemaker_client",
            sagemaker_client,
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_notebook_instance_encryption_enabled.sagemaker_notebook_instance_encryption_enabled import (
                sagemaker_notebook_instance_encryption_enabled,
            )

            check = sagemaker_notebook_instance_encryption_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_instance_with_kms_key(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_notebook_instances = []
        sagemaker_client.sagemaker_notebook_instances.append(
            NotebookInstance(
                name=test_notebook_instance,
                arn=notebook_instance_arn,
                region=AWS_REGION_EU_WEST_1,
                kms_key_id=kms_key,
            )
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.sagemaker.sagemaker_notebook_instance_encryption_enabled.sagemaker_notebook_instance_encryption_enabled.sagemaker_client",
            sagemaker_client,
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_notebook_instance_encryption_enabled.sagemaker_notebook_instance_encryption_enabled import (
                sagemaker_notebook_instance_encryption_enabled,
            )

            check = sagemaker_notebook_instance_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Sagemaker notebook instance {test_notebook_instance} has data encryption enabled."
            )
            assert result[0].resource_id == test_notebook_instance
            assert result[0].resource_arn == notebook_instance_arn

    def test_instance_no_kms_key(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_notebook_instances = []
        sagemaker_client.sagemaker_notebook_instances.append(
            NotebookInstance(
                name=test_notebook_instance,
                arn=notebook_instance_arn,
                region=AWS_REGION_EU_WEST_1,
            )
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.sagemaker.sagemaker_notebook_instance_encryption_enabled.sagemaker_notebook_instance_encryption_enabled.sagemaker_client",
            sagemaker_client,
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_notebook_instance_encryption_enabled.sagemaker_notebook_instance_encryption_enabled import (
                sagemaker_notebook_instance_encryption_enabled,
            )

            check = sagemaker_notebook_instance_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Sagemaker notebook instance {test_notebook_instance} has data encryption disabled."
            )
            assert result[0].resource_id == test_notebook_instance
            assert result[0].resource_arn == notebook_instance_arn
