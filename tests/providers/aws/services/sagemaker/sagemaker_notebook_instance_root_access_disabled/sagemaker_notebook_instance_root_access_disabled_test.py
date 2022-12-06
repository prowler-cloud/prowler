from re import search
from unittest import mock

from prowler.providers.aws.services.sagemaker.sagemaker_service import NotebookInstance

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"

test_notebook_instance = "test-notebook-instance"
notebook_instance_arn = f"arn:aws:sagemaker:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:notebook-instance/{test_notebook_instance}"


class Test_sagemaker_notebook_instance_root_access_disabled:
    def test_no_instances(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_notebook_instances = []
        with mock.patch(
            "prowler.providers.aws.services.sagemaker.sagemaker_service.SageMaker",
            sagemaker_client,
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_notebook_instance_root_access_disabled.sagemaker_notebook_instance_root_access_disabled import (
                sagemaker_notebook_instance_root_access_disabled,
            )

            check = sagemaker_notebook_instance_root_access_disabled()
            result = check.execute()
            assert len(result) == 0

    def test_instance_root_access_disabled(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_notebook_instances = []
        sagemaker_client.sagemaker_notebook_instances.append(
            NotebookInstance(
                name=test_notebook_instance,
                arn=notebook_instance_arn,
                region=AWS_REGION,
                root_access=False,
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.sagemaker.sagemaker_service.SageMaker",
            sagemaker_client,
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_notebook_instance_root_access_disabled.sagemaker_notebook_instance_root_access_disabled import (
                sagemaker_notebook_instance_root_access_disabled,
            )

            check = sagemaker_notebook_instance_root_access_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search("has root access disabled", result[0].status_extended)
            assert result[0].resource_id == test_notebook_instance
            assert result[0].resource_arn == notebook_instance_arn

    def test_instance_root_access_enabled(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_notebook_instances = []
        sagemaker_client.sagemaker_notebook_instances.append(
            NotebookInstance(
                name=test_notebook_instance,
                arn=notebook_instance_arn,
                region=AWS_REGION,
                root_access=True,
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.sagemaker.sagemaker_service.SageMaker",
            sagemaker_client,
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_notebook_instance_root_access_disabled.sagemaker_notebook_instance_root_access_disabled import (
                sagemaker_notebook_instance_root_access_disabled,
            )

            check = sagemaker_notebook_instance_root_access_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search("has root access enabled", result[0].status_extended)
            assert result[0].resource_id == test_notebook_instance
            assert result[0].resource_arn == notebook_instance_arn
