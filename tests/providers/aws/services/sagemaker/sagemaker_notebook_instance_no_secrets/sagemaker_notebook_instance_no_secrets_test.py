from unittest import mock

from prowler.providers.aws.services.sagemaker.sagemaker_service import (
    NotebookInstance,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

test_notebook_instance = "test-notebook-instance"
notebook_instance_arn = (
    f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:"
    f"{AWS_ACCOUNT_NUMBER}:notebook-instance/{test_notebook_instance}"
)


class Test_sagemaker_notebook_instance_no_secrets:
    def test_no_instances(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_notebook_instances = []
        sagemaker_client.audit_config = {}

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_notebook_instance_no_secrets.sagemaker_notebook_instance_no_secrets.sagemaker_client",
                sagemaker_client,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_notebook_instance_no_secrets.sagemaker_notebook_instance_no_secrets import (
                sagemaker_notebook_instance_no_secrets,
            )

            check = sagemaker_notebook_instance_no_secrets()
            result = check.execute()

            assert len(result) == 0

    def test_pass_no_lifecycle_config(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.audit_config = {}
        sagemaker_client.sagemaker_notebook_instances = [
            NotebookInstance(
                name=test_notebook_instance,
                arn=notebook_instance_arn,
                region=AWS_REGION_EU_WEST_1,
                lifecycle_config_name=None,
            )
        ]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_notebook_instance_no_secrets.sagemaker_notebook_instance_no_secrets.sagemaker_client",
                sagemaker_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_notebook_instance_no_secrets.sagemaker_notebook_instance_no_secrets.detect_secrets_scan_batch",
                return_value={},
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_notebook_instance_no_secrets.sagemaker_notebook_instance_no_secrets import (
                sagemaker_notebook_instance_no_secrets,
            )

            check = sagemaker_notebook_instance_no_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == test_notebook_instance
            assert result[0].resource_arn == notebook_instance_arn

    def test_fail_secret_found(self):
        notebook_instance = NotebookInstance(
            name=test_notebook_instance,
            arn=notebook_instance_arn,
            region=AWS_REGION_EU_WEST_1,
            lifecycle_config_name="test-lifecycle-config",
        )

        regional_client = mock.MagicMock()
        regional_client.describe_notebook_instance_lifecycle_config.return_value = {
            "OnCreate": [{"Content": "ZWNobyBBUElfS0VZPTEyMzQ1"}],
            "OnStart": [],
        }

        sagemaker_client = mock.MagicMock
        sagemaker_client.audit_config = {}
        sagemaker_client.sagemaker_notebook_instances = [notebook_instance]
        sagemaker_client.regional_clients = {
            AWS_REGION_EU_WEST_1: regional_client
        }

        fake_secret = {"type": "Secret Keyword", "line_number": 1}

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_notebook_instance_no_secrets.sagemaker_notebook_instance_no_secrets.sagemaker_client",
                sagemaker_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_notebook_instance_no_secrets.sagemaker_notebook_instance_no_secrets.detect_secrets_scan_batch",
                return_value={(0, "OnCreate[0]"): [fake_secret]},
            ),
            mock.patch(
                "prowler.providers.aws.services.sagemaker.sagemaker_notebook_instance_no_secrets.sagemaker_notebook_instance_no_secrets.annotate_verified_secrets",
                lambda report, secrets: None,
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_notebook_instance_no_secrets.sagemaker_notebook_instance_no_secrets import (
                sagemaker_notebook_instance_no_secrets,
            )

            check = sagemaker_notebook_instance_no_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "Secret Keyword" in result[0].status_extended
            assert result[0].resource_id == test_notebook_instance
            assert result[0].resource_arn == notebook_instance_arn