from unittest import mock

from prowler.lib.utils.utils import SecretsScanError
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

other_notebook_instance = "other-notebook-instance"
other_notebook_instance_arn = (
    f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:"
    f"{AWS_ACCOUNT_NUMBER}:notebook-instance/{other_notebook_instance}"
)

CHECK_MODULE = "prowler.providers.aws.services.sagemaker.sagemaker_notebook_instance_no_secrets.sagemaker_notebook_instance_no_secrets"


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
            mock.patch(f"{CHECK_MODULE}.sagemaker_client", sagemaker_client),
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
            mock.patch(f"{CHECK_MODULE}.sagemaker_client", sagemaker_client),
            mock.patch(
                f"{CHECK_MODULE}.detect_secrets_scan_batch",
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
            assert (
                "does not have a lifecycle configuration" in result[0].status_extended
            )
            assert result[0].resource_id == test_notebook_instance
            assert result[0].resource_arn == notebook_instance_arn

    def test_pass_lifecycle_config_scanned_clean(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.audit_config = {}
        sagemaker_client.sagemaker_notebook_instances = [
            NotebookInstance(
                name=test_notebook_instance,
                arn=notebook_instance_arn,
                region=AWS_REGION_EU_WEST_1,
                lifecycle_config_name="test-lifecycle-config",
                lifecycle_scripts={"OnCreate[0]": "echo hello"},
            )
        ]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.sagemaker_client", sagemaker_client),
            mock.patch(
                f"{CHECK_MODULE}.detect_secrets_scan_batch",
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
            assert "No secrets found" in result[0].status_extended
            assert result[0].resource_id == test_notebook_instance
            assert result[0].resource_arn == notebook_instance_arn

    def test_fail_secret_found(self):
        notebook_instance = NotebookInstance(
            name=test_notebook_instance,
            arn=notebook_instance_arn,
            region=AWS_REGION_EU_WEST_1,
            lifecycle_config_name="test-lifecycle-config",
            lifecycle_scripts={"OnCreate[0]": "echo API_KEY=12345"},
        )

        sagemaker_client = mock.MagicMock
        sagemaker_client.audit_config = {}
        sagemaker_client.sagemaker_notebook_instances = [notebook_instance]

        fake_secret = {"type": "Secret Keyword", "line_number": 1}
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.sagemaker_client", sagemaker_client),
            mock.patch(
                f"{CHECK_MODULE}.detect_secrets_scan_batch",
                return_value={(notebook_instance_arn, "OnCreate[0]"): [fake_secret]},
            ),
            mock.patch(
                f"{CHECK_MODULE}.annotate_verified_secrets",
                lambda *_: None,
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
            assert "OnCreate[0]" in result[0].status_extended
            assert result[0].resource_id == test_notebook_instance
            assert result[0].resource_arn == notebook_instance_arn

    def test_manual_lifecycle_describe_failed(self):
        # Service could not fully describe/decode the lifecycle config.
        notebook_instance = NotebookInstance(
            name=test_notebook_instance,
            arn=notebook_instance_arn,
            region=AWS_REGION_EU_WEST_1,
            lifecycle_config_name="test-lifecycle-config",
            lifecycle_scripts={},
            lifecycle_scan_failed=True,
        )

        sagemaker_client = mock.MagicMock
        sagemaker_client.audit_config = {}
        sagemaker_client.sagemaker_notebook_instances = [notebook_instance]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.sagemaker_client", sagemaker_client),
            mock.patch(
                f"{CHECK_MODULE}.detect_secrets_scan_batch",
                return_value={},
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_notebook_instance_no_secrets.sagemaker_notebook_instance_no_secrets import (
                sagemaker_notebook_instance_no_secrets,
            )

            check = sagemaker_notebook_instance_no_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert result[0].resource_id == test_notebook_instance
            assert result[0].resource_arn == notebook_instance_arn

    def test_manual_scan_error_only_scanned_instances(self):
        # Batch scan fails. The instance with scripts must be MANUAL; the
        # instance without a lifecycle config (nothing to scan) must PASS.
        scanned_instance = NotebookInstance(
            name=test_notebook_instance,
            arn=notebook_instance_arn,
            region=AWS_REGION_EU_WEST_1,
            lifecycle_config_name="test-lifecycle-config",
            lifecycle_scripts={"OnStart[0]": "echo hello"},
        )
        unscanned_instance = NotebookInstance(
            name=other_notebook_instance,
            arn=other_notebook_instance_arn,
            region=AWS_REGION_EU_WEST_1,
            lifecycle_config_name=None,
            lifecycle_scripts={},
        )

        sagemaker_client = mock.MagicMock
        sagemaker_client.audit_config = {}
        sagemaker_client.sagemaker_notebook_instances = [
            scanned_instance,
            unscanned_instance,
        ]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.sagemaker_client", sagemaker_client),
            mock.patch(
                f"{CHECK_MODULE}.detect_secrets_scan_batch",
                side_effect=SecretsScanError("scan failed"),
            ),
        ):
            from prowler.providers.aws.services.sagemaker.sagemaker_notebook_instance_no_secrets.sagemaker_notebook_instance_no_secrets import (
                sagemaker_notebook_instance_no_secrets,
            )

            check = sagemaker_notebook_instance_no_secrets()
            result = check.execute()

            assert len(result) == 2
            results_by_id = {report.resource_id: report for report in result}

            assert results_by_id[test_notebook_instance].status == "MANUAL"
            assert results_by_id[other_notebook_instance].status == "PASS"
            assert (
                "does not have a lifecycle configuration"
                in results_by_id[other_notebook_instance].status_extended
            )
