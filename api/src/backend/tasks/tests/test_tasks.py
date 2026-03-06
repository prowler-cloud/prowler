import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import openai
import pytest
from botocore.exceptions import ClientError
from django_celery_beat.models import IntervalSchedule, PeriodicTask
from django_celery_results.models import TaskResult
from tasks.jobs.lighthouse_providers import (
    _create_bedrock_client,
    _extract_bedrock_credentials,
)
from tasks.tasks import (
    _cleanup_orphan_scheduled_scans,
    _perform_scan_complete_tasks,
    check_integrations_task,
    check_lighthouse_provider_connection_task,
    generate_outputs_task,
    perform_attack_paths_scan_task,
    perform_scheduled_scan_task,
    refresh_lighthouse_provider_models_task,
    s3_integration_task,
    security_hub_integration_task,
)

from api.models import (
    Integration,
    LighthouseProviderConfiguration,
    LighthouseProviderModels,
    Scan,
    StateChoices,
    Task,
)


@pytest.mark.django_db
class TestExtractBedrockCredentials:
    """Unit tests for _extract_bedrock_credentials helper function."""

    def test_extract_access_key_credentials(self, tenants_fixture):
        """Test extraction of access key + secret key credentials."""
        provider_cfg = LighthouseProviderConfiguration(
            tenant_id=tenants_fixture[0].id,
            provider_type=LighthouseProviderConfiguration.LLMProviderChoices.BEDROCK,
            is_active=True,
        )
        provider_cfg.credentials_decoded = {
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-east-1",
        }
        provider_cfg.save()

        result = _extract_bedrock_credentials(provider_cfg)

        assert result is not None
        assert result["access_key_id"] == "AKIAIOSFODNN7EXAMPLE"
        assert result["secret_access_key"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        assert result["region"] == "us-east-1"
        assert "api_key" not in result

    def test_extract_api_key_credentials(self, tenants_fixture):
        """Test extraction of API key (bearer token) credentials."""
        valid_api_key = "ABSKQmVkcm9ja0FQSUtleS" + ("A" * 110)
        provider_cfg = LighthouseProviderConfiguration(
            tenant_id=tenants_fixture[0].id,
            provider_type=LighthouseProviderConfiguration.LLMProviderChoices.BEDROCK,
            is_active=True,
        )
        provider_cfg.credentials_decoded = {
            "api_key": valid_api_key,
            "region": "us-west-2",
        }
        provider_cfg.save()

        result = _extract_bedrock_credentials(provider_cfg)

        assert result is not None
        assert result["api_key"] == valid_api_key
        assert result["region"] == "us-west-2"
        assert "access_key_id" not in result
        assert "secret_access_key" not in result

    def test_api_key_takes_precedence_over_access_keys(self, tenants_fixture):
        """Test that API key is preferred when both auth methods are present."""
        valid_api_key = "ABSKQmVkcm9ja0FQSUtleS" + ("B" * 110)
        provider_cfg = LighthouseProviderConfiguration(
            tenant_id=tenants_fixture[0].id,
            provider_type=LighthouseProviderConfiguration.LLMProviderChoices.BEDROCK,
            is_active=True,
        )
        provider_cfg.credentials_decoded = {
            "api_key": valid_api_key,
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "eu-west-1",
        }
        provider_cfg.save()

        result = _extract_bedrock_credentials(provider_cfg)

        assert result is not None
        assert result["api_key"] == valid_api_key
        assert result["region"] == "eu-west-1"
        assert "access_key_id" not in result

    def test_missing_region_returns_none(self, tenants_fixture):
        """Test that missing region returns None."""
        provider_cfg = LighthouseProviderConfiguration(
            tenant_id=tenants_fixture[0].id,
            provider_type=LighthouseProviderConfiguration.LLMProviderChoices.BEDROCK,
            is_active=True,
        )
        provider_cfg.credentials_decoded = {
            "api_key": "ABSKQmVkcm9ja0FQSUtleS" + ("A" * 110),
        }
        provider_cfg.save()

        result = _extract_bedrock_credentials(provider_cfg)

        assert result is None

    def test_empty_credentials_returns_none(self, tenants_fixture):
        """Test that empty credentials dict returns None (region only is not enough)."""
        provider_cfg = LighthouseProviderConfiguration(
            tenant_id=tenants_fixture[0].id,
            provider_type=LighthouseProviderConfiguration.LLMProviderChoices.BEDROCK,
            is_active=True,
        )
        # Only region, no auth credentials - should return None
        provider_cfg.credentials_decoded = {
            "region": "us-east-1",
        }
        provider_cfg.save()

        result = _extract_bedrock_credentials(provider_cfg)

        assert result is None

    def test_non_dict_credentials_returns_none(self, tenants_fixture):
        """Test that non-dict credentials returns None."""
        provider_cfg = LighthouseProviderConfiguration(
            tenant_id=tenants_fixture[0].id,
            provider_type=LighthouseProviderConfiguration.LLMProviderChoices.BEDROCK,
            is_active=True,
        )
        # Store valid credentials first to pass model validation
        provider_cfg.credentials_decoded = {
            "api_key": "ABSKQmVkcm9ja0FQSUtleS" + ("A" * 110),
            "region": "us-east-1",
        }
        provider_cfg.save()

        # Mock the credentials_decoded property to return a non-dict value
        # This simulates corrupted/invalid stored data
        with patch.object(
            type(provider_cfg),
            "credentials_decoded",
            new_callable=lambda: property(lambda self: "invalid"),
        ):
            result = _extract_bedrock_credentials(provider_cfg)

        assert result is None


class TestCreateBedrockClient:
    """Unit tests for _create_bedrock_client helper function."""

    @patch("tasks.jobs.lighthouse_providers.boto3.client")
    def test_create_client_with_access_keys(self, mock_boto_client):
        """Test creating client with access key authentication."""
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        creds = {
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-east-1",
        }

        result = _create_bedrock_client(creds)

        assert result == mock_client
        mock_boto_client.assert_called_once_with(
            service_name="bedrock",
            region_name="us-east-1",
            aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
            aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )

    @patch("tasks.jobs.lighthouse_providers.Config")
    @patch("tasks.jobs.lighthouse_providers.boto3.client")
    def test_create_client_with_api_key(self, mock_boto_client, mock_config):
        """Test creating client with API key authentication."""
        mock_client = MagicMock()
        mock_events = MagicMock()
        mock_client.meta.events = mock_events
        mock_boto_client.return_value = mock_client
        mock_config_instance = MagicMock()
        mock_config.return_value = mock_config_instance
        valid_api_key = "ABSKQmVkcm9ja0FQSUtleS" + ("A" * 110)

        creds = {
            "api_key": valid_api_key,
            "region": "us-west-2",
        }

        result = _create_bedrock_client(creds)

        assert result == mock_client
        mock_boto_client.assert_called_once_with(
            service_name="bedrock",
            region_name="us-west-2",
            config=mock_config_instance,
        )
        mock_events.register.assert_called_once()
        call_args = mock_events.register.call_args
        assert call_args[0][0] == "before-send.*.*"

        # Verify handler injects bearer token
        handler_fn = call_args[0][1]
        mock_request = MagicMock()
        mock_request.headers = {}
        handler_fn(mock_request)
        assert mock_request.headers["Authorization"] == f"Bearer {valid_api_key}"


# TODO Move this to outputs/reports jobs
@pytest.mark.django_db
class TestGenerateOutputs:
    def setup_method(self):
        self.scan_id = str(uuid.uuid4())
        self.provider_id = str(uuid.uuid4())
        self.tenant_id = str(uuid.uuid4())

    def test_no_findings_returns_early(self):
        with patch("tasks.tasks.ScanSummary.objects.filter") as mock_filter:
            mock_filter.return_value.exists.return_value = False

            result = generate_outputs_task(
                scan_id=self.scan_id,
                provider_id=self.provider_id,
                tenant_id=self.tenant_id,
            )

            assert result == {"upload": False}
            mock_filter.assert_called_once_with(scan_id=self.scan_id)

    @patch("tasks.tasks._upload_to_s3")
    @patch("tasks.tasks._compress_output_files")
    @patch("tasks.tasks.get_compliance_frameworks")
    @patch("tasks.tasks.Compliance.get_bulk")
    @patch("tasks.tasks.initialize_prowler_provider")
    @patch("tasks.tasks.Provider.objects.get")
    @patch("tasks.tasks.ScanSummary.objects.filter")
    @patch("tasks.tasks.Finding.all_objects.filter")
    def test_generate_outputs_happy_path(
        self,
        mock_finding_filter,
        mock_scan_summary_filter,
        mock_provider_get,
        mock_initialize_provider,
        mock_compliance_get_bulk,
        mock_get_available_frameworks,
        mock_compress,
        mock_upload,
    ):
        mock_scan_summary_filter.return_value.exists.return_value = True

        mock_provider = MagicMock()
        mock_provider.uid = "provider-uid"
        mock_provider.provider = "aws"
        mock_provider_get.return_value = mock_provider

        prowler_provider = MagicMock()
        mock_initialize_provider.return_value = prowler_provider

        mock_compliance_get_bulk.return_value = {"cis": MagicMock()}
        mock_get_available_frameworks.return_value = ["cis"]

        dummy_finding = MagicMock(uid="f1")
        mock_finding_filter.return_value.order_by.return_value.iterator.return_value = [
            [dummy_finding],
            True,
        ]

        mock_transformed_stats = {"some": "stats"}
        with (
            patch(
                "tasks.tasks.FindingOutput._transform_findings_stats",
                return_value=mock_transformed_stats,
            ),
            patch(
                "tasks.tasks.FindingOutput.transform_api_finding",
                return_value={"transformed": "f1"},
            ),
            patch(
                "tasks.tasks.OUTPUT_FORMATS_MAPPING",
                {
                    "json": {
                        "class": MagicMock(name="JSONWriter"),
                        "suffix": ".json",
                        "kwargs": {},
                    }
                },
            ),
            patch(
                "tasks.tasks.COMPLIANCE_CLASS_MAP",
                {"aws": [(lambda x: True, MagicMock(name="CSVCompliance"))]},
            ),
            patch(
                "tasks.tasks._generate_output_directory",
                return_value=(
                    "/tmp/test/out-dir",
                    "/tmp/test/comp-dir",
                ),
            ),
            patch("tasks.tasks.Scan.all_objects.filter") as mock_scan_update,
            patch("tasks.tasks.rmtree"),
        ):
            mock_compress.return_value = "/tmp/zipped.zip"
            mock_upload.return_value = "s3://bucket/zipped.zip"

            result = generate_outputs_task(
                scan_id=self.scan_id,
                provider_id=self.provider_id,
                tenant_id=self.tenant_id,
            )

            assert result == {"upload": True}
            mock_scan_update.return_value.update.assert_called_once_with(
                output_location="s3://bucket/zipped.zip"
            )

    def test_generate_outputs_fails_upload(self):
        with (
            patch("tasks.tasks.ScanSummary.objects.filter") as mock_filter,
            patch("tasks.tasks.Provider.objects.get"),
            patch("tasks.tasks.initialize_prowler_provider"),
            patch("tasks.tasks.Compliance.get_bulk"),
            patch("tasks.tasks.get_compliance_frameworks"),
            patch("tasks.tasks.Finding.all_objects.filter") as mock_findings,
            patch(
                "tasks.tasks._generate_output_directory",
                return_value=("/tmp/test/out", "/tmp/test/comp"),
            ),
            patch("tasks.tasks.FindingOutput._transform_findings_stats"),
            patch("tasks.tasks.FindingOutput.transform_api_finding"),
            patch(
                "tasks.tasks.OUTPUT_FORMATS_MAPPING",
                {
                    "json": {
                        "class": MagicMock(name="Writer"),
                        "suffix": ".json",
                        "kwargs": {},
                    }
                },
            ),
            patch(
                "tasks.tasks.COMPLIANCE_CLASS_MAP",
                {"aws": [(lambda x: True, MagicMock())]},
            ),
            patch("tasks.tasks._compress_output_files", return_value="/tmp/compressed"),
            patch("tasks.tasks._upload_to_s3", return_value=None),
            patch("tasks.tasks.Scan.all_objects.filter") as mock_scan_update,
            patch("tasks.tasks.rmtree"),
        ):
            mock_filter.return_value.exists.return_value = True
            mock_findings.return_value.order_by.return_value.iterator.return_value = [
                [MagicMock()],
                True,
            ]

            result = generate_outputs_task(
                scan_id="scan",
                provider_id=self.provider_id,
                tenant_id=self.tenant_id,
            )

            assert result == {"upload": False}
            mock_scan_update.return_value.update.assert_called_once()

    def test_generate_outputs_triggers_html_extra_update(self):
        mock_finding_output = MagicMock()
        mock_finding_output.compliance = {"cis": ["requirement-1", "requirement-2"]}

        html_writer_mock = MagicMock()
        html_writer_mock._data = []
        html_writer_mock.close_file = False
        html_writer_mock.transform = MagicMock()
        html_writer_mock.batch_write_data_to_file = MagicMock()

        compliance_writer_mock = MagicMock()
        compliance_writer_mock._data = []
        compliance_writer_mock.close_file = False
        compliance_writer_mock.transform = MagicMock()
        compliance_writer_mock.batch_write_data_to_file = MagicMock()

        # Create a mock class that returns our mock instance when called
        mock_compliance_class = MagicMock(return_value=compliance_writer_mock)

        mock_provider = MagicMock()
        mock_provider.provider = "aws"
        mock_provider.uid = "test-provider-uid"

        with (
            patch("tasks.tasks.ScanSummary.objects.filter") as mock_filter,
            patch("tasks.tasks.Provider.objects.get", return_value=mock_provider),
            patch("tasks.tasks.initialize_prowler_provider"),
            patch("tasks.tasks.Compliance.get_bulk", return_value={"cis": MagicMock()}),
            patch("tasks.tasks.get_compliance_frameworks", return_value=["cis"]),
            patch("tasks.tasks.Finding.all_objects.filter") as mock_findings,
            patch(
                "tasks.tasks._generate_output_directory",
                return_value=("/tmp/test/out", "/tmp/test/comp"),
            ),
            patch(
                "tasks.tasks.FindingOutput._transform_findings_stats",
                return_value={"some": "stats"},
            ),
            patch(
                "tasks.tasks.FindingOutput.transform_api_finding",
                return_value=mock_finding_output,
            ),
            patch("tasks.tasks._compress_output_files", return_value="/tmp/compressed"),
            patch("tasks.tasks._upload_to_s3", return_value="s3://bucket/f.zip"),
            patch("tasks.tasks.Scan.all_objects.filter"),
            patch("tasks.tasks.rmtree"),
            patch(
                "tasks.tasks.OUTPUT_FORMATS_MAPPING",
                {
                    "html": {
                        "class": lambda *args, **kwargs: html_writer_mock,
                        "suffix": ".html",
                        "kwargs": {},
                    }
                },
            ),
            patch(
                "tasks.tasks.COMPLIANCE_CLASS_MAP",
                {"aws": [(lambda x: True, mock_compliance_class)]},
            ),
        ):
            mock_filter.return_value.exists.return_value = True
            mock_findings.return_value.order_by.return_value.iterator.return_value = [
                [MagicMock()],
                True,
            ]

            generate_outputs_task(
                scan_id=self.scan_id,
                provider_id=self.provider_id,
                tenant_id=self.tenant_id,
            )
            html_writer_mock.batch_write_data_to_file.assert_called_once()

    def test_transform_called_only_on_second_batch(self):
        raw1 = MagicMock()
        raw2 = MagicMock()

        tf1 = MagicMock()
        tf1.compliance = {}
        tf2 = MagicMock()
        tf2.compliance = {}

        writer_instances = []

        class TrackingWriter:
            def __init__(self, findings, file_path, file_extension, from_cli):
                self.transform_called = 0
                self.batch_write_data_to_file = MagicMock()
                self._data = []
                self.close_file = False
                writer_instances.append(self)

            def transform(self, fos):
                self.transform_called += 1

        with (
            patch("tasks.tasks.ScanSummary.objects.filter") as mock_summary,
            patch("tasks.tasks.Provider.objects.get"),
            patch("tasks.tasks.initialize_prowler_provider"),
            patch("tasks.tasks.Compliance.get_bulk"),
            patch("tasks.tasks.get_compliance_frameworks", return_value=[]),
            patch("tasks.tasks.FindingOutput._transform_findings_stats"),
            patch(
                "tasks.tasks.FindingOutput.transform_api_finding",
                side_effect=[tf1, tf2],
            ),
            patch(
                "tasks.tasks._generate_output_directory",
                return_value=(
                    "/tmp/test/outdir",
                    "/tmp/test/compdir",
                ),
            ),
            patch("tasks.tasks._compress_output_files", return_value="outdir.zip"),
            patch("tasks.tasks._upload_to_s3", return_value="s3://bucket/outdir.zip"),
            patch("tasks.tasks.Scan.all_objects.filter"),
            patch("tasks.tasks.rmtree"),
            patch(
                "tasks.tasks.batched",
                return_value=[
                    ([raw1], False),
                    ([raw2], True),
                ],
            ),
        ):
            mock_summary.return_value.exists.return_value = True

            with patch(
                "tasks.tasks.OUTPUT_FORMATS_MAPPING",
                {
                    "json": {
                        "class": TrackingWriter,
                        "suffix": ".json",
                        "kwargs": {},
                    }
                },
            ):
                result = generate_outputs_task(
                    scan_id=self.scan_id,
                    provider_id=self.provider_id,
                    tenant_id=self.tenant_id,
                )

        assert result == {"upload": True}
        assert len(writer_instances) == 1
        writer = writer_instances[0]
        assert writer.transform_called == 1

    def test_compliance_transform_called_on_second_batch(self):
        raw1 = MagicMock()
        raw2 = MagicMock()
        compliance_obj = MagicMock()
        writer_instances = []

        class TrackingComplianceWriter:
            def __init__(self, *args, **kwargs):
                self.transform_calls = []
                self._data = []
                self.close_file = False
                writer_instances.append(self)

            def transform(self, fos, comp_obj, name):
                self.transform_calls.append((fos, comp_obj, name))

            def batch_write_data_to_file(self):
                # Mock implementation - do nothing
                pass

        two_batches = [
            ([raw1], False),
            ([raw2], True),
        ]

        with (
            patch("tasks.tasks.ScanSummary.objects.filter") as mock_summary,
            patch(
                "tasks.tasks.Provider.objects.get",
                return_value=MagicMock(uid="UID", provider="aws"),
            ),
            patch("tasks.tasks.initialize_prowler_provider"),
            patch(
                "tasks.tasks.Compliance.get_bulk", return_value={"cis": compliance_obj}
            ),
            patch("tasks.tasks.get_compliance_frameworks", return_value=["cis"]),
            patch(
                "tasks.tasks._generate_output_directory",
                return_value=(
                    "/tmp/test/outdir",
                    "/tmp/test/compdir",
                ),
            ),
            patch("tasks.tasks.FindingOutput._transform_findings_stats"),
            patch(
                "tasks.tasks.FindingOutput.transform_api_finding",
                side_effect=lambda f, prov: f,
            ),
            patch("tasks.tasks._compress_output_files", return_value="outdir.zip"),
            patch("tasks.tasks._upload_to_s3", return_value="s3://bucket/outdir.zip"),
            patch(
                "tasks.tasks.Scan.all_objects.filter",
                return_value=MagicMock(update=lambda **kw: None),
            ),
            patch("tasks.tasks.batched", return_value=two_batches),
            patch("tasks.tasks.OUTPUT_FORMATS_MAPPING", {}),
            patch("tasks.tasks.rmtree"),
            patch(
                "tasks.tasks.COMPLIANCE_CLASS_MAP",
                {"aws": [(lambda name: True, TrackingComplianceWriter)]},
            ),
        ):
            mock_summary.return_value.exists.return_value = True

            result = generate_outputs_task(
                scan_id=self.scan_id,
                provider_id=self.provider_id,
                tenant_id=self.tenant_id,
            )

        assert len(writer_instances) == 1
        writer = writer_instances[0]
        assert writer.transform_calls == [([raw2], compliance_obj, "cis")]
        assert result == {"upload": True}

    # TODO: We need to add a periodic task to delete old output files
    def test_generate_outputs_logs_rmtree_exception(self, caplog):
        mock_finding_output = MagicMock()
        mock_finding_output.compliance = {"cis": ["requirement-1", "requirement-2"]}

        json_writer_mock = MagicMock()
        json_writer_mock._data = []
        json_writer_mock.close_file = False
        json_writer_mock.transform = MagicMock()
        json_writer_mock.batch_write_data_to_file = MagicMock()

        compliance_writer_mock = MagicMock()
        compliance_writer_mock._data = []
        compliance_writer_mock.close_file = False
        compliance_writer_mock.transform = MagicMock()
        compliance_writer_mock.batch_write_data_to_file = MagicMock()

        # Create a mock class that returns our mock instance when called
        mock_compliance_class = MagicMock(return_value=compliance_writer_mock)

        mock_provider = MagicMock()
        mock_provider.provider = "aws"
        mock_provider.uid = "test-provider-uid"

        with (
            patch("tasks.tasks.ScanSummary.objects.filter") as mock_filter,
            patch("tasks.tasks.Provider.objects.get", return_value=mock_provider),
            patch("tasks.tasks.initialize_prowler_provider"),
            patch("tasks.tasks.Compliance.get_bulk", return_value={"cis": MagicMock()}),
            patch("tasks.tasks.get_compliance_frameworks", return_value=["cis"]),
            patch("tasks.tasks.Finding.all_objects.filter") as mock_findings,
            patch(
                "tasks.tasks._generate_output_directory",
                return_value=("/tmp/test/out", "/tmp/test/comp"),
            ),
            patch(
                "tasks.tasks.FindingOutput._transform_findings_stats",
                return_value={"some": "stats"},
            ),
            patch(
                "tasks.tasks.FindingOutput.transform_api_finding",
                return_value=mock_finding_output,
            ),
            patch("tasks.tasks._compress_output_files", return_value="/tmp/compressed"),
            patch("tasks.tasks._upload_to_s3", return_value="s3://bucket/file.zip"),
            patch("tasks.tasks.Scan.all_objects.filter"),
            patch("tasks.tasks.rmtree", side_effect=Exception("Test deletion error")),
            patch(
                "tasks.tasks.OUTPUT_FORMATS_MAPPING",
                {
                    "json": {
                        "class": lambda *args, **kwargs: json_writer_mock,
                        "suffix": ".json",
                        "kwargs": {},
                    }
                },
            ),
            patch(
                "tasks.tasks.COMPLIANCE_CLASS_MAP",
                {"aws": [(lambda x: True, mock_compliance_class)]},
            ),
        ):
            mock_filter.return_value.exists.return_value = True
            mock_findings.return_value.order_by.return_value.iterator.return_value = [
                [MagicMock()],
                True,
            ]

            with caplog.at_level("ERROR"):
                generate_outputs_task(
                    scan_id=self.scan_id,
                    provider_id=self.provider_id,
                    tenant_id=self.tenant_id,
                )
                assert "Error deleting output files" in caplog.text

    @patch("tasks.tasks.rls_transaction")
    @patch("tasks.tasks.Integration.objects.filter")
    def test_generate_outputs_filters_enabled_s3_integrations(
        self, mock_integration_filter, mock_rls
    ):
        """Test that generate_outputs_task only processes enabled S3 integrations."""
        with (
            patch("tasks.tasks.ScanSummary.objects.filter") as mock_summary,
            patch("tasks.tasks.Provider.objects.get"),
            patch("tasks.tasks.initialize_prowler_provider"),
            patch("tasks.tasks.Compliance.get_bulk"),
            patch("tasks.tasks.get_compliance_frameworks", return_value=[]),
            patch("tasks.tasks.Finding.all_objects.filter") as mock_findings,
            patch(
                "tasks.tasks._generate_output_directory",
                return_value=("/tmp/test/out", "/tmp/test/comp"),
            ),
            patch("tasks.tasks.FindingOutput._transform_findings_stats"),
            patch("tasks.tasks.FindingOutput.transform_api_finding"),
            patch("tasks.tasks._compress_output_files", return_value="/tmp/compressed"),
            patch("tasks.tasks._upload_to_s3", return_value="s3://bucket/file.zip"),
            patch("tasks.tasks.Scan.all_objects.filter"),
            patch("tasks.tasks.rmtree"),
            patch("tasks.tasks.s3_integration_task.apply_async") as mock_s3_task,
        ):
            mock_summary.return_value.exists.return_value = True
            mock_findings.return_value.order_by.return_value.iterator.return_value = [
                [MagicMock()],
                True,
            ]
            mock_integration_filter.return_value = [MagicMock()]
            mock_rls.return_value.__enter__.return_value = None

            with (
                patch("tasks.tasks.OUTPUT_FORMATS_MAPPING", {}),
                patch("tasks.tasks.COMPLIANCE_CLASS_MAP", {"aws": []}),
            ):
                generate_outputs_task(
                    scan_id=self.scan_id,
                    provider_id=self.provider_id,
                    tenant_id=self.tenant_id,
                )

            # Verify the S3 integrations filters
            mock_integration_filter.assert_called_once_with(
                integrationproviderrelationship__provider_id=self.provider_id,
                integration_type=Integration.IntegrationChoices.AMAZON_S3,
                enabled=True,
            )
            mock_s3_task.assert_called_once()


class TestScanCompleteTasks:
    @patch("tasks.tasks.aggregate_attack_surface_task.apply_async")
    @patch("tasks.tasks.chain")
    @patch("tasks.tasks.create_compliance_requirements_task.si")
    @patch("tasks.tasks.update_provider_compliance_scores_task.si")
    @patch("tasks.tasks.perform_scan_summary_task.si")
    @patch("tasks.tasks.generate_outputs_task.si")
    @patch("tasks.tasks.generate_compliance_reports_task.si")
    @patch("tasks.tasks.check_integrations_task.si")
    @patch("tasks.tasks.perform_attack_paths_scan_task.apply_async")
    @patch("tasks.tasks.can_provider_run_attack_paths_scan", return_value=False)
    def test_scan_complete_tasks(
        self,
        mock_can_run_attack_paths,
        mock_attack_paths_task,
        mock_check_integrations_task,
        mock_compliance_reports_task,
        mock_outputs_task,
        mock_scan_summary_task,
        mock_update_compliance_scores_task,
        mock_compliance_requirements_task,
        mock_chain,
        mock_attack_surface_task,
    ):
        """Test that scan complete tasks are properly orchestrated with optimized reports."""
        _perform_scan_complete_tasks("tenant-id", "scan-id", "provider-id")

        # Verify compliance requirements task is called via chain
        mock_compliance_requirements_task.assert_called_once_with(
            tenant_id="tenant-id", scan_id="scan-id"
        )

        # Verify update provider compliance scores task is called via chain
        mock_update_compliance_scores_task.assert_called_once_with(
            tenant_id="tenant-id", scan_id="scan-id"
        )

        # Verify attack surface task is called
        mock_attack_surface_task.assert_called_once_with(
            kwargs={"tenant_id": "tenant-id", "scan_id": "scan-id"},
        )

        # Verify scan summary task is called
        mock_scan_summary_task.assert_called_once_with(
            scan_id="scan-id",
            tenant_id="tenant-id",
        )

        # Verify outputs task is called
        mock_outputs_task.assert_called_once_with(
            scan_id="scan-id",
            provider_id="provider-id",
            tenant_id="tenant-id",
        )

        # Verify optimized compliance reports task is called (replaces individual tasks)
        mock_compliance_reports_task.assert_called_once_with(
            tenant_id="tenant-id",
            scan_id="scan-id",
            provider_id="provider-id",
        )

        # Verify integrations task is called
        mock_check_integrations_task.assert_called_once_with(
            tenant_id="tenant-id",
            provider_id="provider-id",
            scan_id="scan-id",
        )

        # Attack Paths task should be skipped when provider cannot run it
        mock_attack_paths_task.assert_not_called()


class TestAttackPathsTasks:
    @staticmethod
    @contextmanager
    def _override_task_request(task, **attrs):
        request = task.request
        sentinel = object()
        previous = {key: getattr(request, key, sentinel) for key in attrs}
        for key, value in attrs.items():
            setattr(request, key, value)

        try:
            yield
        finally:
            for key, prev in previous.items():
                if prev is sentinel:
                    if hasattr(request, key):
                        delattr(request, key)
                else:
                    setattr(request, key, prev)

    def test_perform_attack_paths_scan_task_calls_runner(self):
        with (
            patch("tasks.tasks.attack_paths_scan") as mock_attack_paths_scan,
            self._override_task_request(
                perform_attack_paths_scan_task, id="celery-task-id"
            ),
        ):
            mock_attack_paths_scan.return_value = {"status": "ok"}

            result = perform_attack_paths_scan_task.run(
                tenant_id="tenant-id", scan_id="scan-id"
            )

        mock_attack_paths_scan.assert_called_once_with(
            tenant_id="tenant-id", scan_id="scan-id", task_id="celery-task-id"
        )
        assert result == {"status": "ok"}

    def test_perform_attack_paths_scan_task_propagates_exception(self):
        with (
            patch(
                "tasks.tasks.attack_paths_scan",
                side_effect=RuntimeError("Exception to propagate"),
            ) as mock_attack_paths_scan,
            self._override_task_request(
                perform_attack_paths_scan_task, id="celery-task-error"
            ),
        ):
            with pytest.raises(RuntimeError, match="Exception to propagate"):
                perform_attack_paths_scan_task.run(
                    tenant_id="tenant-id", scan_id="scan-id"
                )

        mock_attack_paths_scan.assert_called_once_with(
            tenant_id="tenant-id", scan_id="scan-id", task_id="celery-task-error"
        )


@pytest.mark.django_db
class TestCheckIntegrationsTask:
    def setup_method(self):
        self.scan_id = str(uuid.uuid4())
        self.provider_id = str(uuid.uuid4())
        self.tenant_id = str(uuid.uuid4())
        self.output_directory = "/tmp/some-output-dir"

    @patch("tasks.tasks.rls_transaction")
    @patch("tasks.tasks.Integration.objects.filter")
    def test_check_integrations_no_integrations(
        self, mock_integration_filter, mock_rls
    ):
        mock_integration_filter.return_value.exists.return_value = False
        # Ensure rls_transaction is mocked
        mock_rls.return_value.__enter__.return_value = None

        result = check_integrations_task(
            tenant_id=self.tenant_id,
            provider_id=self.provider_id,
        )

        assert result == {"integrations_processed": 0}
        mock_integration_filter.assert_called_once_with(
            integrationproviderrelationship__provider_id=self.provider_id,
            enabled=True,
        )

    @patch("tasks.tasks.security_hub_integration_task")
    @patch("tasks.tasks.group")
    @patch("tasks.tasks.rls_transaction")
    @patch("tasks.tasks.Integration.objects.filter")
    def test_check_integrations_security_hub_success(
        self, mock_integration_filter, mock_rls, mock_group, mock_security_hub_task
    ):
        """Test that SecurityHub integrations are processed correctly."""
        # Mock that we have SecurityHub integrations
        mock_integrations = MagicMock()
        mock_integrations.exists.return_value = True

        # Mock SecurityHub integrations to return existing integrations
        mock_security_hub_integrations = MagicMock()
        mock_security_hub_integrations.exists.return_value = True

        # Set up the filter chain
        mock_integration_filter.return_value = mock_integrations
        mock_integrations.filter.return_value = mock_security_hub_integrations

        # Mock the task signature
        mock_task_signature = MagicMock()
        mock_security_hub_task.s.return_value = mock_task_signature

        # Mock group job
        mock_job = MagicMock()
        mock_group.return_value = mock_job

        # Ensure rls_transaction is mocked
        mock_rls.return_value.__enter__.return_value = None

        # Execute the function
        result = check_integrations_task(
            tenant_id=self.tenant_id,
            provider_id=self.provider_id,
            scan_id="test-scan-id",
        )

        # Should process 1 SecurityHub integration
        assert result == {"integrations_processed": 1}

        # Verify the integration filter was called
        mock_integration_filter.assert_called_once_with(
            integrationproviderrelationship__provider_id=self.provider_id,
            enabled=True,
        )

        # Verify SecurityHub integrations were filtered
        mock_integrations.filter.assert_called_once_with(
            integration_type=Integration.IntegrationChoices.AWS_SECURITY_HUB
        )

        # Verify SecurityHub task was created with correct parameters
        mock_security_hub_task.s.assert_called_once_with(
            tenant_id=self.tenant_id,
            provider_id=self.provider_id,
            scan_id="test-scan-id",
        )

        # Verify group was called and job was executed
        mock_group.assert_called_once_with([mock_task_signature])
        mock_job.apply_async.assert_called_once()

    @patch("tasks.tasks.rls_transaction")
    @patch("tasks.tasks.Integration.objects.filter")
    def test_check_integrations_disabled_integrations_ignored(
        self, mock_integration_filter, mock_rls
    ):
        """Test that disabled integrations are not processed."""
        mock_integration_filter.return_value.exists.return_value = False
        mock_rls.return_value.__enter__.return_value = None

        result = check_integrations_task(
            tenant_id=self.tenant_id,
            provider_id=self.provider_id,
        )

        assert result == {"integrations_processed": 0}
        mock_integration_filter.assert_called_once_with(
            integrationproviderrelationship__provider_id=self.provider_id,
            enabled=True,
        )

    @patch("tasks.tasks.s3_integration_task")
    @patch("tasks.tasks.Integration.objects.filter")
    @patch("tasks.tasks.ScanSummary.objects.filter")
    @patch("tasks.tasks.Provider.objects.get")
    @patch("tasks.tasks.initialize_prowler_provider")
    @patch("tasks.tasks.Compliance.get_bulk")
    @patch("tasks.tasks.get_compliance_frameworks")
    @patch("tasks.tasks.Finding.all_objects.filter")
    @patch("tasks.tasks._generate_output_directory")
    @patch("tasks.tasks.FindingOutput._transform_findings_stats")
    @patch("tasks.tasks.FindingOutput.transform_api_finding")
    @patch("tasks.tasks._compress_output_files")
    @patch("tasks.tasks._upload_to_s3")
    @patch("tasks.tasks.Scan.all_objects.filter")
    @patch("tasks.tasks.rmtree")
    def test_generate_outputs_with_asff_for_aws_with_security_hub(
        self,
        mock_rmtree,
        mock_scan_update,
        mock_upload,
        mock_compress,
        mock_transform_finding,
        mock_transform_stats,
        mock_generate_dir,
        mock_findings,
        mock_get_frameworks,
        mock_compliance_bulk,
        mock_initialize_provider,
        mock_provider_get,
        mock_scan_summary,
        mock_integration_filter,
        mock_s3_task,
    ):
        """Test that ASFF output is generated for AWS providers with SecurityHub integration."""
        # Setup
        mock_scan_summary_qs = MagicMock()
        mock_scan_summary_qs.exists.return_value = True
        mock_scan_summary.return_value = mock_scan_summary_qs

        # Mock AWS provider
        mock_provider = MagicMock()
        mock_provider.uid = "aws-account-123"
        mock_provider.provider = "aws"
        mock_provider_get.return_value = mock_provider

        # Mock SecurityHub integration exists
        mock_security_hub_integrations = MagicMock()
        mock_security_hub_integrations.exists.return_value = True
        mock_integration_filter.return_value = mock_security_hub_integrations

        # Mock s3_integration_task
        mock_s3_task.apply_async.return_value.get.return_value = True

        # Mock other necessary components
        mock_initialize_provider.return_value = MagicMock()
        mock_compliance_bulk.return_value = {}
        mock_get_frameworks.return_value = []
        mock_generate_dir.return_value = ("out-dir", "comp-dir")
        mock_transform_stats.return_value = {"stats": "data"}

        # Mock findings
        mock_finding = MagicMock()
        mock_findings.return_value.order_by.return_value.iterator.return_value = [
            [mock_finding],
            True,
        ]
        mock_transform_finding.return_value = MagicMock(compliance={})

        # Track which output formats were created
        created_writers = {}

        def track_writer_creation(cls_type):
            def factory(*args, **kwargs):
                writer = MagicMock()
                writer._data = []
                writer.transform = MagicMock()
                writer.batch_write_data_to_file = MagicMock()
                created_writers[cls_type] = writer
                return writer

            return factory

        # Mock OUTPUT_FORMATS_MAPPING with tracking
        with patch(
            "tasks.tasks.OUTPUT_FORMATS_MAPPING",
            {
                "csv": {
                    "class": track_writer_creation("csv"),
                    "suffix": ".csv",
                    "kwargs": {},
                },
                "json-asff": {
                    "class": track_writer_creation("asff"),
                    "suffix": ".asff.json",
                    "kwargs": {},
                },
                "json-ocsf": {
                    "class": track_writer_creation("ocsf"),
                    "suffix": ".ocsf.json",
                    "kwargs": {},
                },
            },
        ):
            mock_compress.return_value = "/tmp/compressed.zip"
            mock_upload.return_value = "s3://bucket/file.zip"

            # Execute
            result = generate_outputs_task(
                scan_id=self.scan_id,
                provider_id=self.provider_id,
                tenant_id=self.tenant_id,
            )

            # Verify ASFF was created for AWS with SecurityHub
            assert "asff" in created_writers, "ASFF writer should be created"
            assert "csv" in created_writers, "CSV writer should be created"
            assert "ocsf" in created_writers, "OCSF writer should be created"

            # Verify SecurityHub integration was checked
            assert mock_integration_filter.call_count == 2
            mock_integration_filter.assert_any_call(
                integrationproviderrelationship__provider_id=self.provider_id,
                integration_type=Integration.IntegrationChoices.AWS_SECURITY_HUB,
                enabled=True,
            )

            assert result == {"upload": True}

    @patch("tasks.tasks.s3_integration_task")
    @patch("tasks.tasks.Integration.objects.filter")
    @patch("tasks.tasks.ScanSummary.objects.filter")
    @patch("tasks.tasks.Provider.objects.get")
    @patch("tasks.tasks.initialize_prowler_provider")
    @patch("tasks.tasks.Compliance.get_bulk")
    @patch("tasks.tasks.get_compliance_frameworks")
    @patch("tasks.tasks.Finding.all_objects.filter")
    @patch("tasks.tasks._generate_output_directory")
    @patch("tasks.tasks.FindingOutput._transform_findings_stats")
    @patch("tasks.tasks.FindingOutput.transform_api_finding")
    @patch("tasks.tasks._compress_output_files")
    @patch("tasks.tasks._upload_to_s3")
    @patch("tasks.tasks.Scan.all_objects.filter")
    @patch("tasks.tasks.rmtree")
    def test_generate_outputs_no_asff_for_aws_without_security_hub(
        self,
        mock_rmtree,
        mock_scan_update,
        mock_upload,
        mock_compress,
        mock_transform_finding,
        mock_transform_stats,
        mock_generate_dir,
        mock_findings,
        mock_get_frameworks,
        mock_compliance_bulk,
        mock_initialize_provider,
        mock_provider_get,
        mock_scan_summary,
        mock_integration_filter,
        mock_s3_task,
    ):
        """Test that ASFF output is NOT generated for AWS providers without SecurityHub integration."""
        # Setup
        mock_scan_summary_qs = MagicMock()
        mock_scan_summary_qs.exists.return_value = True
        mock_scan_summary.return_value = mock_scan_summary_qs

        # Mock AWS provider
        mock_provider = MagicMock()
        mock_provider.uid = "aws-account-123"
        mock_provider.provider = "aws"
        mock_provider_get.return_value = mock_provider

        # Mock NO SecurityHub integration
        mock_security_hub_integrations = MagicMock()
        mock_security_hub_integrations.exists.return_value = False
        mock_integration_filter.return_value = mock_security_hub_integrations

        # Mock other necessary components
        mock_initialize_provider.return_value = MagicMock()
        mock_compliance_bulk.return_value = {}
        mock_get_frameworks.return_value = []
        mock_generate_dir.return_value = ("out-dir", "comp-dir")
        mock_transform_stats.return_value = {"stats": "data"}

        # Mock findings
        mock_finding = MagicMock()
        mock_findings.return_value.order_by.return_value.iterator.return_value = [
            [mock_finding],
            True,
        ]
        mock_transform_finding.return_value = MagicMock(compliance={})

        # Track which output formats were created
        created_writers = {}

        def track_writer_creation(cls_type):
            def factory(*args, **kwargs):
                writer = MagicMock()
                writer._data = []
                writer.transform = MagicMock()
                writer.batch_write_data_to_file = MagicMock()
                created_writers[cls_type] = writer
                return writer

            return factory

        # Mock OUTPUT_FORMATS_MAPPING with tracking
        with patch(
            "tasks.tasks.OUTPUT_FORMATS_MAPPING",
            {
                "csv": {
                    "class": track_writer_creation("csv"),
                    "suffix": ".csv",
                    "kwargs": {},
                },
                "json-asff": {
                    "class": track_writer_creation("asff"),
                    "suffix": ".asff.json",
                    "kwargs": {},
                },
                "json-ocsf": {
                    "class": track_writer_creation("ocsf"),
                    "suffix": ".ocsf.json",
                    "kwargs": {},
                },
            },
        ):
            mock_compress.return_value = "/tmp/compressed.zip"
            mock_upload.return_value = "s3://bucket/file.zip"

            # Execute
            result = generate_outputs_task(
                scan_id=self.scan_id,
                provider_id=self.provider_id,
                tenant_id=self.tenant_id,
            )

            # Verify ASFF was NOT created when no SecurityHub integration
            assert "asff" not in created_writers, "ASFF writer should NOT be created"
            assert "csv" in created_writers, "CSV writer should be created"
            assert "ocsf" in created_writers, "OCSF writer should be created"

            # Verify SecurityHub integration was checked
            assert mock_integration_filter.call_count == 2
            mock_integration_filter.assert_any_call(
                integrationproviderrelationship__provider_id=self.provider_id,
                integration_type=Integration.IntegrationChoices.AWS_SECURITY_HUB,
                enabled=True,
            )

            assert result == {"upload": True}

    @patch("tasks.tasks.ScanSummary.objects.filter")
    @patch("tasks.tasks.Provider.objects.get")
    @patch("tasks.tasks.initialize_prowler_provider")
    @patch("tasks.tasks.Compliance.get_bulk")
    @patch("tasks.tasks.get_compliance_frameworks")
    @patch("tasks.tasks.Finding.all_objects.filter")
    @patch("tasks.tasks._generate_output_directory")
    @patch("tasks.tasks.FindingOutput._transform_findings_stats")
    @patch("tasks.tasks.FindingOutput.transform_api_finding")
    @patch("tasks.tasks._compress_output_files")
    @patch("tasks.tasks._upload_to_s3")
    @patch("tasks.tasks.Scan.all_objects.filter")
    @patch("tasks.tasks.rmtree")
    def test_generate_outputs_no_asff_for_non_aws_provider(
        self,
        mock_rmtree,
        mock_scan_update,
        mock_upload,
        mock_compress,
        mock_transform_finding,
        mock_transform_stats,
        mock_generate_dir,
        mock_findings,
        mock_get_frameworks,
        mock_compliance_bulk,
        mock_initialize_provider,
        mock_provider_get,
        mock_scan_summary,
    ):
        """Test that ASFF output is NOT generated for non-AWS providers (e.g., Azure, GCP)."""
        # Setup
        mock_scan_summary_qs = MagicMock()
        mock_scan_summary_qs.exists.return_value = True
        mock_scan_summary.return_value = mock_scan_summary_qs

        # Mock Azure provider (non-AWS)
        mock_provider = MagicMock()
        mock_provider.uid = "azure-subscription-123"
        mock_provider.provider = "azure"  # Non-AWS provider
        mock_provider_get.return_value = mock_provider

        # Mock other necessary components
        mock_initialize_provider.return_value = MagicMock()
        mock_compliance_bulk.return_value = {}
        mock_get_frameworks.return_value = []
        mock_generate_dir.return_value = ("out-dir", "comp-dir")
        mock_transform_stats.return_value = {"stats": "data"}

        # Mock findings
        mock_finding = MagicMock()
        mock_findings.return_value.order_by.return_value.iterator.return_value = [
            [mock_finding],
            True,
        ]
        mock_transform_finding.return_value = MagicMock(compliance={})

        # Track which output formats were created
        created_writers = {}

        def track_writer_creation(cls_type):
            def factory(*args, **kwargs):
                writer = MagicMock()
                writer._data = []
                writer.transform = MagicMock()
                writer.batch_write_data_to_file = MagicMock()
                created_writers[cls_type] = writer
                return writer

            return factory

        # Mock OUTPUT_FORMATS_MAPPING with tracking
        with patch(
            "tasks.tasks.OUTPUT_FORMATS_MAPPING",
            {
                "csv": {
                    "class": track_writer_creation("csv"),
                    "suffix": ".csv",
                    "kwargs": {},
                },
                "json-asff": {
                    "class": track_writer_creation("asff"),
                    "suffix": ".asff.json",
                    "kwargs": {},
                },
                "json-ocsf": {
                    "class": track_writer_creation("ocsf"),
                    "suffix": ".ocsf.json",
                    "kwargs": {},
                },
            },
        ):
            mock_compress.return_value = "/tmp/compressed.zip"
            mock_upload.return_value = "s3://bucket/file.zip"

            # Execute
            result = generate_outputs_task(
                scan_id=self.scan_id,
                provider_id=self.provider_id,
                tenant_id=self.tenant_id,
            )

            # Verify ASFF was NOT created for non-AWS provider
            assert (
                "asff" not in created_writers
            ), "ASFF writer should NOT be created for non-AWS providers"
            assert "csv" in created_writers, "CSV writer should be created"
            assert "ocsf" in created_writers, "OCSF writer should be created"

            assert result == {"upload": True}

    @patch("tasks.tasks.upload_s3_integration")
    def test_s3_integration_task_success(self, mock_upload):
        mock_upload.return_value = True
        output_directory = "/tmp/prowler_api_output/test"

        result = s3_integration_task(
            tenant_id=self.tenant_id,
            provider_id=self.provider_id,
            output_directory=output_directory,
        )

        assert result is True
        mock_upload.assert_called_once_with(
            self.tenant_id, self.provider_id, output_directory
        )

    @patch("tasks.tasks.upload_s3_integration")
    def test_s3_integration_task_failure(self, mock_upload):
        mock_upload.return_value = False
        output_directory = "/tmp/prowler_api_output/test"

        result = s3_integration_task(
            tenant_id=self.tenant_id,
            provider_id=self.provider_id,
            output_directory=output_directory,
        )

        assert result is False
        mock_upload.assert_called_once_with(
            self.tenant_id, self.provider_id, output_directory
        )

    @patch("tasks.tasks.upload_security_hub_integration")
    def test_security_hub_integration_task_success(self, mock_upload):
        """Test successful SecurityHub integration task execution."""
        mock_upload.return_value = True
        scan_id = "test-scan-123"

        result = security_hub_integration_task(
            tenant_id=self.tenant_id,
            provider_id=self.provider_id,
            scan_id=scan_id,
        )

        assert result is True
        mock_upload.assert_called_once_with(self.tenant_id, self.provider_id, scan_id)

    @patch("tasks.tasks.upload_security_hub_integration")
    def test_security_hub_integration_task_failure(self, mock_upload):
        """Test SecurityHub integration task handling failure."""
        mock_upload.return_value = False
        scan_id = "test-scan-123"

        result = security_hub_integration_task(
            tenant_id=self.tenant_id,
            provider_id=self.provider_id,
            scan_id=scan_id,
        )

        assert result is False
        mock_upload.assert_called_once_with(self.tenant_id, self.provider_id, scan_id)


@pytest.mark.django_db
class TestCheckLighthouseProviderConnectionTask:
    def setup_method(self):
        self.tenant_id = str(uuid.uuid4())

    @pytest.mark.parametrize(
        "provider_type,credentials,base_url,expected_result",
        [
            (
                LighthouseProviderConfiguration.LLMProviderChoices.OPENAI,
                {"api_key": "sk-test123"},
                None,
                {"connected": True, "error": None},
            ),
            (
                LighthouseProviderConfiguration.LLMProviderChoices.OPENAI_COMPATIBLE,
                {"api_key": "sk-test123"},
                "https://openrouter.ai/api/v1",
                {"connected": True, "error": None},
            ),
            (
                LighthouseProviderConfiguration.LLMProviderChoices.BEDROCK,
                {
                    "access_key_id": "AKIA123",
                    "secret_access_key": "secret",
                    "region": "us-east-1",
                },
                None,
                {"connected": True, "error": None},
            ),
            # Bedrock API key authentication
            (
                LighthouseProviderConfiguration.LLMProviderChoices.BEDROCK,
                {
                    "api_key": "ABSKQmVkcm9ja0FQSUtleS" + ("A" * 110),
                    "region": "us-east-1",
                },
                None,
                {"connected": True, "error": None},
            ),
        ],
    )
    def test_check_connection_success_all_providers(
        self, tenants_fixture, provider_type, credentials, base_url, expected_result
    ):
        """Test successful connection check for all provider types."""
        # Create provider configuration
        provider_cfg = LighthouseProviderConfiguration(
            tenant_id=tenants_fixture[0].id,
            provider_type=provider_type,
            base_url=base_url,
            is_active=False,
        )
        provider_cfg.credentials_decoded = credentials
        provider_cfg.save()

        # Mock the appropriate API calls
        with (
            patch("tasks.jobs.lighthouse_providers.openai.OpenAI") as mock_openai,
            patch("tasks.jobs.lighthouse_providers.boto3.client") as mock_boto3,
        ):
            mock_client = MagicMock()
            mock_client.models.list.return_value = MagicMock()
            mock_client.list_foundation_models.return_value = {}
            mock_openai.return_value = mock_client
            mock_boto3.return_value = mock_client

            # Execute
            result = check_lighthouse_provider_connection_task(
                provider_config_id=str(provider_cfg.id),
                tenant_id=str(tenants_fixture[0].id),
            )

            # Assert
            assert result == expected_result
            provider_cfg.refresh_from_db()
            assert provider_cfg.is_active is True

    @pytest.mark.parametrize(
        "provider_type,credentials,base_url,exception_to_raise",
        [
            (
                LighthouseProviderConfiguration.LLMProviderChoices.OPENAI,
                {"api_key": "sk-invalid"},
                None,
                openai.AuthenticationError(
                    "Invalid API key", response=MagicMock(), body=None
                ),
            ),
            (
                LighthouseProviderConfiguration.LLMProviderChoices.OPENAI_COMPATIBLE,
                {"api_key": "sk-invalid"},
                "https://openrouter.ai/api/v1",
                openai.APIConnectionError(request=MagicMock()),
            ),
            (
                LighthouseProviderConfiguration.LLMProviderChoices.BEDROCK,
                {
                    "access_key_id": "AKIA123",
                    "secret_access_key": "secret",
                    "region": "us-east-1",
                },
                None,
                ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
                    "list_foundation_models",
                ),
            ),
            # Bedrock API key authentication failure
            (
                LighthouseProviderConfiguration.LLMProviderChoices.BEDROCK,
                {
                    "api_key": "ABSKQmVkcm9ja0FQSUtleS" + ("X" * 110),
                    "region": "us-east-1",
                },
                None,
                ClientError(
                    {
                        "Error": {
                            "Code": "UnrecognizedClientException",
                            "Message": "Invalid API key",
                        }
                    },
                    "list_foundation_models",
                ),
            ),
        ],
    )
    def test_check_connection_api_failure(
        self,
        tenants_fixture,
        provider_type,
        credentials,
        base_url,
        exception_to_raise,
    ):
        """Test connection check when API calls fail."""
        # Create provider configuration
        provider_cfg = LighthouseProviderConfiguration(
            tenant_id=tenants_fixture[0].id,
            provider_type=provider_type,
            base_url=base_url,
            is_active=True,
        )
        provider_cfg.credentials_decoded = credentials
        provider_cfg.save()

        # Mock the API to raise exception
        with (
            patch("tasks.jobs.lighthouse_providers.openai.OpenAI") as mock_openai,
            patch("tasks.jobs.lighthouse_providers.boto3.client") as mock_boto3,
        ):
            mock_client = MagicMock()
            if (
                provider_type
                == LighthouseProviderConfiguration.LLMProviderChoices.BEDROCK
            ):
                mock_client.list_foundation_models.side_effect = exception_to_raise
                mock_boto3.return_value = mock_client
            else:
                mock_client.models.list.side_effect = exception_to_raise
                mock_openai.return_value = mock_client

            # Execute
            result = check_lighthouse_provider_connection_task(
                provider_config_id=str(provider_cfg.id),
                tenant_id=str(tenants_fixture[0].id),
            )

            # Assert
            assert result["connected"] is False
            assert result["error"] is not None
            provider_cfg.refresh_from_db()
            assert provider_cfg.is_active is False

    def test_check_connection_updates_active_status(self, tenants_fixture):
        """Test that connection check toggles is_active from True to False on failure."""
        # Create provider with is_active=True
        provider_cfg = LighthouseProviderConfiguration(
            tenant_id=tenants_fixture[0].id,
            provider_type=LighthouseProviderConfiguration.LLMProviderChoices.OPENAI,
            base_url=None,
            is_active=True,
        )
        provider_cfg.credentials_decoded = {"api_key": "sk-test123"}
        provider_cfg.save()

        # Mock API to fail
        with patch("tasks.jobs.lighthouse_providers.openai.OpenAI") as mock_openai:
            mock_client = MagicMock()
            mock_client.models.list.side_effect = openai.AuthenticationError(
                "Invalid", response=MagicMock(), body=None
            )
            mock_openai.return_value = mock_client

            # Execute
            result = check_lighthouse_provider_connection_task(
                provider_config_id=str(provider_cfg.id),
                tenant_id=str(tenants_fixture[0].id),
            )

            # Assert status changed
            assert result["connected"] is False
            provider_cfg.refresh_from_db()
            assert provider_cfg.is_active is False

    def test_check_connection_provider_does_not_exist(self, tenants_fixture):
        """Test that checking non-existent provider raises DoesNotExist."""
        non_existent_id = str(uuid.uuid4())

        with pytest.raises(LighthouseProviderConfiguration.DoesNotExist):
            check_lighthouse_provider_connection_task(
                provider_config_id=non_existent_id,
                tenant_id=str(tenants_fixture[0].id),
            )


@pytest.mark.django_db
class TestRefreshLighthouseProviderModelsTask:
    def setup_method(self):
        self.tenant_id = str(uuid.uuid4())

    @pytest.mark.parametrize(
        "provider_type,credentials,base_url,mock_models,expected_count",
        [
            (
                LighthouseProviderConfiguration.LLMProviderChoices.OPENAI,
                {"api_key": "sk-test123"},
                None,
                {"gpt-5": "gpt-5", "gpt-4o": "gpt-4o"},
                2,
            ),
            (
                LighthouseProviderConfiguration.LLMProviderChoices.OPENAI_COMPATIBLE,
                {"api_key": "sk-test123"},
                "https://openrouter.ai/api/v1",
                {"model-1": "Model One", "model-2": "Model Two"},
                2,
            ),
            (
                LighthouseProviderConfiguration.LLMProviderChoices.BEDROCK,
                {
                    "access_key_id": "AKIA123",
                    "secret_access_key": "secret",
                    "region": "us-east-1",
                },
                None,
                {"openai.gpt-oss-120b-1:0": "gpt-oss-120b"},
                1,
            ),
            # Bedrock API key authentication
            (
                LighthouseProviderConfiguration.LLMProviderChoices.BEDROCK,
                {
                    "api_key": "ABSKQmVkcm9ja0FQSUtleS" + ("A" * 110),
                    "region": "us-east-1",
                },
                None,
                {"anthropic.claude-v3": "Claude 3"},
                1,
            ),
        ],
    )
    def test_refresh_models_create_new(
        self,
        tenants_fixture,
        provider_type,
        credentials,
        base_url,
        mock_models,
        expected_count,
    ):
        """Test creating new models for all provider types."""
        # Create provider configuration
        provider_cfg = LighthouseProviderConfiguration(
            tenant_id=tenants_fixture[0].id,
            provider_type=provider_type,
            base_url=base_url,
            is_active=True,
        )
        provider_cfg.credentials_decoded = credentials
        provider_cfg.save()

        # Mock the fetch functions
        with (
            patch(
                "tasks.jobs.lighthouse_providers._fetch_openai_models",
                return_value=mock_models,
            ),
            patch(
                "tasks.jobs.lighthouse_providers._fetch_openai_compatible_models",
                return_value=mock_models,
            ),
            patch(
                "tasks.jobs.lighthouse_providers._fetch_bedrock_models",
                return_value=mock_models,
            ),
        ):
            # Execute
            result = refresh_lighthouse_provider_models_task(
                provider_config_id=str(provider_cfg.id),
                tenant_id=str(tenants_fixture[0].id),
            )

            # Assert
            assert result["created"] == expected_count
            assert result["updated"] == 0
            assert result["deleted"] == 0
            assert (
                LighthouseProviderModels.objects.filter(
                    provider_configuration=provider_cfg
                ).count()
                == expected_count
            )

    def test_refresh_models_mixed_operations(self, tenants_fixture):
        """Test mixed create, update, and delete operations."""
        # Create provider configuration
        provider_cfg = LighthouseProviderConfiguration(
            tenant_id=tenants_fixture[0].id,
            provider_type=LighthouseProviderConfiguration.LLMProviderChoices.OPENAI,
            base_url=None,
            is_active=True,
        )
        provider_cfg.credentials_decoded = {"api_key": "sk-test123"}
        provider_cfg.save()

        # Create 2 existing models (A, B)
        LighthouseProviderModels.objects.create(
            tenant_id=tenants_fixture[0].id,
            provider_configuration=provider_cfg,
            model_id="model-a",
            model_name="Model A",
        )
        LighthouseProviderModels.objects.create(
            tenant_id=tenants_fixture[0].id,
            provider_configuration=provider_cfg,
            model_id="model-b",
            model_name="Model B",
        )

        # Mock API to return models B (existing), C (new) - A will be deleted
        mock_models = {"model-b": "Model B", "model-c": "Model C"}
        with patch(
            "tasks.jobs.lighthouse_providers._fetch_openai_models",
            return_value=mock_models,
        ):
            # Execute
            result = refresh_lighthouse_provider_models_task(
                provider_config_id=str(provider_cfg.id),
                tenant_id=str(tenants_fixture[0].id),
            )

            # Assert
            assert result["created"] == 1  # model-c created
            assert result["updated"] == 1  # model-b updated
            assert result["deleted"] == 1  # model-a deleted

            # Verify only B and C exist
            remaining_models = LighthouseProviderModels.objects.filter(
                provider_configuration=provider_cfg
            )
            assert remaining_models.count() == 2
            assert set(remaining_models.values_list("model_id", flat=True)) == {
                "model-b",
                "model-c",
            }

    def test_refresh_models_api_exception(self, tenants_fixture):
        """Test refresh when API raises an exception."""
        # Create provider configuration
        provider_cfg = LighthouseProviderConfiguration(
            tenant_id=tenants_fixture[0].id,
            provider_type=LighthouseProviderConfiguration.LLMProviderChoices.OPENAI,
            base_url=None,
            is_active=True,
        )
        provider_cfg.credentials_decoded = {"api_key": "sk-test123"}
        provider_cfg.save()

        # Mock fetch to raise exception
        with patch(
            "tasks.jobs.lighthouse_providers._fetch_openai_models",
            side_effect=openai.APIError("API Error", request=MagicMock(), body=None),
        ):
            # Execute
            result = refresh_lighthouse_provider_models_task(
                provider_config_id=str(provider_cfg.id),
                tenant_id=str(tenants_fixture[0].id),
            )

            # Assert
            assert result["created"] == 0
            assert result["updated"] == 0
            assert result["deleted"] == 0
            assert "error" in result
            assert result["error"] is not None


@pytest.mark.django_db
class TestCleanupOrphanScheduledScans:
    """Unit tests for _cleanup_orphan_scheduled_scans helper function."""

    def _create_periodic_task(self, provider_id, tenant_id):
        """Helper to create a PeriodicTask for testing."""
        interval, _ = IntervalSchedule.objects.get_or_create(every=24, period="hours")
        return PeriodicTask.objects.create(
            name=f"scan-perform-scheduled-{provider_id}",
            task="scan-perform-scheduled",
            interval=interval,
            kwargs=f'{{"tenant_id": "{tenant_id}", "provider_id": "{provider_id}"}}',
            enabled=True,
        )

    def test_cleanup_deletes_orphan_when_both_available_and_scheduled_exist(
        self, tenants_fixture, providers_fixture
    ):
        """Test that AVAILABLE scan is deleted when SCHEDULED also exists."""
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]
        periodic_task = self._create_periodic_task(provider.id, tenant.id)

        # Create orphan AVAILABLE scan
        orphan_scan = Scan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            name="Daily scheduled scan",
            trigger=Scan.TriggerChoices.SCHEDULED,
            state=StateChoices.AVAILABLE,
            scheduler_task_id=periodic_task.id,
        )

        # Create SCHEDULED scan (next execution)
        scheduled_scan = Scan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            name="Daily scheduled scan",
            trigger=Scan.TriggerChoices.SCHEDULED,
            state=StateChoices.SCHEDULED,
            scheduler_task_id=periodic_task.id,
        )

        # Execute cleanup
        deleted_count = _cleanup_orphan_scheduled_scans(
            tenant_id=str(tenant.id),
            provider_id=str(provider.id),
            scheduler_task_id=periodic_task.id,
        )

        # Verify orphan was deleted
        assert deleted_count == 1
        assert not Scan.objects.filter(id=orphan_scan.id).exists()
        assert Scan.objects.filter(id=scheduled_scan.id).exists()

    def test_cleanup_does_not_delete_when_only_available_exists(
        self, tenants_fixture, providers_fixture
    ):
        """Test that AVAILABLE scan is NOT deleted when no SCHEDULED exists."""
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]
        periodic_task = self._create_periodic_task(provider.id, tenant.id)

        # Create only AVAILABLE scan (normal first scan scenario)
        available_scan = Scan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            name="Daily scheduled scan",
            trigger=Scan.TriggerChoices.SCHEDULED,
            state=StateChoices.AVAILABLE,
            scheduler_task_id=periodic_task.id,
        )

        # Execute cleanup
        deleted_count = _cleanup_orphan_scheduled_scans(
            tenant_id=str(tenant.id),
            provider_id=str(provider.id),
            scheduler_task_id=periodic_task.id,
        )

        # Verify nothing was deleted
        assert deleted_count == 0
        assert Scan.objects.filter(id=available_scan.id).exists()

    def test_cleanup_does_not_delete_when_only_scheduled_exists(
        self, tenants_fixture, providers_fixture
    ):
        """Test that nothing is deleted when only SCHEDULED exists."""
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]
        periodic_task = self._create_periodic_task(provider.id, tenant.id)

        # Create only SCHEDULED scan (normal subsequent scan scenario)
        scheduled_scan = Scan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            name="Daily scheduled scan",
            trigger=Scan.TriggerChoices.SCHEDULED,
            state=StateChoices.SCHEDULED,
            scheduler_task_id=periodic_task.id,
        )

        # Execute cleanup
        deleted_count = _cleanup_orphan_scheduled_scans(
            tenant_id=str(tenant.id),
            provider_id=str(provider.id),
            scheduler_task_id=periodic_task.id,
        )

        # Verify nothing was deleted
        assert deleted_count == 0
        assert Scan.objects.filter(id=scheduled_scan.id).exists()

    def test_cleanup_returns_zero_when_no_scans_exist(
        self, tenants_fixture, providers_fixture
    ):
        """Test that cleanup returns 0 when no scans exist."""
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]
        periodic_task = self._create_periodic_task(provider.id, tenant.id)

        # Execute cleanup with no scans
        deleted_count = _cleanup_orphan_scheduled_scans(
            tenant_id=str(tenant.id),
            provider_id=str(provider.id),
            scheduler_task_id=periodic_task.id,
        )

        assert deleted_count == 0

    def test_cleanup_deletes_multiple_orphan_available_scans(
        self, tenants_fixture, providers_fixture
    ):
        """Test that multiple AVAILABLE orphan scans are all deleted."""
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]
        periodic_task = self._create_periodic_task(provider.id, tenant.id)

        # Create multiple orphan AVAILABLE scans
        orphan_scan_1 = Scan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            name="Daily scheduled scan",
            trigger=Scan.TriggerChoices.SCHEDULED,
            state=StateChoices.AVAILABLE,
            scheduler_task_id=periodic_task.id,
        )
        orphan_scan_2 = Scan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            name="Daily scheduled scan",
            trigger=Scan.TriggerChoices.SCHEDULED,
            state=StateChoices.AVAILABLE,
            scheduler_task_id=periodic_task.id,
        )

        # Create SCHEDULED scan
        scheduled_scan = Scan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            name="Daily scheduled scan",
            trigger=Scan.TriggerChoices.SCHEDULED,
            state=StateChoices.SCHEDULED,
            scheduler_task_id=periodic_task.id,
        )

        # Execute cleanup
        deleted_count = _cleanup_orphan_scheduled_scans(
            tenant_id=str(tenant.id),
            provider_id=str(provider.id),
            scheduler_task_id=periodic_task.id,
        )

        # Verify all orphans were deleted
        assert deleted_count == 2
        assert not Scan.objects.filter(id=orphan_scan_1.id).exists()
        assert not Scan.objects.filter(id=orphan_scan_2.id).exists()
        assert Scan.objects.filter(id=scheduled_scan.id).exists()

    def test_cleanup_does_not_affect_different_provider(
        self, tenants_fixture, providers_fixture
    ):
        """Test that cleanup only affects scans for the specified provider."""
        tenant = tenants_fixture[0]
        provider1 = providers_fixture[0]
        provider2 = providers_fixture[1]
        periodic_task1 = self._create_periodic_task(provider1.id, tenant.id)
        periodic_task2 = self._create_periodic_task(provider2.id, tenant.id)

        # Create orphan scenario for provider1
        orphan_scan_p1 = Scan.objects.create(
            tenant_id=tenant.id,
            provider=provider1,
            name="Daily scheduled scan",
            trigger=Scan.TriggerChoices.SCHEDULED,
            state=StateChoices.AVAILABLE,
            scheduler_task_id=periodic_task1.id,
        )
        scheduled_scan_p1 = Scan.objects.create(
            tenant_id=tenant.id,
            provider=provider1,
            name="Daily scheduled scan",
            trigger=Scan.TriggerChoices.SCHEDULED,
            state=StateChoices.SCHEDULED,
            scheduler_task_id=periodic_task1.id,
        )

        # Create AVAILABLE scan for provider2 (should not be affected)
        available_scan_p2 = Scan.objects.create(
            tenant_id=tenant.id,
            provider=provider2,
            name="Daily scheduled scan",
            trigger=Scan.TriggerChoices.SCHEDULED,
            state=StateChoices.AVAILABLE,
            scheduler_task_id=periodic_task2.id,
        )

        # Execute cleanup for provider1 only
        deleted_count = _cleanup_orphan_scheduled_scans(
            tenant_id=str(tenant.id),
            provider_id=str(provider1.id),
            scheduler_task_id=periodic_task1.id,
        )

        # Verify only provider1's orphan was deleted
        assert deleted_count == 1
        assert not Scan.objects.filter(id=orphan_scan_p1.id).exists()
        assert Scan.objects.filter(id=scheduled_scan_p1.id).exists()
        assert Scan.objects.filter(id=available_scan_p2.id).exists()

    def test_cleanup_does_not_affect_manual_scans(
        self, tenants_fixture, providers_fixture
    ):
        """Test that cleanup only affects SCHEDULED trigger scans, not MANUAL."""
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]
        periodic_task = self._create_periodic_task(provider.id, tenant.id)

        # Create orphan AVAILABLE scheduled scan
        orphan_scan = Scan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            name="Daily scheduled scan",
            trigger=Scan.TriggerChoices.SCHEDULED,
            state=StateChoices.AVAILABLE,
            scheduler_task_id=periodic_task.id,
        )

        # Create SCHEDULED scan
        scheduled_scan = Scan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            name="Daily scheduled scan",
            trigger=Scan.TriggerChoices.SCHEDULED,
            state=StateChoices.SCHEDULED,
            scheduler_task_id=periodic_task.id,
        )

        # Create AVAILABLE manual scan (should not be affected)
        manual_scan = Scan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            name="Manual scan",
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.AVAILABLE,
        )

        # Execute cleanup
        deleted_count = _cleanup_orphan_scheduled_scans(
            tenant_id=str(tenant.id),
            provider_id=str(provider.id),
            scheduler_task_id=periodic_task.id,
        )

        # Verify only scheduled orphan was deleted
        assert deleted_count == 1
        assert not Scan.objects.filter(id=orphan_scan.id).exists()
        assert Scan.objects.filter(id=scheduled_scan.id).exists()
        assert Scan.objects.filter(id=manual_scan.id).exists()

    def test_cleanup_does_not_affect_different_scheduler_task(
        self, tenants_fixture, providers_fixture
    ):
        """Test that cleanup only affects scans with the specified scheduler_task_id."""
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]
        periodic_task1 = self._create_periodic_task(provider.id, tenant.id)

        # Create another periodic task
        interval, _ = IntervalSchedule.objects.get_or_create(every=24, period="hours")
        periodic_task2 = PeriodicTask.objects.create(
            name=f"scan-perform-scheduled-other-{provider.id}",
            task="scan-perform-scheduled",
            interval=interval,
            kwargs=f'{{"tenant_id": "{tenant.id}", "provider_id": "{provider.id}"}}',
            enabled=True,
        )

        # Create orphan scenario for periodic_task1
        orphan_scan = Scan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            name="Daily scheduled scan",
            trigger=Scan.TriggerChoices.SCHEDULED,
            state=StateChoices.AVAILABLE,
            scheduler_task_id=periodic_task1.id,
        )
        scheduled_scan = Scan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            name="Daily scheduled scan",
            trigger=Scan.TriggerChoices.SCHEDULED,
            state=StateChoices.SCHEDULED,
            scheduler_task_id=periodic_task1.id,
        )

        # Create AVAILABLE scan for periodic_task2 (should not be affected)
        available_scan_other_task = Scan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            name="Daily scheduled scan",
            trigger=Scan.TriggerChoices.SCHEDULED,
            state=StateChoices.AVAILABLE,
            scheduler_task_id=periodic_task2.id,
        )

        # Execute cleanup for periodic_task1 only
        deleted_count = _cleanup_orphan_scheduled_scans(
            tenant_id=str(tenant.id),
            provider_id=str(provider.id),
            scheduler_task_id=periodic_task1.id,
        )

        # Verify only periodic_task1's orphan was deleted
        assert deleted_count == 1
        assert not Scan.objects.filter(id=orphan_scan.id).exists()
        assert Scan.objects.filter(id=scheduled_scan.id).exists()
        assert Scan.objects.filter(id=available_scan_other_task.id).exists()


@pytest.mark.django_db
class TestPerformScheduledScanTask:
    """Unit tests for perform_scheduled_scan_task."""

    @staticmethod
    @contextmanager
    def _override_task_request(task, **attrs):
        request = task.request
        sentinel = object()
        previous = {key: getattr(request, key, sentinel) for key in attrs}
        for key, value in attrs.items():
            setattr(request, key, value)

        try:
            yield
        finally:
            for key, prev in previous.items():
                if prev is sentinel:
                    if hasattr(request, key):
                        delattr(request, key)
                else:
                    setattr(request, key, prev)

    def _create_periodic_task(self, provider_id, tenant_id, interval_hours=24):
        interval, _ = IntervalSchedule.objects.get_or_create(
            every=interval_hours, period="hours"
        )
        return PeriodicTask.objects.create(
            name=f"scan-perform-scheduled-{provider_id}",
            task="scan-perform-scheduled",
            interval=interval,
            kwargs=f'{{"tenant_id": "{tenant_id}", "provider_id": "{provider_id}"}}',
            enabled=True,
        )

    def _create_task_result(self, tenant_id, task_id):
        task_result = TaskResult.objects.create(
            task_id=task_id,
            task_name="scan-perform-scheduled",
            status="STARTED",
            date_created=datetime.now(timezone.utc),
        )
        Task.objects.create(
            id=task_id, task_runner_task=task_result, tenant_id=tenant_id
        )
        return task_result

    def test_skip_when_scheduled_scan_executing(
        self, tenants_fixture, providers_fixture
    ):
        """Skip a scheduled run when another scheduled scan is already executing."""
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]
        periodic_task = self._create_periodic_task(provider.id, tenant.id)
        task_id = str(uuid.uuid4())
        self._create_task_result(tenant.id, task_id)

        executing_scan = Scan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            name="Daily scheduled scan",
            trigger=Scan.TriggerChoices.SCHEDULED,
            state=StateChoices.EXECUTING,
            scheduler_task_id=periodic_task.id,
        )

        with (
            patch("tasks.tasks.perform_prowler_scan") as mock_scan,
            patch("tasks.tasks._perform_scan_complete_tasks") as mock_complete_tasks,
            self._override_task_request(perform_scheduled_scan_task, id=task_id),
        ):
            result = perform_scheduled_scan_task.run(
                tenant_id=str(tenant.id), provider_id=str(provider.id)
            )

        mock_scan.assert_not_called()
        mock_complete_tasks.assert_not_called()
        assert result["id"] == str(executing_scan.id)
        assert result["state"] == StateChoices.EXECUTING
        assert (
            Scan.objects.filter(
                tenant_id=tenant.id,
                provider=provider,
                trigger=Scan.TriggerChoices.SCHEDULED,
                state=StateChoices.SCHEDULED,
            ).count()
            == 0
        )

    def test_creates_next_scheduled_scan_after_completion(
        self, tenants_fixture, providers_fixture
    ):
        """Create a next scheduled scan after a successful run completes."""
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]
        self._create_periodic_task(provider.id, tenant.id)
        task_id = str(uuid.uuid4())
        self._create_task_result(tenant.id, task_id)

        def _complete_scan(tenant_id, scan_id, provider_id):
            other_scheduled = Scan.objects.filter(
                tenant_id=tenant_id,
                provider_id=provider_id,
                trigger=Scan.TriggerChoices.SCHEDULED,
                state=StateChoices.SCHEDULED,
            ).exclude(id=scan_id)
            assert not other_scheduled.exists()
            scan_instance = Scan.objects.get(id=scan_id)
            scan_instance.state = StateChoices.COMPLETED
            scan_instance.save()
            return {"status": "ok"}

        with (
            patch("tasks.tasks.perform_prowler_scan", side_effect=_complete_scan),
            patch("tasks.tasks._perform_scan_complete_tasks"),
            self._override_task_request(perform_scheduled_scan_task, id=task_id),
        ):
            perform_scheduled_scan_task.run(
                tenant_id=str(tenant.id), provider_id=str(provider.id)
            )

        scheduled_scans = Scan.objects.filter(
            tenant_id=tenant.id,
            provider=provider,
            trigger=Scan.TriggerChoices.SCHEDULED,
            state=StateChoices.SCHEDULED,
        )
        assert scheduled_scans.count() == 1
        assert scheduled_scans.first().scheduled_at > datetime.now(timezone.utc)
        assert (
            Scan.objects.filter(
                tenant_id=tenant.id,
                provider=provider,
                trigger=Scan.TriggerChoices.SCHEDULED,
                state__in=(StateChoices.SCHEDULED, StateChoices.AVAILABLE),
            ).count()
            == 1
        )
        assert (
            Scan.objects.filter(
                tenant_id=tenant.id,
                provider=provider,
                trigger=Scan.TriggerChoices.SCHEDULED,
                state=StateChoices.COMPLETED,
            ).count()
            == 1
        )

    def test_dedupes_multiple_scheduled_scans_before_run(
        self, tenants_fixture, providers_fixture
    ):
        """Ensure duplicated scheduled scans are removed before executing."""
        tenant = tenants_fixture[0]
        provider = providers_fixture[0]
        periodic_task = self._create_periodic_task(provider.id, tenant.id)
        task_id = str(uuid.uuid4())
        self._create_task_result(tenant.id, task_id)

        scheduled_scan = Scan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            name="Daily scheduled scan",
            trigger=Scan.TriggerChoices.SCHEDULED,
            state=StateChoices.SCHEDULED,
            scheduled_at=datetime.now(timezone.utc),
            scheduler_task_id=periodic_task.id,
        )
        duplicate_scan = Scan.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            name="Daily scheduled scan",
            trigger=Scan.TriggerChoices.SCHEDULED,
            state=StateChoices.AVAILABLE,
            scheduled_at=scheduled_scan.scheduled_at,
            scheduler_task_id=periodic_task.id,
        )

        def _complete_scan(tenant_id, scan_id, provider_id):
            other_scheduled = Scan.objects.filter(
                tenant_id=tenant_id,
                provider_id=provider_id,
                trigger=Scan.TriggerChoices.SCHEDULED,
                state__in=(StateChoices.SCHEDULED, StateChoices.AVAILABLE),
            ).exclude(id=scan_id)
            assert not other_scheduled.exists()
            scan_instance = Scan.objects.get(id=scan_id)
            scan_instance.state = StateChoices.COMPLETED
            scan_instance.save()
            return {"status": "ok"}

        with (
            patch("tasks.tasks.perform_prowler_scan", side_effect=_complete_scan),
            patch("tasks.tasks._perform_scan_complete_tasks"),
            self._override_task_request(perform_scheduled_scan_task, id=task_id),
        ):
            perform_scheduled_scan_task.run(
                tenant_id=str(tenant.id), provider_id=str(provider.id)
            )

        assert not Scan.objects.filter(id=duplicate_scan.id).exists()
        assert Scan.objects.filter(id=scheduled_scan.id).exists()
        assert (
            Scan.objects.filter(
                tenant_id=tenant.id,
                provider=provider,
                trigger=Scan.TriggerChoices.SCHEDULED,
                state__in=(StateChoices.SCHEDULED, StateChoices.AVAILABLE),
            ).count()
            == 1
        )
