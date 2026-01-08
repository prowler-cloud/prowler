# Example: Celery Task Tests
# Source: api/src/backend/tasks/tests/test_tasks.py

import uuid
from unittest.mock import MagicMock, patch

import pytest


@pytest.mark.django_db
class TestGenerateOutputs:
    """Example task test with heavy mocking."""

    def setup_method(self):
        """Set up test data for each test method."""
        self.scan_id = str(uuid.uuid4())
        self.provider_id = str(uuid.uuid4())
        self.tenant_id = str(uuid.uuid4())

    def test_no_findings_returns_early(self):
        """Test early return when no findings exist."""
        with patch("tasks.tasks.ScanSummary.objects.filter") as mock_filter:
            mock_filter.return_value.exists.return_value = False

            from tasks.tasks import generate_outputs_task

            result = generate_outputs_task(
                scan_id=self.scan_id,
                provider_id=self.provider_id,
                tenant_id=self.tenant_id,
            )

            assert result == {"upload": False}
            mock_filter.assert_called_once_with(scan_id=self.scan_id)

    @patch("tasks.tasks._upload_to_s3")
    @patch("tasks.tasks._compress_output_files")
    @patch("tasks.tasks.Provider.objects.get")
    @patch("tasks.tasks.ScanSummary.objects.filter")
    def test_generate_outputs_success(
        self,
        mock_scan_summary_filter,
        mock_provider_get,
        mock_compress,
        mock_upload,
    ):
        """Test successful output generation with all mocks."""
        # Set up mocks
        mock_scan_summary_filter.return_value.exists.return_value = True

        mock_provider = MagicMock()
        mock_provider.uid = "provider-uid"
        mock_provider.provider = "aws"
        mock_provider_get.return_value = mock_provider

        mock_compress.return_value = "/tmp/zipped.zip"
        mock_upload.return_value = "s3://bucket/zipped.zip"

        with (
            patch("tasks.tasks.Scan.all_objects.filter") as mock_scan_update,
            patch("tasks.tasks.rmtree"),
        ):
            from tasks.tasks import generate_outputs_task

            result = generate_outputs_task(
                scan_id=self.scan_id,
                provider_id=self.provider_id,
                tenant_id=self.tenant_id,
            )

            assert result == {"upload": True}


class TestScanCompleteTasks:
    """Test task orchestration patterns."""

    @patch("tasks.tasks.aggregate_attack_surface_task.apply_async")
    @patch("tasks.tasks.create_compliance_requirements_task.apply_async")
    @patch("tasks.tasks.perform_scan_summary_task.si")
    @patch("tasks.tasks.generate_outputs_task.si")
    def test_scan_complete_tasks(
        self,
        mock_outputs_task,
        mock_scan_summary_task,
        mock_compliance_requirements_task,
        mock_attack_surface_task,
    ):
        """Verify all follow-up tasks are called with correct args."""
        from tasks.tasks import _perform_scan_complete_tasks

        _perform_scan_complete_tasks("tenant-id", "scan-id", "provider-id")

        mock_compliance_requirements_task.assert_called_once_with(
            kwargs={"tenant_id": "tenant-id", "scan_id": "scan-id"},
        )
        mock_attack_surface_task.assert_called_once_with(
            kwargs={"tenant_id": "tenant-id", "scan_id": "scan-id"},
        )
        mock_scan_summary_task.assert_called_once()
        mock_outputs_task.assert_called_once()


@pytest.mark.django_db
class TestCheckIntegrationsTask:
    """Test integration checking task."""

    def setup_method(self):
        self.provider_id = str(uuid.uuid4())
        self.tenant_id = str(uuid.uuid4())

    @patch("tasks.tasks.rls_transaction")
    @patch("tasks.tasks.Integration.objects.filter")
    def test_no_integrations(self, mock_integration_filter, mock_rls):
        """Test when no integrations are configured."""
        mock_integration_filter.return_value.exists.return_value = False
        mock_rls.return_value.__enter__.return_value = None

        from tasks.tasks import check_integrations_task

        result = check_integrations_task(
            tenant_id=self.tenant_id,
            provider_id=self.provider_id,
        )

        assert result == {"integrations_processed": 0}
        mock_integration_filter.assert_called_once_with(
            integrationproviderrelationship__provider_id=self.provider_id,
            enabled=True,
        )
