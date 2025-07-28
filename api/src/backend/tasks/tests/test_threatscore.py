import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from tasks.jobs.report import (
    generate_threatscore_report,
    generate_threatscore_report_job,
)
from tasks.tasks import generate_threatscore_report_task


@pytest.mark.django_db
class TestGenerateThreatscoreReport:
    def setup_method(self):
        self.scan_id = str(uuid.uuid4())
        self.provider_id = str(uuid.uuid4())
        self.tenant_id = str(uuid.uuid4())

    def test_no_findings_returns_early(self):
        with patch("tasks.jobs.report.ScanSummary.objects.filter") as mock_filter:
            mock_filter.return_value.exists.return_value = False

            result = generate_threatscore_report_job(
                tenant_id=self.tenant_id,
                scan_id=self.scan_id,
                provider_id=self.provider_id,
            )

            assert result == {"upload": False}
            mock_filter.assert_called_once_with(scan_id=self.scan_id)

    @patch("tasks.jobs.report.rmtree")
    @patch("tasks.jobs.report._upload_to_s3")
    @patch("tasks.jobs.report.generate_threatscore_report")
    @patch("tasks.jobs.report._generate_output_directory")
    @patch("tasks.jobs.report.Provider.objects.get")
    @patch("tasks.jobs.report.ScanSummary.objects.filter")
    @patch("tasks.jobs.report.Scan.all_objects.filter")
    def test_generate_threatscore_report_happy_path(
        self,
        mock_scan_update,
        mock_scan_summary_filter,
        mock_provider_get,
        mock_generate_output_directory,
        mock_generate_report,
        mock_upload,
        mock_rmtree,
    ):
        mock_scan_summary_filter.return_value.exists.return_value = True

        mock_provider = MagicMock()
        mock_provider.uid = "provider-uid"
        mock_provider.provider = "aws"
        mock_provider_get.return_value = mock_provider

        mock_generate_output_directory.return_value = (
            "/tmp/output",
            "/tmp/compressed",
            "/tmp/threatscore_path",
        )

        mock_upload.return_value = "s3://bucket/threatscore_report.pdf"

        result = generate_threatscore_report_job(
            tenant_id=self.tenant_id,
            scan_id=self.scan_id,
            provider_id=self.provider_id,
        )

        assert result == {"upload": True}
        mock_generate_report.assert_called_once_with(
            scan_id=self.scan_id,
            compliance_id="prowler_threatscore_aws",
            output_path="/tmp/threatscore_path_threatscore_report.pdf",
            provider_id=self.provider_id,
            only_failed=True,
            min_risk_level=4,
        )
        mock_scan_update.return_value.update.assert_called_once_with(
            output_location="s3://bucket/threatscore_report.pdf"
        )
        mock_rmtree.assert_called_once_with(
            Path("/tmp/threatscore_path_threatscore_report.pdf").parent,
            ignore_errors=True,
        )

    def test_generate_threatscore_report_fails_upload(self):
        with (
            patch("tasks.jobs.report.ScanSummary.objects.filter") as mock_filter,
            patch("tasks.jobs.report.Provider.objects.get") as mock_provider_get,
            patch("tasks.jobs.report._generate_output_directory") as mock_gen_dir,
            patch("tasks.jobs.report.generate_threatscore_report"),
            patch("tasks.jobs.report._upload_to_s3", return_value=None),
            patch("tasks.jobs.report.Scan.all_objects.filter") as mock_scan_update,
        ):
            mock_filter.return_value.exists.return_value = True

            # Mock provider
            mock_provider = MagicMock()
            mock_provider.uid = "aws-provider-uid"
            mock_provider.provider = "aws"
            mock_provider_get.return_value = mock_provider

            mock_gen_dir.return_value = (
                "/tmp/output",
                "/tmp/compressed",
                "/tmp/threatscore_path",
            )

            result = generate_threatscore_report_job(
                tenant_id=self.tenant_id,
                scan_id=self.scan_id,
                provider_id=self.provider_id,
            )

            assert result == {"upload": False}
            mock_scan_update.return_value.update.assert_called_once()

    def test_generate_threatscore_report_logs_rmtree_exception(self, caplog):
        with (
            patch("tasks.jobs.report.ScanSummary.objects.filter") as mock_filter,
            patch("tasks.jobs.report.Provider.objects.get") as mock_provider_get,
            patch("tasks.jobs.report._generate_output_directory") as mock_gen_dir,
            patch("tasks.jobs.report.generate_threatscore_report"),
            patch(
                "tasks.jobs.report._upload_to_s3", return_value="s3://bucket/report.pdf"
            ),
            patch("tasks.jobs.report.Scan.all_objects.filter"),
            patch(
                "tasks.jobs.report.rmtree", side_effect=Exception("Test deletion error")
            ),
        ):
            mock_filter.return_value.exists.return_value = True

            # Mock provider
            mock_provider = MagicMock()
            mock_provider.uid = "aws-provider-uid"
            mock_provider.provider = "aws"
            mock_provider_get.return_value = mock_provider

            mock_gen_dir.return_value = (
                "/tmp/output",
                "/tmp/compressed",
                "/tmp/threatscore_path",
            )

            with caplog.at_level("ERROR"):
                generate_threatscore_report_job(
                    tenant_id=self.tenant_id,
                    scan_id=self.scan_id,
                    provider_id=self.provider_id,
                )
                assert "Error deleting output files" in caplog.text

    def test_generate_threatscore_report_azure_provider(self):
        with (
            patch("tasks.jobs.report.ScanSummary.objects.filter") as mock_filter,
            patch("tasks.jobs.report.Provider.objects.get") as mock_provider_get,
            patch("tasks.jobs.report._generate_output_directory") as mock_gen_dir,
            patch("tasks.jobs.report.generate_threatscore_report") as mock_generate,
            patch(
                "tasks.jobs.report._upload_to_s3", return_value="s3://bucket/report.pdf"
            ),
            patch("tasks.jobs.report.Scan.all_objects.filter"),
            patch("tasks.jobs.report.rmtree"),
        ):
            mock_filter.return_value.exists.return_value = True

            mock_provider = MagicMock()
            mock_provider.uid = "azure-provider-uid"
            mock_provider.provider = "azure"
            mock_provider_get.return_value = mock_provider

            mock_gen_dir.return_value = (
                "/tmp/output",
                "/tmp/compressed",
                "/tmp/threatscore_path",
            )

            generate_threatscore_report_job(
                tenant_id=self.tenant_id,
                scan_id=self.scan_id,
                provider_id=self.provider_id,
            )

            mock_generate.assert_called_once_with(
                scan_id=self.scan_id,
                compliance_id="prowler_threatscore_azure",
                output_path="/tmp/threatscore_path_threatscore_report.pdf",
                provider_id=self.provider_id,
                only_failed=True,
                min_risk_level=4,
            )


@pytest.mark.django_db
class TestGenerateThreatscoreReportFunction:
    def setup_method(self):
        self.scan_id = str(uuid.uuid4())
        self.provider_id = str(uuid.uuid4())
        self.compliance_id = "prowler_threatscore_aws"
        self.output_path = "/tmp/test_threatscore_report.pdf"

    @patch("tasks.jobs.report.initialize_prowler_provider")
    @patch("tasks.jobs.report.Provider.objects.get")
    @patch("tasks.jobs.report.Compliance.get_bulk")
    @patch("tasks.jobs.report.Finding.all_objects.filter")
    @patch("tasks.jobs.report.batched")
    @patch("tasks.jobs.report.FindingOutput.transform_api_finding")
    @patch("tasks.jobs.report.SimpleDocTemplate")
    @patch("tasks.jobs.report.Image")
    @patch("tasks.jobs.report.Spacer")
    @patch("tasks.jobs.report.Paragraph")
    @patch("tasks.jobs.report.PageBreak")
    @patch("tasks.jobs.report.Table")
    @patch("tasks.jobs.report.TableStyle")
    @patch("tasks.jobs.report.plt.subplots")
    @patch("tasks.jobs.report.plt.savefig")
    @patch("tasks.jobs.report.io.BytesIO")
    def test_generate_threatscore_report_success(
        self,
        mock_bytesio,
        mock_savefig,
        mock_subplots,
        mock_table_style,
        mock_table,
        mock_page_break,
        mock_paragraph,
        mock_spacer,
        mock_image,
        mock_doc_template,
        mock_transform_finding,
        mock_batched,
        mock_finding_filter,
        mock_compliance_get_bulk,
        mock_provider_get,
        mock_initialize_provider,
    ):
        mock_provider = MagicMock()
        mock_provider.provider = "aws"
        mock_provider_get.return_value = mock_provider

        prowler_provider = MagicMock()
        mock_initialize_provider.return_value = prowler_provider

        mock_compliance_obj = MagicMock()
        mock_compliance_obj.Framework = "ProwlerThreatScore"
        mock_compliance_obj.Version = "1.0"
        mock_compliance_obj.Description = "Test Description"
        mock_compliance_obj.Requirements = []
        mock_compliance_get_bulk.return_value = {
            self.compliance_id: mock_compliance_obj
        }

        mock_finding = MagicMock()
        mock_finding.uid = "finding-1"
        mock_finding_filter.return_value.order_by.return_value.iterator.return_value = [
            mock_finding
        ]

        mock_batched.return_value = [([mock_finding], True)]

        mock_transformed_finding = MagicMock()
        mock_transformed_finding.check_id = "check-1"
        mock_transformed_finding.status = "FAIL"
        mock_transformed_finding.description = "Test finding"
        mock_transformed_finding.metadata = MagicMock()
        mock_transformed_finding.metadata.CheckTitle = "Test Check"
        mock_transformed_finding.metadata.Severity = "HIGH"
        mock_transformed_finding.resource_name = "test-resource"
        mock_transformed_finding.region = "us-east-1"
        mock_transform_finding.return_value = mock_transformed_finding

        mock_doc = MagicMock()
        mock_doc_template.return_value = mock_doc

        mock_fig, mock_ax = MagicMock(), MagicMock()
        mock_subplots.return_value = (mock_fig, mock_ax)
        mock_buffer = MagicMock()
        mock_bytesio.return_value = mock_buffer

        mock_image.return_value = MagicMock()
        mock_spacer.return_value = MagicMock()
        mock_paragraph.return_value = MagicMock()
        mock_page_break.return_value = MagicMock()
        mock_table.return_value = MagicMock()
        mock_table_style.return_value = MagicMock()

        generate_threatscore_report(
            scan_id=self.scan_id,
            compliance_id=self.compliance_id,
            output_path=self.output_path,
            provider_id=self.provider_id,
            only_failed=True,
            min_risk_level=4,
        )

        mock_provider_get.assert_called_once_with(id=self.provider_id)
        mock_initialize_provider.assert_called_once_with(mock_provider)
        mock_compliance_get_bulk.assert_called_once_with("aws")
        mock_finding_filter.assert_called_once_with(scan_id=self.scan_id)
        mock_batched.assert_called_once()
        mock_transform_finding.assert_called_once_with(mock_finding, prowler_provider)
        mock_doc_template.assert_called_once()
        mock_doc.build.assert_called_once()

    @patch("tasks.jobs.report.initialize_prowler_provider")
    @patch("tasks.jobs.report.Provider.objects.get")
    @patch("tasks.jobs.report.Compliance.get_bulk")
    @patch("tasks.jobs.report.Finding.all_objects.filter")
    def test_generate_threatscore_report_exception_handling(
        self,
        mock_finding_filter,
        mock_compliance_get_bulk,
        mock_provider_get,
        mock_initialize_provider,
    ):
        mock_provider_get.side_effect = Exception("Provider not found")

        with pytest.raises(Exception, match="Provider not found"):
            generate_threatscore_report(
                scan_id=self.scan_id,
                compliance_id=self.compliance_id,
                output_path=self.output_path,
                provider_id=self.provider_id,
                only_failed=True,
                min_risk_level=4,
            )


@pytest.mark.django_db
class TestGenerateThreatscoreReportTask:
    def setup_method(self):
        self.scan_id = str(uuid.uuid4())
        self.provider_id = str(uuid.uuid4())
        self.tenant_id = str(uuid.uuid4())

    @patch("tasks.tasks.generate_threatscore_report_job")
    def test_generate_threatscore_report_task_calls_job(self, mock_generate_job):
        mock_generate_job.return_value = {"upload": True}

        result = generate_threatscore_report_task(
            tenant_id=self.tenant_id,
            scan_id=self.scan_id,
            provider_id=self.provider_id,
        )

        assert result == {"upload": True}
        mock_generate_job.assert_called_once_with(
            tenant_id=self.tenant_id,
            scan_id=self.scan_id,
            provider_id=self.provider_id,
        )

    @patch("tasks.tasks.generate_threatscore_report_job")
    def test_generate_threatscore_report_task_handles_job_exception(
        self, mock_generate_job
    ):
        mock_generate_job.side_effect = Exception("Job failed")

        with pytest.raises(Exception, match="Job failed"):
            generate_threatscore_report_task(
                tenant_id=self.tenant_id,
                scan_id=self.scan_id,
                provider_id=self.provider_id,
            )
