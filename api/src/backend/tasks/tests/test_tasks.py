import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from tasks.tasks import _perform_scan_complete_tasks, generate_outputs_task


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

    @patch("tasks.tasks.rmtree")
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
        mock_rmtree,
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
                return_value=("out-dir", "comp-dir"),
            ),
            patch("tasks.tasks.Scan.all_objects.filter") as mock_scan_update,
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
            mock_rmtree.assert_called_once_with(
                Path("/tmp/zipped.zip").parent, ignore_errors=True
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
                "tasks.tasks._generate_output_directory", return_value=("out", "comp")
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
        ):
            mock_filter.return_value.exists.return_value = True
            mock_findings.return_value.order_by.return_value.iterator.return_value = [
                [MagicMock()],
                True,
            ]

            result = generate_outputs_task(
                scan_id="scan",
                provider_id="provider",
                tenant_id=self.tenant_id,
            )

            assert result == {"upload": False}
            mock_scan_update.return_value.update.assert_called_once()

    def test_generate_outputs_triggers_html_extra_update(self):
        mock_finding_output = MagicMock()
        mock_finding_output.compliance = {"cis": ["requirement-1", "requirement-2"]}

        with (
            patch("tasks.tasks.ScanSummary.objects.filter") as mock_filter,
            patch("tasks.tasks.Provider.objects.get"),
            patch("tasks.tasks.initialize_prowler_provider"),
            patch("tasks.tasks.Compliance.get_bulk", return_value={"cis": MagicMock()}),
            patch("tasks.tasks.get_compliance_frameworks", return_value=["cis"]),
            patch("tasks.tasks.Finding.all_objects.filter") as mock_findings,
            patch(
                "tasks.tasks._generate_output_directory", return_value=("out", "comp")
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
        ):
            mock_filter.return_value.exists.return_value = True
            mock_findings.return_value.order_by.return_value.iterator.return_value = [
                [MagicMock()],
                True,
            ]

            html_writer_mock = MagicMock()
            with (
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
                    {"aws": [(lambda x: True, MagicMock())]},
                ),
            ):
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
                return_value=("outdir", "compdir"),
            ),
            patch("tasks.tasks._compress_output_files", return_value="outdir.zip"),
            patch("tasks.tasks._upload_to_s3", return_value="s3://bucket/outdir.zip"),
            patch("tasks.tasks.rmtree"),
            patch("tasks.tasks.Scan.all_objects.filter"),
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
                writer_instances.append(self)

            def transform(self, fos, comp_obj, name):
                self.transform_calls.append((fos, comp_obj, name))

            def batch_write_data_to_file(self):
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
                return_value=("outdir", "compdir"),
            ),
            patch("tasks.tasks.FindingOutput._transform_findings_stats"),
            patch(
                "tasks.tasks.FindingOutput.transform_api_finding",
                side_effect=lambda f, prov: f,
            ),
            patch("tasks.tasks._compress_output_files", return_value="outdir.zip"),
            patch("tasks.tasks._upload_to_s3", return_value="s3://bucket/outdir.zip"),
            patch("tasks.tasks.rmtree"),
            patch(
                "tasks.tasks.Scan.all_objects.filter",
                return_value=MagicMock(update=lambda **kw: None),
            ),
            patch("tasks.tasks.batched", return_value=two_batches),
            patch("tasks.tasks.OUTPUT_FORMATS_MAPPING", {}),
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

    def test_generate_outputs_logs_rmtree_exception(self, caplog):
        mock_finding_output = MagicMock()
        mock_finding_output.compliance = {"cis": ["requirement-1", "requirement-2"]}

        with (
            patch("tasks.tasks.ScanSummary.objects.filter") as mock_filter,
            patch("tasks.tasks.Provider.objects.get"),
            patch("tasks.tasks.initialize_prowler_provider"),
            patch("tasks.tasks.Compliance.get_bulk", return_value={"cis": MagicMock()}),
            patch("tasks.tasks.get_compliance_frameworks", return_value=["cis"]),
            patch("tasks.tasks.Finding.all_objects.filter") as mock_findings,
            patch(
                "tasks.tasks._generate_output_directory", return_value=("out", "comp")
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
        ):
            mock_filter.return_value.exists.return_value = True
            mock_findings.return_value.order_by.return_value.iterator.return_value = [
                [MagicMock()],
                True,
            ]

            with (
                patch(
                    "tasks.tasks.OUTPUT_FORMATS_MAPPING",
                    {
                        "json": {
                            "class": lambda *args, **kwargs: MagicMock(),
                            "suffix": ".json",
                            "kwargs": {},
                        }
                    },
                ),
                patch(
                    "tasks.tasks.COMPLIANCE_CLASS_MAP",
                    {"aws": [(lambda x: True, MagicMock())]},
                ),
            ):
                with caplog.at_level("ERROR"):
                    generate_outputs_task(
                        scan_id=self.scan_id,
                        provider_id=self.provider_id,
                        tenant_id=self.tenant_id,
                    )
                    assert "Error deleting output files" in caplog.text


class TestScanCompleteTasks:
    @patch("tasks.tasks.create_compliance_requirements_task.apply_async")
    @patch("tasks.tasks.perform_scan_summary_task.si")
    @patch("tasks.tasks.generate_outputs_task.si")
    def test_scan_complete_tasks(
        self, mock_outputs_task, mock_scan_summary_task, mock_compliance_tasks
    ):
        _perform_scan_complete_tasks("tenant-id", "scan-id", "provider-id")
        mock_compliance_tasks.assert_called_once_with(
            kwargs={"tenant_id": "tenant-id", "scan_id": "scan-id"},
        )
        mock_scan_summary_task.assert_called_once_with(
            scan_id="scan-id",
            tenant_id="tenant-id",
        )
        mock_outputs_task.assert_called_once_with(
            scan_id="scan-id",
            provider_id="provider-id",
            tenant_id="tenant-id",
        )
