import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import matplotlib
import pytest
from tasks.jobs.report import (
    _load_findings_for_requirement_checks,
    generate_threatscore_report,
    generate_threatscore_report_job,
)
from tasks.jobs.threatscore_utils import (
    _aggregate_requirement_statistics_from_database,
    _calculate_requirements_data_from_statistics,
)
from tasks.tasks import generate_threatscore_report_task

from api.models import Finding, StatusChoices
from prowler.lib.check.models import Severity

matplotlib.use("Agg")  # Use non-interactive backend for tests


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
    def test_generate_threatscore_report_happy_path(
        self,
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
            tenant_id=self.tenant_id,
            scan_id=self.scan_id,
            compliance_id="prowler_threatscore_aws",
            output_path="/tmp/threatscore_path_threatscore_report.pdf",
            provider_id=self.provider_id,
            only_failed=True,
            min_risk_level=4,
        )
        mock_upload.assert_called_once_with(
            self.tenant_id,
            self.scan_id,
            "/tmp/threatscore_path_threatscore_report.pdf",
            "threatscore/threatscore_path_threatscore_report.pdf",
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

    def test_generate_threatscore_report_logs_rmtree_exception(self, caplog):
        with (
            patch("tasks.jobs.report.ScanSummary.objects.filter") as mock_filter,
            patch("tasks.jobs.report.Provider.objects.get") as mock_provider_get,
            patch("tasks.jobs.report._generate_output_directory") as mock_gen_dir,
            patch("tasks.jobs.report.generate_threatscore_report"),
            patch(
                "tasks.jobs.report._upload_to_s3", return_value="s3://bucket/report.pdf"
            ),
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
                tenant_id=self.tenant_id,
                scan_id=self.scan_id,
                compliance_id="prowler_threatscore_azure",
                output_path="/tmp/threatscore_path_threatscore_report.pdf",
                provider_id=self.provider_id,
                only_failed=True,
                min_risk_level=4,
            )


@pytest.mark.django_db
class TestAggregateRequirementStatistics:
    """Test suite for _aggregate_requirement_statistics_from_database function."""

    def test_aggregates_findings_correctly(self, tenants_fixture, scans_fixture):
        """Verify correct pass/total counts per check are aggregated from database."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]

        # Create findings with different check_ids and statuses
        Finding.objects.create(
            tenant_id=tenant.id,
            scan=scan,
            uid="finding-1",
            check_id="check_1",
            status=StatusChoices.PASS,
            severity=Severity.high,
            impact=Severity.high,
            check_metadata={},
            raw_result={},
        )
        Finding.objects.create(
            tenant_id=tenant.id,
            scan=scan,
            uid="finding-2",
            check_id="check_1",
            status=StatusChoices.FAIL,
            severity=Severity.high,
            impact=Severity.high,
            check_metadata={},
            raw_result={},
        )
        Finding.objects.create(
            tenant_id=tenant.id,
            scan=scan,
            uid="finding-3",
            check_id="check_2",
            status=StatusChoices.PASS,
            severity=Severity.medium,
            impact=Severity.medium,
            check_metadata={},
            raw_result={},
        )

        result = _aggregate_requirement_statistics_from_database(
            str(tenant.id), str(scan.id)
        )

        assert result == {
            "check_1": {"passed": 1, "total": 2},
            "check_2": {"passed": 1, "total": 1},
        }

    def test_handles_empty_scan(self, tenants_fixture, scans_fixture):
        """Return empty dict when no findings exist for the scan."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]

        result = _aggregate_requirement_statistics_from_database(
            str(tenant.id), str(scan.id)
        )

        assert result == {}

    def test_multiple_findings_same_check(self, tenants_fixture, scans_fixture):
        """Aggregate multiple findings for same check_id correctly."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]

        # Create 5 findings for same check, 3 passed
        for i in range(3):
            Finding.objects.create(
                tenant_id=tenant.id,
                scan=scan,
                uid=f"finding-pass-{i}",
                check_id="check_same",
                status=StatusChoices.PASS,
                severity=Severity.medium,
                impact=Severity.medium,
                check_metadata={},
                raw_result={},
            )

        for i in range(2):
            Finding.objects.create(
                tenant_id=tenant.id,
                scan=scan,
                uid=f"finding-fail-{i}",
                check_id="check_same",
                status=StatusChoices.FAIL,
                severity=Severity.medium,
                impact=Severity.medium,
                check_metadata={},
                raw_result={},
            )

        result = _aggregate_requirement_statistics_from_database(
            str(tenant.id), str(scan.id)
        )

        assert result == {"check_same": {"passed": 3, "total": 5}}

    def test_only_failed_findings(self, tenants_fixture, scans_fixture):
        """Correctly count when all findings are FAIL status."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]

        Finding.objects.create(
            tenant_id=tenant.id,
            scan=scan,
            uid="finding-fail-1",
            check_id="check_fail",
            status=StatusChoices.FAIL,
            severity=Severity.medium,
            impact=Severity.medium,
            check_metadata={},
            raw_result={},
        )
        Finding.objects.create(
            tenant_id=tenant.id,
            scan=scan,
            uid="finding-fail-2",
            check_id="check_fail",
            status=StatusChoices.FAIL,
            severity=Severity.medium,
            impact=Severity.medium,
            check_metadata={},
            raw_result={},
        )

        result = _aggregate_requirement_statistics_from_database(
            str(tenant.id), str(scan.id)
        )

        assert result == {"check_fail": {"passed": 0, "total": 2}}

    def test_mixed_statuses(self, tenants_fixture, scans_fixture):
        """Test with PASS, FAIL, and MANUAL statuses mixed."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]

        Finding.objects.create(
            tenant_id=tenant.id,
            scan=scan,
            uid="finding-pass",
            check_id="check_mixed",
            status=StatusChoices.PASS,
            severity=Severity.medium,
            impact=Severity.medium,
            check_metadata={},
            raw_result={},
        )
        Finding.objects.create(
            tenant_id=tenant.id,
            scan=scan,
            uid="finding-fail",
            check_id="check_mixed",
            status=StatusChoices.FAIL,
            severity=Severity.medium,
            impact=Severity.medium,
            check_metadata={},
            raw_result={},
        )
        Finding.objects.create(
            tenant_id=tenant.id,
            scan=scan,
            uid="finding-manual",
            check_id="check_mixed",
            status=StatusChoices.MANUAL,
            severity=Severity.medium,
            impact=Severity.medium,
            check_metadata={},
            raw_result={},
        )

        result = _aggregate_requirement_statistics_from_database(
            str(tenant.id), str(scan.id)
        )

        # Only PASS status is counted as passed
        assert result == {"check_mixed": {"passed": 1, "total": 3}}


@pytest.mark.django_db
class TestLoadFindingsForChecks:
    """Test suite for _load_findings_for_requirement_checks function."""

    def test_loads_only_requested_checks(
        self, tenants_fixture, scans_fixture, providers_fixture
    ):
        """Verify only findings for specified check_ids are loaded."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]
        providers_fixture[0]

        # Create findings with different check_ids
        Finding.objects.create(
            tenant_id=tenant.id,
            scan=scan,
            uid="finding-1",
            check_id="check_requested",
            status=StatusChoices.PASS,
            severity=Severity.medium,
            impact=Severity.medium,
            check_metadata={},
            raw_result={},
        )
        Finding.objects.create(
            tenant_id=tenant.id,
            scan=scan,
            uid="finding-2",
            check_id="check_not_requested",
            status=StatusChoices.FAIL,
            severity=Severity.medium,
            impact=Severity.medium,
            check_metadata={},
            raw_result={},
        )

        mock_provider = MagicMock()

        with patch(
            "tasks.jobs.report.FindingOutput.transform_api_finding"
        ) as mock_transform:
            mock_finding_output = MagicMock()
            mock_finding_output.check_id = "check_requested"
            mock_transform.return_value = mock_finding_output

            result = _load_findings_for_requirement_checks(
                str(tenant.id), str(scan.id), ["check_requested"], mock_provider
            )

            # Only one finding should be loaded
            assert "check_requested" in result
            assert "check_not_requested" not in result
            assert len(result["check_requested"]) == 1
            assert mock_transform.call_count == 1

    def test_empty_check_ids_returns_empty(
        self, tenants_fixture, scans_fixture, providers_fixture
    ):
        """Return empty dict when check_ids list is empty."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]
        mock_provider = MagicMock()

        result = _load_findings_for_requirement_checks(
            str(tenant.id), str(scan.id), [], mock_provider
        )

        assert result == {}

    def test_groups_by_check_id(
        self, tenants_fixture, scans_fixture, providers_fixture
    ):
        """Multiple findings for same check are grouped correctly."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]

        # Create multiple findings for same check
        for i in range(3):
            Finding.objects.create(
                tenant_id=tenant.id,
                scan=scan,
                uid=f"finding-{i}",
                check_id="check_group",
                status=StatusChoices.PASS,
                severity=Severity.medium,
                impact=Severity.medium,
                check_metadata={},
                raw_result={},
            )

        mock_provider = MagicMock()

        with patch(
            "tasks.jobs.report.FindingOutput.transform_api_finding"
        ) as mock_transform:
            mock_finding_output = MagicMock()
            mock_finding_output.check_id = "check_group"
            mock_transform.return_value = mock_finding_output

            result = _load_findings_for_requirement_checks(
                str(tenant.id), str(scan.id), ["check_group"], mock_provider
            )

            assert len(result["check_group"]) == 3

    def test_transforms_to_finding_output(
        self, tenants_fixture, scans_fixture, providers_fixture
    ):
        """Findings are transformed using FindingOutput.transform_api_finding."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]

        Finding.objects.create(
            tenant_id=tenant.id,
            scan=scan,
            uid="finding-transform",
            check_id="check_transform",
            status=StatusChoices.PASS,
            severity=Severity.medium,
            impact=Severity.medium,
            check_metadata={},
            raw_result={},
        )

        mock_provider = MagicMock()

        with patch(
            "tasks.jobs.report.FindingOutput.transform_api_finding"
        ) as mock_transform:
            mock_finding_output = MagicMock()
            mock_finding_output.check_id = "check_transform"
            mock_transform.return_value = mock_finding_output

            result = _load_findings_for_requirement_checks(
                str(tenant.id), str(scan.id), ["check_transform"], mock_provider
            )

            # Verify transform was called
            mock_transform.assert_called_once()
            # Verify the transformed output is in the result
            assert result["check_transform"][0] == mock_finding_output

    def test_batched_iteration(self, tenants_fixture, scans_fixture, providers_fixture):
        """Works correctly with multiple batches of findings."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]

        # Create enough findings to ensure batching (assuming batch size > 1)
        for i in range(10):
            Finding.objects.create(
                tenant_id=tenant.id,
                scan=scan,
                uid=f"finding-batch-{i}",
                check_id="check_batch",
                status=StatusChoices.PASS,
                severity=Severity.medium,
                impact=Severity.medium,
                check_metadata={},
                raw_result={},
            )

        mock_provider = MagicMock()

        with patch(
            "tasks.jobs.report.FindingOutput.transform_api_finding"
        ) as mock_transform:
            mock_finding_output = MagicMock()
            mock_finding_output.check_id = "check_batch"
            mock_transform.return_value = mock_finding_output

            result = _load_findings_for_requirement_checks(
                str(tenant.id), str(scan.id), ["check_batch"], mock_provider
            )

            # All 10 findings should be loaded regardless of batching
            assert len(result["check_batch"]) == 10
            assert mock_transform.call_count == 10


@pytest.mark.django_db
class TestCalculateRequirementsData:
    """Test suite for _calculate_requirements_data_from_statistics function."""

    def test_requirement_status_all_pass(self):
        """Status is PASS when all findings for requirement checks pass."""
        mock_compliance = MagicMock()
        mock_compliance.Framework = "TestFramework"
        mock_compliance.Version = "1.0"

        mock_requirement = MagicMock()
        mock_requirement.Id = "req_1"
        mock_requirement.Description = "Test requirement"
        mock_requirement.Checks = ["check_1", "check_2"]
        mock_requirement.Attributes = [MagicMock()]

        mock_compliance.Requirements = [mock_requirement]

        requirement_statistics = {
            "check_1": {"passed": 5, "total": 5},
            "check_2": {"passed": 3, "total": 3},
        }

        attributes_by_id, requirements_list = (
            _calculate_requirements_data_from_statistics(
                mock_compliance, requirement_statistics
            )
        )

        assert len(requirements_list) == 1
        assert requirements_list[0]["attributes"]["status"] == StatusChoices.PASS
        assert requirements_list[0]["attributes"]["passed_findings"] == 8
        assert requirements_list[0]["attributes"]["total_findings"] == 8

    def test_requirement_status_some_fail(self):
        """Status is FAIL when some findings fail."""
        mock_compliance = MagicMock()
        mock_compliance.Framework = "TestFramework"
        mock_compliance.Version = "1.0"

        mock_requirement = MagicMock()
        mock_requirement.Id = "req_2"
        mock_requirement.Description = "Test requirement with failures"
        mock_requirement.Checks = ["check_3"]
        mock_requirement.Attributes = [MagicMock()]

        mock_compliance.Requirements = [mock_requirement]

        requirement_statistics = {
            "check_3": {"passed": 2, "total": 5},
        }

        attributes_by_id, requirements_list = (
            _calculate_requirements_data_from_statistics(
                mock_compliance, requirement_statistics
            )
        )

        assert len(requirements_list) == 1
        assert requirements_list[0]["attributes"]["status"] == StatusChoices.FAIL
        assert requirements_list[0]["attributes"]["passed_findings"] == 2
        assert requirements_list[0]["attributes"]["total_findings"] == 5

    def test_requirement_status_no_findings(self):
        """Status is MANUAL when no findings exist for requirement."""
        mock_compliance = MagicMock()
        mock_compliance.Framework = "TestFramework"
        mock_compliance.Version = "1.0"

        mock_requirement = MagicMock()
        mock_requirement.Id = "req_3"
        mock_requirement.Description = "Manual requirement"
        mock_requirement.Checks = ["check_nonexistent"]
        mock_requirement.Attributes = [MagicMock()]

        mock_compliance.Requirements = [mock_requirement]

        requirement_statistics = {}

        attributes_by_id, requirements_list = (
            _calculate_requirements_data_from_statistics(
                mock_compliance, requirement_statistics
            )
        )

        assert len(requirements_list) == 1
        assert requirements_list[0]["attributes"]["status"] == StatusChoices.MANUAL
        assert requirements_list[0]["attributes"]["passed_findings"] == 0
        assert requirements_list[0]["attributes"]["total_findings"] == 0

    def test_aggregates_multiple_checks(self):
        """Correctly sum stats across multiple checks in requirement."""
        mock_compliance = MagicMock()
        mock_compliance.Framework = "TestFramework"
        mock_compliance.Version = "1.0"

        mock_requirement = MagicMock()
        mock_requirement.Id = "req_4"
        mock_requirement.Description = "Multi-check requirement"
        mock_requirement.Checks = ["check_a", "check_b", "check_c"]
        mock_requirement.Attributes = [MagicMock()]

        mock_compliance.Requirements = [mock_requirement]

        requirement_statistics = {
            "check_a": {"passed": 10, "total": 15},
            "check_b": {"passed": 5, "total": 10},
            "check_c": {"passed": 0, "total": 5},
        }

        attributes_by_id, requirements_list = (
            _calculate_requirements_data_from_statistics(
                mock_compliance, requirement_statistics
            )
        )

        assert len(requirements_list) == 1
        # 10 + 5 + 0 = 15 passed
        assert requirements_list[0]["attributes"]["passed_findings"] == 15
        # 15 + 10 + 5 = 30 total
        assert requirements_list[0]["attributes"]["total_findings"] == 30
        # Not all passed, so should be FAIL
        assert requirements_list[0]["attributes"]["status"] == StatusChoices.FAIL

    def test_returns_correct_structure(self):
        """Verify tuple structure and dict keys are correct."""
        mock_compliance = MagicMock()
        mock_compliance.Framework = "TestFramework"
        mock_compliance.Version = "1.0"

        mock_attribute = MagicMock()
        mock_requirement = MagicMock()
        mock_requirement.Id = "req_5"
        mock_requirement.Description = "Structure test"
        mock_requirement.Checks = ["check_struct"]
        mock_requirement.Attributes = [mock_attribute]

        mock_compliance.Requirements = [mock_requirement]

        requirement_statistics = {"check_struct": {"passed": 1, "total": 1}}

        attributes_by_id, requirements_list = (
            _calculate_requirements_data_from_statistics(
                mock_compliance, requirement_statistics
            )
        )

        # Verify attributes_by_id structure
        assert "req_5" in attributes_by_id
        assert "attributes" in attributes_by_id["req_5"]
        assert "description" in attributes_by_id["req_5"]
        assert "req_attributes" in attributes_by_id["req_5"]["attributes"]
        assert "checks" in attributes_by_id["req_5"]["attributes"]

        # Verify requirements_list structure
        assert len(requirements_list) == 1
        req = requirements_list[0]
        assert "id" in req
        assert "attributes" in req
        assert "framework" in req["attributes"]
        assert "version" in req["attributes"]
        assert "status" in req["attributes"]
        assert "description" in req["attributes"]
        assert "passed_findings" in req["attributes"]
        assert "total_findings" in req["attributes"]


@pytest.mark.django_db
class TestGenerateThreatscoreReportFunction:
    def setup_method(self):
        self.scan_id = str(uuid.uuid4())
        self.provider_id = str(uuid.uuid4())
        self.tenant_id = str(uuid.uuid4())
        self.compliance_id = "prowler_threatscore_aws"
        self.output_path = "/tmp/test_threatscore_report.pdf"

    @patch("tasks.jobs.report.initialize_prowler_provider")
    @patch("tasks.jobs.report.Provider.objects.get")
    @patch("tasks.jobs.report.Compliance.get_bulk")
    @patch(
        "tasks.jobs.threatscore_utils._aggregate_requirement_statistics_from_database"
    )
    @patch("tasks.jobs.threatscore_utils._calculate_requirements_data_from_statistics")
    @patch("tasks.jobs.report._load_findings_for_requirement_checks")
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
        mock_load_findings,
        mock_calculate_requirements,
        mock_aggregate_statistics,
        mock_compliance_get_bulk,
        mock_provider_get,
        mock_initialize_provider,
    ):
        """Test the updated generate_threatscore_report using new memory-efficient architecture."""
        mock_provider = MagicMock()
        mock_provider.provider = "aws"
        mock_provider_get.return_value = mock_provider

        prowler_provider = MagicMock()
        mock_initialize_provider.return_value = prowler_provider

        # Mock compliance object with requirements
        mock_compliance_obj = MagicMock()
        mock_compliance_obj.Framework = "ProwlerThreatScore"
        mock_compliance_obj.Version = "1.0"
        mock_compliance_obj.Description = "Test Description"

        # Configure requirement with properly set numeric attributes for chart generation
        mock_requirement = MagicMock()
        mock_requirement.Id = "req_1"
        mock_requirement.Description = "Test requirement"
        mock_requirement.Checks = ["check_1"]

        # Create a properly configured attribute mock with numeric values
        mock_requirement_attr = MagicMock()
        mock_requirement_attr.Section = "1. IAM"
        mock_requirement_attr.SubSection = "1.1 Identity"
        mock_requirement_attr.Title = "Test Requirement Title"
        mock_requirement_attr.LevelOfRisk = 3
        mock_requirement_attr.Weight = 100
        mock_requirement_attr.AttributeDescription = "Test requirement description"
        mock_requirement_attr.AdditionalInformation = "Additional test information"

        mock_requirement.Attributes = [mock_requirement_attr]
        mock_compliance_obj.Requirements = [mock_requirement]

        mock_compliance_get_bulk.return_value = {
            self.compliance_id: mock_compliance_obj
        }

        # Mock the aggregated statistics from database
        mock_aggregate_statistics.return_value = {"check_1": {"passed": 5, "total": 10}}

        # Mock the calculated requirements data with properly configured attributes
        mock_attributes_by_id = {
            "req_1": {
                "attributes": {
                    "req_attributes": [mock_requirement_attr],
                    "checks": ["check_1"],
                },
                "description": "Test requirement",
            }
        }
        mock_requirements_list = [
            {
                "id": "req_1",
                "attributes": {
                    "framework": "ProwlerThreatScore",
                    "version": "1.0",
                    "status": StatusChoices.FAIL,
                    "description": "Test requirement",
                    "passed_findings": 5,
                    "total_findings": 10,
                },
            }
        ]
        mock_calculate_requirements.return_value = (
            mock_attributes_by_id,
            mock_requirements_list,
        )

        # Mock the on-demand loaded findings
        mock_finding_output = MagicMock()
        mock_finding_output.check_id = "check_1"
        mock_finding_output.status = "FAIL"
        mock_finding_output.metadata = MagicMock()
        mock_finding_output.metadata.CheckTitle = "Test Check"
        mock_finding_output.metadata.Severity = "HIGH"
        mock_finding_output.resource_name = "test-resource"
        mock_finding_output.region = "us-east-1"

        mock_load_findings.return_value = {"check_1": [mock_finding_output]}

        # Mock PDF generation components
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

        # Execute the function
        generate_threatscore_report(
            tenant_id=self.tenant_id,
            scan_id=self.scan_id,
            compliance_id=self.compliance_id,
            output_path=self.output_path,
            provider_id=self.provider_id,
            only_failed=True,
            min_risk_level=4,
        )

        # Verify the new workflow was followed
        mock_provider_get.assert_called_once_with(id=self.provider_id)
        mock_initialize_provider.assert_called_once_with(mock_provider)
        mock_compliance_get_bulk.assert_called_once_with("aws")

        # Verify the new functions were called in correct order with correct parameters
        mock_aggregate_statistics.assert_called_once_with(self.tenant_id, self.scan_id)
        mock_calculate_requirements.assert_called_once_with(
            mock_compliance_obj, {"check_1": {"passed": 5, "total": 10}}
        )
        mock_load_findings.assert_called_once_with(
            self.tenant_id, self.scan_id, ["check_1"], prowler_provider
        )

        # Verify PDF was built
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
                tenant_id=self.tenant_id,
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
