import io
import uuid
from unittest.mock import MagicMock, Mock, patch

import matplotlib
import pytest
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle
from tasks.jobs.report import (
    CHART_COLOR_GREEN_1,
    CHART_COLOR_GREEN_2,
    CHART_COLOR_ORANGE,
    CHART_COLOR_RED,
    CHART_COLOR_YELLOW,
    COLOR_BLUE,
    COLOR_ENS_ALTO,
    COLOR_ENS_BAJO,
    COLOR_ENS_MEDIO,
    COLOR_ENS_OPCIONAL,
    COLOR_HIGH_RISK,
    COLOR_LOW_RISK,
    COLOR_MEDIUM_RISK,
    COLOR_SAFE,
    _aggregate_requirement_statistics_from_database,
    _calculate_requirements_data_from_statistics,
    _create_dimensions_radar_chart,
    _create_ens_dimension_badges,
    _create_ens_nivel_badge,
    _create_ens_tipo_badge,
    _create_findings_table_style,
    _create_header_table_style,
    _create_info_table_style,
    _create_marco_category_chart,
    _create_pdf_styles,
    _create_risk_component,
    _create_section_score_chart,
    _create_status_component,
    _get_chart_color_for_percentage,
    _get_color_for_compliance,
    _get_color_for_risk_level,
    _get_color_for_weight,
    _get_ens_nivel_color,
    _load_findings_for_requirement_checks,
    _safe_getattr,
    generate_compliance_reports_job,
    generate_threatscore_report,
)

from api.models import Finding, StatusChoices
from prowler.lib.check.models import Severity

matplotlib.use("Agg")  # Use non-interactive backend for tests


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
    @patch("tasks.jobs.report._aggregate_requirement_statistics_from_database")
    @patch("tasks.jobs.report._calculate_requirements_data_from_statistics")
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
class TestColorHelperFunctions:
    """Test suite for color selection helper functions."""

    def test_get_color_for_risk_level_high(self):
        """High risk level (>=4) returns red color."""
        assert _get_color_for_risk_level(4) == COLOR_HIGH_RISK
        assert _get_color_for_risk_level(5) == COLOR_HIGH_RISK

    def test_get_color_for_risk_level_medium_high(self):
        """Medium-high risk level (3) returns orange color."""
        assert _get_color_for_risk_level(3) == COLOR_MEDIUM_RISK

    def test_get_color_for_risk_level_medium(self):
        """Medium risk level (2) returns yellow color."""
        assert _get_color_for_risk_level(2) == COLOR_LOW_RISK

    def test_get_color_for_risk_level_low(self):
        """Low risk level (<2) returns green color."""
        assert _get_color_for_risk_level(0) == COLOR_SAFE
        assert _get_color_for_risk_level(1) == COLOR_SAFE

    def test_get_color_for_weight_high(self):
        """High weight (>100) returns red color."""
        assert _get_color_for_weight(101) == COLOR_HIGH_RISK
        assert _get_color_for_weight(200) == COLOR_HIGH_RISK

    def test_get_color_for_weight_medium(self):
        """Medium weight (51-100) returns yellow color."""
        assert _get_color_for_weight(51) == COLOR_LOW_RISK
        assert _get_color_for_weight(100) == COLOR_LOW_RISK

    def test_get_color_for_weight_low(self):
        """Low weight (<=50) returns green color."""
        assert _get_color_for_weight(0) == COLOR_SAFE
        assert _get_color_for_weight(50) == COLOR_SAFE

    def test_get_color_for_compliance_high(self):
        """High compliance (>=80%) returns green color."""
        assert _get_color_for_compliance(80.0) == COLOR_SAFE
        assert _get_color_for_compliance(100.0) == COLOR_SAFE

    def test_get_color_for_compliance_medium(self):
        """Medium compliance (60-79%) returns yellow color."""
        assert _get_color_for_compliance(60.0) == COLOR_LOW_RISK
        assert _get_color_for_compliance(79.9) == COLOR_LOW_RISK

    def test_get_color_for_compliance_low(self):
        """Low compliance (<60%) returns red color."""
        assert _get_color_for_compliance(0.0) == COLOR_HIGH_RISK
        assert _get_color_for_compliance(59.9) == COLOR_HIGH_RISK

    def test_get_chart_color_for_percentage_excellent(self):
        """Excellent percentage (>=80%) returns green."""
        assert _get_chart_color_for_percentage(80.0) == CHART_COLOR_GREEN_1
        assert _get_chart_color_for_percentage(100.0) == CHART_COLOR_GREEN_1

    def test_get_chart_color_for_percentage_good(self):
        """Good percentage (60-79%) returns light green."""
        assert _get_chart_color_for_percentage(60.0) == CHART_COLOR_GREEN_2
        assert _get_chart_color_for_percentage(79.9) == CHART_COLOR_GREEN_2

    def test_get_chart_color_for_percentage_fair(self):
        """Fair percentage (40-59%) returns yellow."""
        assert _get_chart_color_for_percentage(40.0) == CHART_COLOR_YELLOW
        assert _get_chart_color_for_percentage(59.9) == CHART_COLOR_YELLOW

    def test_get_chart_color_for_percentage_poor(self):
        """Poor percentage (20-39%) returns orange."""
        assert _get_chart_color_for_percentage(20.0) == CHART_COLOR_ORANGE
        assert _get_chart_color_for_percentage(39.9) == CHART_COLOR_ORANGE

    def test_get_chart_color_for_percentage_critical(self):
        """Critical percentage (<20%) returns red."""
        assert _get_chart_color_for_percentage(0.0) == CHART_COLOR_RED
        assert _get_chart_color_for_percentage(19.9) == CHART_COLOR_RED

    def test_get_ens_nivel_color_alto(self):
        """Alto nivel returns red color."""
        assert _get_ens_nivel_color("alto") == COLOR_ENS_ALTO
        assert _get_ens_nivel_color("ALTO") == COLOR_ENS_ALTO

    def test_get_ens_nivel_color_medio(self):
        """Medio nivel returns yellow/orange color."""
        assert _get_ens_nivel_color("medio") == COLOR_ENS_MEDIO
        assert _get_ens_nivel_color("MEDIO") == COLOR_ENS_MEDIO

    def test_get_ens_nivel_color_bajo(self):
        """Bajo nivel returns green color."""
        assert _get_ens_nivel_color("bajo") == COLOR_ENS_BAJO
        assert _get_ens_nivel_color("BAJO") == COLOR_ENS_BAJO

    def test_get_ens_nivel_color_opcional(self):
        """Opcional and unknown nivels return gray color."""
        assert _get_ens_nivel_color("opcional") == COLOR_ENS_OPCIONAL
        assert _get_ens_nivel_color("unknown") == COLOR_ENS_OPCIONAL


class TestSafeGetattr:
    """Test suite for _safe_getattr helper function."""

    def test_safe_getattr_attribute_exists(self):
        """Returns attribute value when it exists."""
        obj = Mock()
        obj.test_attr = "value"
        assert _safe_getattr(obj, "test_attr") == "value"

    def test_safe_getattr_attribute_missing_default(self):
        """Returns default 'N/A' when attribute doesn't exist."""
        obj = Mock(spec=[])
        result = _safe_getattr(obj, "missing_attr")
        assert result == "N/A"

    def test_safe_getattr_custom_default(self):
        """Returns custom default when specified."""
        obj = Mock(spec=[])
        result = _safe_getattr(obj, "missing_attr", "custom")
        assert result == "custom"

    def test_safe_getattr_none_value(self):
        """Returns None if attribute value is None."""
        obj = Mock()
        obj.test_attr = None
        assert _safe_getattr(obj, "test_attr") is None


class TestPDFStylesCreation:
    """Test suite for PDF styles creation and caching."""

    def test_create_pdf_styles_returns_dict(self):
        """Returns a dictionary with all required styles."""
        styles = _create_pdf_styles()

        assert isinstance(styles, dict)
        assert "title" in styles
        assert "h1" in styles
        assert "h2" in styles
        assert "h3" in styles
        assert "normal" in styles
        assert "normal_center" in styles

    def test_create_pdf_styles_caches_result(self):
        """Subsequent calls return cached styles."""
        styles1 = _create_pdf_styles()
        styles2 = _create_pdf_styles()

        # Should return the exact same object (not just equal)
        assert styles1 is styles2

    def test_pdf_styles_have_correct_fonts(self):
        """Styles use the correct fonts."""
        styles = _create_pdf_styles()

        assert styles["title"].fontName == "PlusJakartaSans"
        assert styles["h1"].fontName == "PlusJakartaSans"
        assert styles["normal"].fontName == "PlusJakartaSans"


class TestTableStyleFactories:
    """Test suite for table style factory functions."""

    def test_create_info_table_style_returns_table_style(self):
        """Returns a TableStyle object."""
        style = _create_info_table_style()
        assert isinstance(style, TableStyle)

    def test_create_header_table_style_default_color(self):
        """Uses default blue color when not specified."""
        style = _create_header_table_style()
        assert isinstance(style, TableStyle)
        # Verify it has styling commands
        assert len(style.getCommands()) > 0

    def test_create_header_table_style_custom_color(self):
        """Uses custom color when specified."""
        custom_color = colors.red
        style = _create_header_table_style(custom_color)
        assert isinstance(style, TableStyle)

    def test_create_findings_table_style(self):
        """Returns appropriate style for findings tables."""
        style = _create_findings_table_style()
        assert isinstance(style, TableStyle)
        assert len(style.getCommands()) > 0


class TestRiskComponent:
    """Test suite for _create_risk_component function."""

    def test_create_risk_component_returns_table(self):
        """Returns a Table object."""
        table = _create_risk_component(risk_level=3, weight=100, score=50)
        assert isinstance(table, Table)

    def test_create_risk_component_high_risk(self):
        """High risk level uses red color."""
        table = _create_risk_component(risk_level=4, weight=50, score=0)
        assert isinstance(table, Table)
        # Table is created successfully

    def test_create_risk_component_low_risk(self):
        """Low risk level uses green color."""
        table = _create_risk_component(risk_level=1, weight=30, score=100)
        assert isinstance(table, Table)

    def test_create_risk_component_default_score(self):
        """Uses default score of 0 when not specified."""
        table = _create_risk_component(risk_level=2, weight=50)
        assert isinstance(table, Table)


class TestStatusComponent:
    """Test suite for _create_status_component function."""

    def test_create_status_component_pass(self):
        """PASS status uses green color."""
        table = _create_status_component("pass")
        assert isinstance(table, Table)

    def test_create_status_component_fail(self):
        """FAIL status uses red color."""
        table = _create_status_component("fail")
        assert isinstance(table, Table)

    def test_create_status_component_manual(self):
        """MANUAL status uses gray color."""
        table = _create_status_component("manual")
        assert isinstance(table, Table)

    def test_create_status_component_uppercase(self):
        """Handles uppercase status strings."""
        table = _create_status_component("PASS")
        assert isinstance(table, Table)


class TestENSBadges:
    """Test suite for ENS-specific badge creation functions."""

    def test_create_ens_nivel_badge_alto(self):
        """Creates badge for alto nivel."""
        table = _create_ens_nivel_badge("alto")
        assert isinstance(table, Table)

    def test_create_ens_nivel_badge_medio(self):
        """Creates badge for medio nivel."""
        table = _create_ens_nivel_badge("medio")
        assert isinstance(table, Table)

    def test_create_ens_nivel_badge_bajo(self):
        """Creates badge for bajo nivel."""
        table = _create_ens_nivel_badge("bajo")
        assert isinstance(table, Table)

    def test_create_ens_nivel_badge_opcional(self):
        """Creates badge for opcional nivel."""
        table = _create_ens_nivel_badge("opcional")
        assert isinstance(table, Table)

    def test_create_ens_tipo_badge_requisito(self):
        """Creates badge for requisito type."""
        table = _create_ens_tipo_badge("requisito")
        assert isinstance(table, Table)

    def test_create_ens_tipo_badge_unknown(self):
        """Handles unknown tipo gracefully."""
        table = _create_ens_tipo_badge("unknown")
        assert isinstance(table, Table)

    def test_create_ens_dimension_badges_single(self):
        """Creates badges for single dimension."""
        table = _create_ens_dimension_badges(["trazabilidad"])
        assert isinstance(table, Table)

    def test_create_ens_dimension_badges_multiple(self):
        """Creates badges for multiple dimensions."""
        dimensiones = ["trazabilidad", "autenticidad", "integridad"]
        table = _create_ens_dimension_badges(dimensiones)
        assert isinstance(table, Table)

    def test_create_ens_dimension_badges_empty(self):
        """Returns N/A table for empty dimensions list."""
        table = _create_ens_dimension_badges([])
        assert isinstance(table, Table)

    def test_create_ens_dimension_badges_invalid(self):
        """Filters out invalid dimensions."""
        table = _create_ens_dimension_badges(["invalid", "trazabilidad"])
        assert isinstance(table, Table)


class TestChartCreation:
    """Test suite for chart generation functions."""

    @patch("tasks.jobs.report.plt.close")
    @patch("tasks.jobs.report.plt.savefig")
    @patch("tasks.jobs.report.plt.subplots")
    def test_create_section_score_chart_with_data(
        self, mock_subplots, mock_savefig, mock_close
    ):
        """Creates chart successfully with valid data."""
        mock_fig, mock_ax = MagicMock(), MagicMock()
        mock_subplots.return_value = (mock_fig, mock_ax)
        mock_ax.bar.return_value = [MagicMock(), MagicMock()]

        requirements_list = [
            {
                "id": "req_1",
                "attributes": {
                    "passed_findings": 10,
                    "total_findings": 10,
                },
            }
        ]

        mock_metadata = MagicMock()
        mock_metadata.Section = "1. IAM"
        mock_metadata.LevelOfRisk = 3
        mock_metadata.Weight = 100

        attributes_by_id = {
            "req_1": {
                "attributes": {
                    "req_attributes": [mock_metadata],
                }
            }
        }

        result = _create_section_score_chart(requirements_list, attributes_by_id)

        assert isinstance(result, io.BytesIO)
        mock_subplots.assert_called_once()
        mock_close.assert_called_once_with(mock_fig)

    @patch("tasks.jobs.report.plt.close")
    @patch("tasks.jobs.report.plt.savefig")
    @patch("tasks.jobs.report.plt.subplots")
    def test_create_marco_category_chart_with_data(
        self, mock_subplots, mock_savefig, mock_close
    ):
        """Creates marco/category chart successfully."""
        mock_fig, mock_ax = MagicMock(), MagicMock()
        mock_subplots.return_value = (mock_fig, mock_ax)
        mock_ax.barh.return_value = [MagicMock()]

        requirements_list = [
            {
                "id": "req_1",
                "attributes": {
                    "status": StatusChoices.PASS,
                },
            }
        ]

        mock_metadata = MagicMock()
        mock_metadata.Marco = "Marco1"
        mock_metadata.Categoria = "Cat1"

        attributes_by_id = {
            "req_1": {
                "attributes": {
                    "req_attributes": [mock_metadata],
                }
            }
        }

        result = _create_marco_category_chart(requirements_list, attributes_by_id)

        assert isinstance(result, io.BytesIO)
        mock_close.assert_called_once_with(mock_fig)

    @patch("tasks.jobs.report.plt.close")
    @patch("tasks.jobs.report.plt.savefig")
    @patch("tasks.jobs.report.plt.subplots")
    def test_create_dimensions_radar_chart(
        self, mock_subplots, mock_savefig, mock_close
    ):
        """Creates radar chart for dimensions."""
        mock_fig, mock_ax = MagicMock(), MagicMock()
        mock_ax.plot = MagicMock()
        mock_ax.fill = MagicMock()
        mock_subplots.return_value = (mock_fig, mock_ax)

        requirements_list = [
            {
                "id": "req_1",
                "attributes": {
                    "status": StatusChoices.PASS,
                },
            }
        ]

        mock_metadata = MagicMock()
        mock_metadata.Dimensiones = ["trazabilidad", "integridad"]

        attributes_by_id = {
            "req_1": {
                "attributes": {
                    "req_attributes": [mock_metadata],
                }
            }
        }

        result = _create_dimensions_radar_chart(requirements_list, attributes_by_id)

        assert isinstance(result, io.BytesIO)
        mock_close.assert_called_once_with(mock_fig)

    @patch("tasks.jobs.report.plt.close")
    @patch("tasks.jobs.report.plt.savefig")
    @patch("tasks.jobs.report.plt.subplots")
    def test_create_chart_closes_figure_on_error(
        self, mock_subplots, mock_savefig, mock_close
    ):
        """Ensures figure is closed even if savefig fails."""
        mock_fig, mock_ax = MagicMock(), MagicMock()
        mock_subplots.return_value = (mock_fig, mock_ax)
        mock_savefig.side_effect = Exception("Save failed")

        requirements_list = []
        attributes_by_id = {}

        with pytest.raises(Exception):
            _create_section_score_chart(requirements_list, attributes_by_id)

        # Verify figure was still closed
        mock_close.assert_called_with(mock_fig)


@pytest.mark.django_db
class TestOptimizationImprovements:
    """Test suite to verify optimization improvements work correctly."""

    def test_constants_are_color_objects(self):
        """Verify color constants are properly instantiated Color objects."""
        assert isinstance(COLOR_BLUE, colors.Color)
        assert isinstance(COLOR_HIGH_RISK, colors.Color)
        assert isinstance(COLOR_SAFE, colors.Color)

    def test_chart_color_constants_are_strings(self):
        """Verify chart color constants are hex strings."""
        assert isinstance(CHART_COLOR_GREEN_1, str)
        assert CHART_COLOR_GREEN_1.startswith("#")
        assert len(CHART_COLOR_GREEN_1) == 7

    def test_style_cache_persists_across_calls(self):
        """Verify style caching reduces object creation."""
        # Clear any existing cache by calling directly
        styles1 = _create_pdf_styles()
        styles2 = _create_pdf_styles()

        # Should be the exact same cached object
        assert id(styles1) == id(styles2)

    def test_helper_functions_return_consistent_results(self):
        """Verify helper functions return consistent results."""
        # Same input should always return same output
        assert _get_color_for_risk_level(3) == _get_color_for_risk_level(3)
        assert _get_color_for_weight(100) == _get_color_for_weight(100)
        assert _get_chart_color_for_percentage(75.0) == _get_chart_color_for_percentage(
            75.0
        )


@pytest.mark.django_db
class TestGenerateComplianceReportsOptimized:
    """Test suite for the optimized generate_compliance_reports_job function."""

    def setup_method(self):
        self.scan_id = str(uuid.uuid4())
        self.provider_id = str(uuid.uuid4())
        self.tenant_id = str(uuid.uuid4())

    def test_no_findings_returns_early_for_both_reports(self):
        """Test that function returns early when no findings exist."""
        with patch("tasks.jobs.report.ScanSummary.objects.filter") as mock_filter:
            mock_filter.return_value.exists.return_value = False

            result = generate_compliance_reports_job(
                tenant_id=self.tenant_id,
                scan_id=self.scan_id,
                provider_id=self.provider_id,
            )

            assert result["threatscore"] == {"upload": False, "path": ""}
            assert result["ens"] == {"upload": False, "path": ""}
            mock_filter.assert_called_once_with(scan_id=self.scan_id)

    @patch("tasks.jobs.report.rmtree")
    @patch("tasks.jobs.report._upload_to_s3")
    @patch("tasks.jobs.report.generate_ens_report")
    @patch("tasks.jobs.report.generate_threatscore_report")
    @patch("tasks.jobs.report._generate_output_directory")
    @patch("tasks.jobs.report._aggregate_requirement_statistics_from_database")
    @patch("tasks.jobs.report.Provider")
    @patch("tasks.jobs.report.ScanSummary")
    def test_generates_both_reports_with_shared_queries(
        self,
        mock_scan_summary,
        mock_provider,
        mock_aggregate_stats,
        mock_gen_dir,
        mock_gen_threatscore,
        mock_gen_ens,
        mock_upload,
        mock_rmtree,
    ):
        """Test that both reports are generated with shared database queries."""
        # Setup mocks
        mock_scan_summary.objects.filter.return_value.exists.return_value = True
        mock_provider_obj = Mock()
        mock_provider_obj.uid = "test-uid"
        mock_provider_obj.provider = "aws"
        mock_provider.objects.get.return_value = mock_provider_obj

        mock_aggregate_stats.return_value = {"check-1": {"passed": 10, "total": 15}}
        # Mock returns different paths for different compliance_framework calls
        mock_gen_dir.side_effect = [
            "/tmp/threatscore_path",  # First call with compliance_framework="threatscore"
            "/tmp/ens_path",  # Second call with compliance_framework="ens"
        ]
        mock_upload.side_effect = [
            "s3://bucket/threatscore.pdf",
            "s3://bucket/ens.pdf",
        ]

        result = generate_compliance_reports_job(
            tenant_id=self.tenant_id,
            scan_id=self.scan_id,
            provider_id=self.provider_id,
            generate_threatscore=True,
            generate_ens=True,
        )

        # Verify Provider fetched only ONCE (optimization)
        mock_provider.objects.get.assert_called_once_with(id=self.provider_id)

        # Verify aggregation called only ONCE (optimization)
        mock_aggregate_stats.assert_called_once_with(self.tenant_id, self.scan_id)

        # Verify both report generation functions were called with shared data
        assert mock_gen_threatscore.call_count == 1
        assert mock_gen_ens.call_count == 1

        # Verify provider_obj and requirement_statistics were passed to both
        threatscore_call_kwargs = mock_gen_threatscore.call_args[1]
        assert threatscore_call_kwargs["provider_obj"] == mock_provider_obj
        assert threatscore_call_kwargs["requirement_statistics"] == {
            "check-1": {"passed": 10, "total": 15}
        }

        ens_call_kwargs = mock_gen_ens.call_args[1]
        assert ens_call_kwargs["provider_obj"] == mock_provider_obj
        assert ens_call_kwargs["requirement_statistics"] == {
            "check-1": {"passed": 10, "total": 15}
        }

        # Verify both reports were uploaded successfully
        assert result["threatscore"]["upload"] is True
        assert result["threatscore"]["path"] == "s3://bucket/threatscore.pdf"
        assert result["ens"]["upload"] is True
        assert result["ens"]["path"] == "s3://bucket/ens.pdf"

    @patch("tasks.jobs.report._aggregate_requirement_statistics_from_database")
    @patch("tasks.jobs.report.Provider")
    @patch("tasks.jobs.report.ScanSummary")
    def test_skips_ens_for_unsupported_provider(
        self, mock_scan_summary, mock_provider, mock_aggregate_stats
    ):
        """Test that ENS report is skipped for M365 provider."""
        mock_scan_summary.objects.filter.return_value.exists.return_value = True
        mock_provider_obj = Mock()
        mock_provider_obj.uid = "test-uid"
        mock_provider_obj.provider = "m365"  # Not supported for ENS
        mock_provider.objects.get.return_value = mock_provider_obj

        result = generate_compliance_reports_job(
            tenant_id=self.tenant_id,
            scan_id=self.scan_id,
            provider_id=self.provider_id,
        )

        # ENS should be skipped, only ThreatScore key should have error/status
        assert "ens" in result
        assert result["ens"]["upload"] is False

    def test_findings_cache_reuses_loaded_findings(self):
        """Test that findings cache properly reuses findings across calls."""
        # Create mock findings
        mock_finding1 = Mock()
        mock_finding1.check_id = "check-1"
        mock_finding2 = Mock()
        mock_finding2.check_id = "check-2"
        mock_finding3 = Mock()
        mock_finding3.check_id = "check-1"

        mock_output1 = Mock()
        mock_output1.check_id = "check-1"
        mock_output2 = Mock()
        mock_output2.check_id = "check-2"
        mock_output3 = Mock()
        mock_output3.check_id = "check-1"

        # Pre-populate cache
        findings_cache = {
            "check-1": [mock_output1, mock_output3],
        }

        with (
            patch("tasks.jobs.report.Finding") as mock_finding_class,
            patch("tasks.jobs.report.FindingOutput") as mock_finding_output,
            patch("tasks.jobs.report.rls_transaction"),
            patch("tasks.jobs.report.batched") as mock_batched,
        ):
            # Setup mocks
            mock_finding_class.all_objects.filter.return_value.order_by.return_value.iterator.return_value = [
                mock_finding2
            ]
            mock_batched.return_value = [([mock_finding2], True)]
            mock_finding_output.transform_api_finding.return_value = mock_output2

            mock_provider = Mock()

            # Call with cache containing check-1, requesting check-1 and check-2
            result = _load_findings_for_requirement_checks(
                tenant_id=self.tenant_id,
                scan_id=self.scan_id,
                check_ids=["check-1", "check-2"],
                prowler_provider=mock_provider,
                findings_cache=findings_cache,
            )

            # Verify check-1 was reused from cache (no DB query)
            assert len(result["check-1"]) == 2
            assert result["check-1"] == [mock_output1, mock_output3]

            # Verify check-2 was loaded from DB
            assert len(result["check-2"]) == 1
            assert result["check-2"][0] == mock_output2

            # Verify cache was updated with check-2
            assert "check-2" in findings_cache
            assert findings_cache["check-2"] == [mock_output2]

            # Verify DB was only queried for check-2 (not check-1)
            filter_call = mock_finding_class.all_objects.filter.call_args
            assert filter_call[1]["check_id__in"] == ["check-2"]
