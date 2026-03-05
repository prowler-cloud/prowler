import uuid
from unittest.mock import Mock, patch

import matplotlib
import pytest
from reportlab.lib import colors
from tasks.jobs.report import generate_compliance_reports, generate_threatscore_report
from tasks.jobs.reports import (
    CHART_COLOR_GREEN_1,
    CHART_COLOR_GREEN_2,
    CHART_COLOR_ORANGE,
    CHART_COLOR_RED,
    CHART_COLOR_YELLOW,
    COLOR_BLUE,
    COLOR_ENS_ALTO,
    COLOR_HIGH_RISK,
    COLOR_LOW_RISK,
    COLOR_MEDIUM_RISK,
    COLOR_NIS2_PRIMARY,
    COLOR_SAFE,
    create_pdf_styles,
    get_chart_color_for_percentage,
    get_color_for_compliance,
    get_color_for_risk_level,
    get_color_for_weight,
)
from tasks.jobs.threatscore_utils import (
    _aggregate_requirement_statistics_from_database,
    _load_findings_for_requirement_checks,
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

        assert "check_1" in result
        assert result["check_1"]["passed"] == 1
        assert result["check_1"]["total"] == 2

        assert "check_2" in result
        assert result["check_2"]["passed"] == 1
        assert result["check_2"]["total"] == 1

    def test_handles_empty_scan(self, tenants_fixture, scans_fixture):
        """Verify empty result is returned for scan with no findings."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]

        result = _aggregate_requirement_statistics_from_database(
            str(tenant.id), str(scan.id)
        )

        assert result == {}

    def test_only_failed_findings(self, tenants_fixture, scans_fixture):
        """Verify correct counts when all findings are FAIL."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]

        Finding.objects.create(
            tenant_id=tenant.id,
            scan=scan,
            uid="finding-1",
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
            uid="finding-2",
            check_id="check_1",
            status=StatusChoices.FAIL,
            severity=Severity.high,
            impact=Severity.high,
            check_metadata={},
            raw_result={},
        )

        result = _aggregate_requirement_statistics_from_database(
            str(tenant.id), str(scan.id)
        )

        assert result["check_1"]["passed"] == 0
        assert result["check_1"]["total"] == 2

    def test_multiple_findings_same_check(self, tenants_fixture, scans_fixture):
        """Verify multiple findings for same check are correctly aggregated."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]

        for i in range(5):
            Finding.objects.create(
                tenant_id=tenant.id,
                scan=scan,
                uid=f"finding-{i}",
                check_id="check_1",
                status=StatusChoices.PASS if i % 2 == 0 else StatusChoices.FAIL,
                severity=Severity.high,
                impact=Severity.high,
                check_metadata={},
                raw_result={},
            )

        result = _aggregate_requirement_statistics_from_database(
            str(tenant.id), str(scan.id)
        )

        assert result["check_1"]["passed"] == 3
        assert result["check_1"]["total"] == 5

    def test_mixed_statuses(self, tenants_fixture, scans_fixture):
        """Verify MANUAL status is counted in total but not passed."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]

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
            status=StatusChoices.MANUAL,
            severity=Severity.high,
            impact=Severity.high,
            check_metadata={},
            raw_result={},
        )

        result = _aggregate_requirement_statistics_from_database(
            str(tenant.id), str(scan.id)
        )

        # MANUAL findings are excluded from the aggregation query
        # since it only counts PASS and FAIL statuses
        assert result["check_1"]["passed"] == 1
        assert result["check_1"]["total"] == 1


class TestColorHelperFunctions:
    """Test suite for color helper functions."""

    def test_get_color_for_risk_level_high(self):
        """Test high risk level returns correct color."""
        result = get_color_for_risk_level(5)
        assert result == COLOR_HIGH_RISK

    def test_get_color_for_risk_level_medium_high(self):
        """Test risk level 4 returns high risk color."""
        result = get_color_for_risk_level(4)
        assert result == COLOR_HIGH_RISK  # >= 4 is high risk

    def test_get_color_for_risk_level_medium(self):
        """Test risk level 3 returns medium risk color."""
        result = get_color_for_risk_level(3)
        assert result == COLOR_MEDIUM_RISK  # >= 3 is medium risk

    def test_get_color_for_risk_level_low(self):
        """Test low risk level returns safe color."""
        result = get_color_for_risk_level(1)
        assert result == COLOR_SAFE  # < 2 is safe

    def test_get_color_for_weight_high(self):
        """Test high weight returns correct color."""
        result = get_color_for_weight(150)
        assert result == COLOR_HIGH_RISK  # > 100 is high risk

    def test_get_color_for_weight_medium(self):
        """Test medium weight returns low risk color."""
        result = get_color_for_weight(100)
        assert result == COLOR_LOW_RISK  # 51-100 is low risk

    def test_get_color_for_weight_low(self):
        """Test low weight returns safe color."""
        result = get_color_for_weight(50)
        assert result == COLOR_SAFE  # <= 50 is safe

    def test_get_color_for_compliance_high(self):
        """Test high compliance returns green color."""
        result = get_color_for_compliance(85)
        assert result == COLOR_SAFE

    def test_get_color_for_compliance_medium(self):
        """Test medium compliance returns yellow color."""
        result = get_color_for_compliance(70)
        assert result == COLOR_LOW_RISK

    def test_get_color_for_compliance_low(self):
        """Test low compliance returns red color."""
        result = get_color_for_compliance(50)
        assert result == COLOR_HIGH_RISK

    def test_get_chart_color_for_percentage_excellent(self):
        """Test excellent percentage returns correct chart color."""
        result = get_chart_color_for_percentage(90)
        assert result == CHART_COLOR_GREEN_1

    def test_get_chart_color_for_percentage_good(self):
        """Test good percentage returns correct chart color."""
        result = get_chart_color_for_percentage(70)
        assert result == CHART_COLOR_GREEN_2

    def test_get_chart_color_for_percentage_fair(self):
        """Test fair percentage returns correct chart color."""
        result = get_chart_color_for_percentage(50)
        assert result == CHART_COLOR_YELLOW

    def test_get_chart_color_for_percentage_poor(self):
        """Test poor percentage returns correct chart color."""
        result = get_chart_color_for_percentage(30)
        assert result == CHART_COLOR_ORANGE

    def test_get_chart_color_for_percentage_critical(self):
        """Test critical percentage returns correct chart color."""
        result = get_chart_color_for_percentage(10)
        assert result == CHART_COLOR_RED


class TestPDFStylesCreation:
    """Test suite for PDF styles creation."""

    def test_create_pdf_styles_returns_dict(self):
        """Test that create_pdf_styles returns a dictionary."""
        result = create_pdf_styles()
        assert isinstance(result, dict)

    def test_create_pdf_styles_caches_result(self):
        """Test that create_pdf_styles caches the result."""
        result1 = create_pdf_styles()
        result2 = create_pdf_styles()
        assert result1 is result2

    def test_pdf_styles_have_correct_keys(self):
        """Test that PDF styles dictionary has expected keys."""
        result = create_pdf_styles()
        expected_keys = ["title", "h1", "h2", "h3", "normal", "normal_center"]
        for key in expected_keys:
            assert key in result


@pytest.mark.django_db
class TestLoadFindingsForChecks:
    """Test suite for _load_findings_for_requirement_checks function."""

    def test_empty_check_ids_returns_empty(self, tenants_fixture, providers_fixture):
        """Test that empty check_ids list returns empty dict."""
        tenant = tenants_fixture[0]

        mock_prowler_provider = Mock()
        mock_prowler_provider.identity.account = "test-account"

        result = _load_findings_for_requirement_checks(
            str(tenant.id), str(uuid.uuid4()), [], mock_prowler_provider
        )

        assert result == {}


@pytest.mark.django_db
class TestGenerateThreatscoreReportFunction:
    """Test suite for generate_threatscore_report function."""

    @patch("tasks.jobs.reports.base.initialize_prowler_provider")
    def test_generate_threatscore_report_exception_handling(
        self,
        mock_initialize_provider,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
    ):
        """Test that exceptions during report generation are properly handled."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]
        provider = providers_fixture[0]

        mock_initialize_provider.side_effect = Exception("Test exception")

        with pytest.raises(Exception) as exc_info:
            generate_threatscore_report(
                tenant_id=str(tenant.id),
                scan_id=str(scan.id),
                compliance_id="prowler_threatscore_aws",
                output_path="/tmp/test_report.pdf",
                provider_id=str(provider.id),
            )

        assert "Test exception" in str(exc_info.value)


@pytest.mark.django_db
class TestGenerateComplianceReportsOptimized:
    """Test suite for generate_compliance_reports function."""

    @patch("tasks.jobs.report._upload_to_s3")
    @patch("tasks.jobs.report.generate_threatscore_report")
    @patch("tasks.jobs.report.generate_ens_report")
    @patch("tasks.jobs.report.generate_nis2_report")
    def test_no_findings_returns_early_for_both_reports(
        self,
        mock_nis2,
        mock_ens,
        mock_threatscore,
        mock_upload,
        tenants_fixture,
        scans_fixture,
        providers_fixture,
    ):
        """Test that function returns early when scan has no findings."""
        tenant = tenants_fixture[0]
        scan = scans_fixture[0]
        provider = providers_fixture[0]

        result = generate_compliance_reports(
            tenant_id=str(tenant.id),
            scan_id=str(scan.id),
            provider_id=str(provider.id),
            generate_threatscore=True,
            generate_ens=True,
            generate_nis2=True,
        )

        assert result["threatscore"]["upload"] is False
        assert result["ens"]["upload"] is False
        assert result["nis2"]["upload"] is False

        mock_threatscore.assert_not_called()
        mock_ens.assert_not_called()
        mock_nis2.assert_not_called()


class TestOptimizationImprovements:
    """Test suite for optimization-related functionality."""

    def test_chart_color_constants_are_strings(self):
        """Verify chart color constants are valid hex color strings."""
        assert CHART_COLOR_GREEN_1.startswith("#")
        assert CHART_COLOR_GREEN_2.startswith("#")
        assert CHART_COLOR_YELLOW.startswith("#")
        assert CHART_COLOR_ORANGE.startswith("#")
        assert CHART_COLOR_RED.startswith("#")

    def test_color_constants_are_color_objects(self):
        """Verify color constants are Color objects."""
        assert isinstance(COLOR_BLUE, colors.Color)
        assert isinstance(COLOR_HIGH_RISK, colors.Color)
        assert isinstance(COLOR_SAFE, colors.Color)
        assert isinstance(COLOR_ENS_ALTO, colors.Color)
        assert isinstance(COLOR_NIS2_PRIMARY, colors.Color)
