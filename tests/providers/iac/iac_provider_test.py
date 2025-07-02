from unittest.mock import Mock, patch

import pytest

from prowler.lib.check.models import CheckReportIAC
from prowler.providers.iac.iac_provider import IacProvider
from tests.providers.iac.iac_fixtures import (
    DEFAULT_SCAN_PATH,
    SAMPLE_ANOTHER_FAILED_CHECK,
    SAMPLE_ANOTHER_PASSED_CHECK,
    SAMPLE_ANOTHER_SKIPPED_CHECK,
    SAMPLE_CHECK_WITHOUT_GUIDELINE,
    SAMPLE_CLOUDFORMATION_CHECK,
    SAMPLE_CRITICAL_SEVERITY_CHECK,
    SAMPLE_DOCKERFILE_CHECK,
    SAMPLE_DOCKERFILE_REPORT,
    SAMPLE_FAILED_CHECK,
    SAMPLE_FINDING,
    SAMPLE_HIGH_SEVERITY_CHECK,
    SAMPLE_KUBERNETES_CHECK,
    SAMPLE_KUBERNETES_FINDING,
    SAMPLE_MEDIUM_SEVERITY_CHECK,
    SAMPLE_PASSED_CHECK,
    SAMPLE_SKIPPED_CHECK,
    SAMPLE_YAML_CHECK,
    SAMPLE_YAML_REPORT,
)


class TestIacProvider:
    def test_iac_provider(self):
        """Test IAC provider with default parameters"""

        provider = IacProvider()

        assert provider._type == "iac"
        assert provider.type == "iac"
        assert provider.scan_path == DEFAULT_SCAN_PATH
        assert provider._audit_config == {}
        assert provider._mutelist is None

    def test_iac_provider_custom_scan_path(self):
        """Test IAC provider with custom scan path"""
        custom_path = "/custom/path"

        provider = IacProvider(scan_path=custom_path)

        assert provider._type == "iac"
        assert provider.scan_path == custom_path

    def test_iac_provider_process_check_failed(self):
        """Test processing a failed check"""
        provider = IacProvider()

        report = provider._process_check(SAMPLE_FINDING, SAMPLE_FAILED_CHECK, "FAIL")

        assert isinstance(report, CheckReportIAC)
        assert report.status == "FAIL"

        assert report.check_metadata.Provider == "iac"
        assert report.check_metadata.CheckID == SAMPLE_FAILED_CHECK.check_id
        assert report.check_metadata.CheckTitle == SAMPLE_FAILED_CHECK.check_name
        assert report.check_metadata.Severity == "low"
        assert report.check_metadata.RelatedUrl == SAMPLE_FAILED_CHECK.guideline

    def test_iac_provider_process_check_passed(self):
        """Test processing a passed check"""
        provider = IacProvider()

        report = provider._process_check(SAMPLE_FINDING, SAMPLE_PASSED_CHECK, "PASS")

        assert isinstance(report, CheckReportIAC)
        assert report.status == "PASS"

        assert report.check_metadata.Provider == "iac"
        assert report.check_metadata.CheckID == SAMPLE_PASSED_CHECK.check_id
        assert report.check_metadata.CheckTitle == SAMPLE_PASSED_CHECK.check_name
        assert report.check_metadata.Severity == "low"
        assert report.check_metadata.RelatedUrl == SAMPLE_PASSED_CHECK.guideline

    def test_iac_provider_process_check_skipped(self):
        """Test processing a skipped check"""
        provider = IacProvider()

        report = provider._process_check(SAMPLE_FINDING, SAMPLE_SKIPPED_CHECK, "MUTED")

        assert isinstance(report, CheckReportIAC)
        assert report.status == "MUTED"
        assert report.muted is True

        assert report.check_metadata.Provider == "iac"
        assert report.check_metadata.CheckID == SAMPLE_SKIPPED_CHECK.check_id
        assert report.check_metadata.CheckTitle == SAMPLE_SKIPPED_CHECK.check_name
        assert report.check_metadata.Severity == "high"
        assert report.check_metadata.RelatedUrl == SAMPLE_SKIPPED_CHECK.guideline

    def test_iac_provider_process_check_high_severity(self):
        """Test processing a high severity check"""
        provider = IacProvider()

        report = provider._process_check(
            SAMPLE_FINDING, SAMPLE_HIGH_SEVERITY_CHECK, "FAIL"
        )

        assert isinstance(report, CheckReportIAC)
        assert report.status == "FAIL"
        assert report.check_metadata.Severity == "high"

    def test_iac_provider_process_check_different_framework(self):
        """Test processing a check from a different framework (Kubernetes)"""
        provider = IacProvider()

        report = provider._process_check(
            SAMPLE_KUBERNETES_FINDING, SAMPLE_KUBERNETES_CHECK, "FAIL"
        )

        assert isinstance(report, CheckReportIAC)
        assert report.status == "FAIL"
        assert report.check_metadata.ServiceName == "kubernetes"
        assert report.check_metadata.CheckID == SAMPLE_KUBERNETES_CHECK.check_id

    def test_iac_provider_process_check_no_guideline(self):
        """Test processing a check without guideline URL"""
        provider = IacProvider()

        report = provider._process_check(
            SAMPLE_FINDING, SAMPLE_CHECK_WITHOUT_GUIDELINE, "FAIL"
        )

        assert isinstance(report, CheckReportIAC)
        assert report.status == "FAIL"
        assert report.check_metadata.RelatedUrl == ""

    def test_iac_provider_process_check_medium_severity(self):
        """Test processing a medium severity check"""
        provider = IacProvider()

        report = provider._process_check(
            SAMPLE_FINDING, SAMPLE_MEDIUM_SEVERITY_CHECK, "FAIL"
        )

        assert isinstance(report, CheckReportIAC)
        assert report.status == "FAIL"
        assert report.check_metadata.Severity == "medium"

    def test_iac_provider_process_check_critical_severity(self):
        """Test processing a critical severity check"""
        provider = IacProvider()

        report = provider._process_check(
            SAMPLE_FINDING, SAMPLE_CRITICAL_SEVERITY_CHECK, "FAIL"
        )

        assert isinstance(report, CheckReportIAC)
        assert report.status == "FAIL"
        assert report.check_metadata.Severity == "critical"

    def test_iac_provider_process_check_dockerfile(self):
        """Test processing a Dockerfile check"""
        provider = IacProvider()

        report = provider._process_check(
            SAMPLE_DOCKERFILE_REPORT, SAMPLE_DOCKERFILE_CHECK, "FAIL"
        )

        assert isinstance(report, CheckReportIAC)
        assert report.status == "FAIL"
        assert report.check_metadata.ServiceName == "dockerfile"
        assert report.check_metadata.CheckID == SAMPLE_DOCKERFILE_CHECK.check_id

    def test_iac_provider_process_check_yaml(self):
        """Test processing a YAML check"""
        provider = IacProvider()

        report = provider._process_check(SAMPLE_YAML_REPORT, SAMPLE_YAML_CHECK, "PASS")

        assert isinstance(report, CheckReportIAC)
        assert report.status == "PASS"
        assert report.check_metadata.ServiceName == "yaml"
        assert report.check_metadata.CheckID == SAMPLE_YAML_CHECK.check_id

    @patch("prowler.providers.iac.iac_provider.RunnerRegistry")
    @patch("prowler.providers.iac.iac_provider.RunnerFilter")
    @patch("prowler.providers.iac.iac_provider.logger")
    def test_run_scan_success_with_failed_and_passed_checks(
        self, mock_logger, mock_runner_filter, mock_runner_registry
    ):
        """Test successful run_scan with both failed and passed checks"""
        # Setup mocks
        mock_registry_instance = Mock()
        mock_runner_registry.return_value = mock_registry_instance

        # Create mock reports with failed and passed checks
        mock_report = Mock()
        mock_report.check_type = "terraform"  # Set the check_type attribute
        mock_report.failed_checks = [SAMPLE_FAILED_CHECK]
        mock_report.passed_checks = [SAMPLE_PASSED_CHECK]
        mock_report.skipped_checks = []

        mock_registry_instance.run.return_value = [mock_report]

        provider = IacProvider()
        result = provider.run_scan("/test/directory", ["terraform"], [])

        # Verify logger was called
        mock_logger.info.assert_called_with("Running IaC scan on /test/directory...")

        # Verify RunnerFilter was created with correct parameters
        mock_runner_filter.assert_called_with(
            framework=["terraform"], excluded_paths=[]
        )

        # Verify RunnerRegistry was created and run was called
        mock_runner_registry.assert_called_once()
        mock_registry_instance.run.assert_called_with(root_folder="/test/directory")

        # Verify results
        assert len(result) == 2
        assert all(isinstance(report, CheckReportIAC) for report in result)

        # Check that we have one FAIL and one PASS report
        statuses = [report.status for report in result]
        assert "FAIL" in statuses
        assert "PASS" in statuses

    @patch("prowler.providers.iac.iac_provider.RunnerRegistry")
    @patch("prowler.providers.iac.iac_provider.RunnerFilter")
    @patch("prowler.providers.iac.iac_provider.logger")
    def test_run_scan_with_skipped_checks(
        self, mock_logger, mock_runner_filter, mock_runner_registry
    ):
        """Test run_scan with skipped checks (muted)"""
        # Setup mocks
        mock_registry_instance = Mock()
        mock_runner_registry.return_value = mock_registry_instance

        # Create mock report with skipped checks
        mock_report = Mock()
        mock_report.check_type = "terraform"  # Set the check_type attribute
        mock_report.failed_checks = []
        mock_report.passed_checks = []
        mock_report.skipped_checks = [SAMPLE_SKIPPED_CHECK]

        mock_registry_instance.run.return_value = [mock_report]

        provider = IacProvider()
        result = provider.run_scan("/test/directory", ["all"], ["exclude/path"])

        # Verify RunnerFilter was created with correct parameters
        mock_runner_filter.assert_called_with(
            framework=["all"], excluded_paths=["exclude/path"]
        )

        # Verify results
        assert len(result) == 1
        assert isinstance(result[0], CheckReportIAC)
        assert result[0].status == "MUTED"
        assert result[0].muted is True

    @patch("prowler.providers.iac.iac_provider.RunnerRegistry")
    @patch("prowler.providers.iac.iac_provider.RunnerFilter")
    @patch("prowler.providers.iac.iac_provider.logger")
    def test_run_scan_empty_results(
        self, mock_logger, mock_runner_filter, mock_runner_registry
    ):
        """Test run_scan with no findings"""
        # Setup mocks
        mock_registry_instance = Mock()
        mock_runner_registry.return_value = mock_registry_instance

        # Create mock report with no checks
        mock_report = Mock()
        mock_report.check_type = "terraform"  # Set the check_type attribute
        mock_report.failed_checks = []
        mock_report.passed_checks = []
        mock_report.skipped_checks = []

        mock_registry_instance.run.return_value = [mock_report]

        provider = IacProvider()
        result = provider.run_scan("/test/directory", ["kubernetes"], [])

        # Verify results
        assert len(result) == 0

    @patch("prowler.providers.iac.iac_provider.RunnerRegistry")
    @patch("prowler.providers.iac.iac_provider.RunnerFilter")
    @patch("prowler.providers.iac.iac_provider.logger")
    def test_run_scan_multiple_reports(
        self, mock_logger, mock_runner_filter, mock_runner_registry
    ):
        """Test run_scan with multiple reports from different frameworks"""
        # Setup mocks
        mock_registry_instance = Mock()
        mock_runner_registry.return_value = mock_registry_instance

        # Create multiple mock reports
        mock_report1 = Mock()
        mock_report1.check_type = "terraform"  # Set the check_type attribute
        mock_report1.failed_checks = [SAMPLE_FAILED_CHECK]
        mock_report1.passed_checks = []
        mock_report1.skipped_checks = []

        mock_report2 = Mock()
        mock_report2.check_type = "kubernetes"  # Set the check_type attribute
        mock_report2.failed_checks = []
        mock_report2.passed_checks = [SAMPLE_PASSED_CHECK]
        mock_report2.skipped_checks = []

        mock_registry_instance.run.return_value = [mock_report1, mock_report2]

        provider = IacProvider()
        result = provider.run_scan("/test/directory", ["terraform", "kubernetes"], [])

        # Verify results
        assert len(result) == 2
        assert all(isinstance(report, CheckReportIAC) for report in result)

        # Check that we have one FAIL and one PASS report
        statuses = [report.status for report in result]
        assert "FAIL" in statuses
        assert "PASS" in statuses

    @patch("prowler.providers.iac.iac_provider.RunnerRegistry")
    @patch("prowler.providers.iac.iac_provider.RunnerFilter")
    @patch("prowler.providers.iac.iac_provider.logger")
    @patch("prowler.providers.iac.iac_provider.sys")
    def test_run_scan_exception_handling(
        self, mock_sys, mock_logger, mock_runner_filter, mock_runner_registry
    ):
        """Test run_scan exception handling"""
        # Setup mocks to raise an exception
        mock_registry_instance = Mock()
        mock_runner_registry.return_value = mock_registry_instance
        mock_registry_instance.run.side_effect = Exception("Test exception")

        # Configure sys.exit to raise SystemExit
        mock_sys.exit.side_effect = SystemExit(1)

        provider = IacProvider()

        # The function should call sys.exit(1) when an exception occurs
        with pytest.raises(SystemExit) as exc_info:
            provider.run_scan("/test/directory", ["terraform"], [])

        assert exc_info.value.code == 1

        # Verify logger was called with error information
        mock_logger.critical.assert_called_once()
        critical_call_args = mock_logger.critical.call_args[0][0]
        assert "Exception" in critical_call_args
        assert "Test exception" in critical_call_args

    @patch("prowler.providers.iac.iac_provider.RunnerRegistry")
    @patch("prowler.providers.iac.iac_provider.RunnerFilter")
    @patch("prowler.providers.iac.iac_provider.logger")
    def test_run_scan_with_different_frameworks(
        self, mock_logger, mock_runner_filter, mock_runner_registry
    ):
        """Test run_scan with different framework configurations"""
        # Setup mocks
        mock_registry_instance = Mock()
        mock_runner_registry.return_value = mock_registry_instance

        mock_report = Mock()
        mock_report.check_type = "terraform"  # Set the check_type attribute
        mock_report.failed_checks = []
        mock_report.passed_checks = [SAMPLE_PASSED_CHECK]
        mock_report.skipped_checks = []

        mock_registry_instance.run.return_value = [mock_report]

        provider = IacProvider()

        # Test with specific frameworks
        frameworks = ["terraform", "kubernetes", "cloudformation"]
        result = provider.run_scan("/test/directory", frameworks, [])

        # Verify RunnerFilter was created with correct frameworks
        mock_runner_filter.assert_called_with(framework=frameworks, excluded_paths=[])

        # Verify results
        assert len(result) == 1
        assert result[0].status == "PASS"

    @patch("prowler.providers.iac.iac_provider.RunnerRegistry")
    @patch("prowler.providers.iac.iac_provider.RunnerFilter")
    @patch("prowler.providers.iac.iac_provider.logger")
    def test_run_scan_with_exclude_paths(
        self, mock_logger, mock_runner_filter, mock_runner_registry
    ):
        """Test run_scan with exclude paths"""
        # Setup mocks
        mock_registry_instance = Mock()
        mock_runner_registry.return_value = mock_registry_instance

        mock_report = Mock()
        mock_report.check_type = "terraform"  # Set the check_type attribute
        mock_report.failed_checks = []
        mock_report.passed_checks = [SAMPLE_PASSED_CHECK]
        mock_report.skipped_checks = []

        mock_registry_instance.run.return_value = [mock_report]

        provider = IacProvider()

        # Test with exclude paths
        exclude_paths = ["node_modules", ".git", "vendor"]
        result = provider.run_scan("/test/directory", ["all"], exclude_paths)

        # Verify RunnerFilter was created with correct exclude paths
        mock_runner_filter.assert_called_with(
            framework=["all"], excluded_paths=exclude_paths
        )

        # Verify results
        assert len(result) == 1
        assert result[0].status == "PASS"

    @patch("prowler.providers.iac.iac_provider.RunnerRegistry")
    @patch("prowler.providers.iac.iac_provider.RunnerFilter")
    @patch("prowler.providers.iac.iac_provider.logger")
    def test_run_scan_all_check_types(
        self, mock_logger, mock_runner_filter, mock_runner_registry
    ):
        """Test run_scan with all types of checks (failed, passed, skipped)"""
        # Setup mocks
        mock_registry_instance = Mock()
        mock_runner_registry.return_value = mock_registry_instance

        mock_report = Mock()
        mock_report.check_type = "terraform"  # Set the check_type attribute
        mock_report.failed_checks = [SAMPLE_FAILED_CHECK, SAMPLE_HIGH_SEVERITY_CHECK]
        mock_report.passed_checks = [SAMPLE_PASSED_CHECK, SAMPLE_CLOUDFORMATION_CHECK]
        mock_report.skipped_checks = [SAMPLE_SKIPPED_CHECK]

        mock_registry_instance.run.return_value = [mock_report]

        provider = IacProvider()
        result = provider.run_scan("/test/directory", ["all"], [])

        # Verify results
        assert len(result) == 5  # 2 failed + 2 passed + 1 skipped

        # Check status distribution
        statuses = [report.status for report in result]
        assert statuses.count("FAIL") == 2
        assert statuses.count("PASS") == 2
        assert statuses.count("MUTED") == 1

        # Check that muted reports have muted=True
        muted_reports = [report for report in result if report.status == "MUTED"]
        assert all(report.muted for report in muted_reports)

    @patch("prowler.providers.iac.iac_provider.RunnerRegistry")
    @patch("prowler.providers.iac.iac_provider.RunnerFilter")
    @patch("prowler.providers.iac.iac_provider.logger")
    def test_run_scan_no_reports_returned(
        self, mock_logger, mock_runner_filter, mock_runner_registry
    ):
        """Test run_scan when no reports are returned from registry"""
        # Setup mocks
        mock_registry_instance = Mock()
        mock_runner_registry.return_value = mock_registry_instance

        # Return empty list of reports
        mock_registry_instance.run.return_value = []

        provider = IacProvider()
        result = provider.run_scan("/test/directory", ["terraform"], [])

        # Verify results
        assert len(result) == 0

    @patch("prowler.providers.iac.iac_provider.RunnerRegistry")
    @patch("prowler.providers.iac.iac_provider.RunnerFilter")
    @patch("prowler.providers.iac.iac_provider.logger")
    def test_run_scan_multiple_frameworks_with_different_checks(
        self, mock_logger, mock_runner_filter, mock_runner_registry
    ):
        """Test run_scan with multiple frameworks and different types of checks"""
        # Setup mocks
        mock_registry_instance = Mock()
        mock_runner_registry.return_value = mock_registry_instance

        # Create reports for different frameworks
        terraform_report = Mock()
        terraform_report.check_type = "terraform"
        terraform_report.failed_checks = [
            SAMPLE_FAILED_CHECK,
            SAMPLE_ANOTHER_FAILED_CHECK,
        ]
        terraform_report.passed_checks = [SAMPLE_PASSED_CHECK]
        terraform_report.skipped_checks = []

        kubernetes_report = Mock()
        kubernetes_report.check_type = "kubernetes"
        kubernetes_report.failed_checks = [SAMPLE_KUBERNETES_CHECK]
        kubernetes_report.passed_checks = []
        kubernetes_report.skipped_checks = [SAMPLE_ANOTHER_SKIPPED_CHECK]

        cloudformation_report = Mock()
        cloudformation_report.check_type = "cloudformation"
        cloudformation_report.failed_checks = []
        cloudformation_report.passed_checks = [
            SAMPLE_CLOUDFORMATION_CHECK,
            SAMPLE_ANOTHER_PASSED_CHECK,
        ]
        cloudformation_report.skipped_checks = []

        mock_registry_instance.run.return_value = [
            terraform_report,
            kubernetes_report,
            cloudformation_report,
        ]

        provider = IacProvider()
        result = provider.run_scan(
            "/test/directory", ["terraform", "kubernetes", "cloudformation"], []
        )

        # Verify results
        assert (
            len(result) == 7
        )  # 2 failed + 1 passed (terraform) + 1 failed + 1 skipped (kubernetes) + 2 passed (cloudformation)

        # Check status distribution
        statuses = [report.status for report in result]
        assert statuses.count("FAIL") == 3
        assert statuses.count("PASS") == 3
        assert statuses.count("MUTED") == 1

    def test_run_method_calls_run_scan(self):
        """Test that the run method calls run_scan with correct parameters"""
        provider = IacProvider(
            scan_path="/custom/path", frameworks=["terraform"], exclude_path=["exclude"]
        )

        with patch.object(provider, "run_scan") as mock_run_scan:
            mock_run_scan.return_value = []
            provider.run()

            mock_run_scan.assert_called_once_with(
                "/custom/path", ["terraform"], ["exclude"]
            )
