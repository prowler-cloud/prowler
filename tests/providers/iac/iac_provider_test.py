from unittest.mock import MagicMock, patch

import pytest

from prowler.lib.check.models import CheckReportIAC
from prowler.providers.iac.iac_provider import IacProvider
from tests.providers.iac.iac_fixtures import (
    DEFAULT_SCAN_PATH,
    SAMPLE_FAILED_CHECK,
    SAMPLE_FINDING,
    SAMPLE_PASSED_CHECK,
    get_empty_checkov_output,
    get_invalid_checkov_output,
    get_sample_checkov_json_output,
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
        assert report.check_metadata.CheckID == SAMPLE_FAILED_CHECK["check_id"]
        assert report.check_metadata.CheckTitle == SAMPLE_FAILED_CHECK["check_name"]
        assert report.check_metadata.Severity == "low"
        assert report.check_metadata.RelatedUrl == SAMPLE_FAILED_CHECK["guideline"]

    def test_iac_provider_process_check_passed(self):
        """Test processing a passed check"""
        provider = IacProvider()

        report = provider._process_check(SAMPLE_FINDING, SAMPLE_PASSED_CHECK, "PASS")

        assert isinstance(report, CheckReportIAC)
        assert report.status == "PASS"

        assert report.check_metadata.Provider == "iac"
        assert report.check_metadata.CheckID == SAMPLE_PASSED_CHECK["check_id"]
        assert report.check_metadata.CheckTitle == SAMPLE_PASSED_CHECK["check_name"]
        assert report.check_metadata.Severity == "low"

    @patch("subprocess.run")
    def test_iac_provider_run_scan_success(self, mock_subprocess):
        """Test successful IAC scan with Checkov"""
        provider = IacProvider()

        mock_subprocess.return_value = MagicMock(
            stdout=get_sample_checkov_json_output(), stderr=""
        )

        reports = provider.run_scan("/test/directory")

        # Should have 2 failed checks + 1 passed check = 3 total reports
        assert len(reports) == 3

        # Check that we have both failed and passed reports
        failed_reports = [r for r in reports if r.status == "FAIL"]
        passed_reports = [r for r in reports if r.status == "PASS"]

        assert len(failed_reports) == 2
        assert len(passed_reports) == 1

        # Verify subprocess was called correctly
        mock_subprocess.assert_called_once_with(
            ["checkov", "-d", "/test/directory", "-o", "json"],
            capture_output=True,
            text=True,
        )

    @patch("subprocess.run")
    def test_iac_provider_run_scan_empty_output(self, mock_subprocess):
        """Test IAC scan with empty Checkov output"""
        provider = IacProvider()

        mock_subprocess.return_value = MagicMock(
            stdout=get_empty_checkov_output(), stderr=""
        )

        reports = provider.run_scan("/test/directory")

        assert len(reports) == 0

    @patch("subprocess.run")
    def test_iac_provider_run_scan_invalid_json(self, mock_subprocess):
        """Test IAC scan with invalid JSON output"""
        provider = IacProvider()

        mock_subprocess.return_value = MagicMock(
            stdout=get_invalid_checkov_output(), stderr=""
        )

        with pytest.raises(SystemExit) as excinfo:
            provider.run_scan("/test/directory")

        assert excinfo.value.code == 1

    @patch("subprocess.run")
    def test_iac_provider_run_scan_null_output(self, mock_subprocess):
        """Test IAC scan with null Checkov output"""
        provider = IacProvider()

        mock_subprocess.return_value = MagicMock(stdout="null", stderr="")

        reports = provider.run_scan("/test/directory")

        assert len(reports) == 0
