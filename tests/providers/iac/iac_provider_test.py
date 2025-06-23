import tempfile
from unittest import mock
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

    def test_provider_run_local_scan(self):
        scan_path = "."
        provider = IacProvider(scan_path=scan_path)
        with mock.patch(
            "prowler.providers.iac.iac_provider.IacProvider.run_scan",
        ) as mock_run_scan:
            provider.run()
            mock_run_scan.assert_called_with(scan_path)

    def test_provider_run_remote_scan(self):
        scan_repository_url = "https://github.com/user/repo"
        provider = IacProvider(scan_repository_url=scan_repository_url)

        with tempfile.TemporaryDirectory() as temp_dir:
            with (
                mock.patch(
                    "prowler.providers.iac.iac_provider.IacProvider._clone_repository",
                    return_value=temp_dir,
                ) as mock_clone,
                mock.patch(
                    "prowler.providers.iac.iac_provider.IacProvider.run_scan"
                ) as mock_run_scan,
            ):
                provider.run()
                mock_clone.assert_called_with(scan_repository_url)
                mock_run_scan.assert_called_with(temp_dir)

    def test_print_credentials_local(self):
        scan_path = "/path/to/scan"
        provider = IacProvider(scan_path=scan_path)
        with mock.patch("builtins.print") as mock_print:
            provider.print_credentials()
            assert any(
                f"Directory: \x1b[33m{scan_path}\x1b[0m" in call.args[0]
                for call in mock_print.call_args_list
            )
            assert any(
                "Scanning local IaC directory:" in call.args[0]
                for call in mock_print.call_args_list
            )

    def test_print_credentials_remote(self):
        repo_url = "https://github.com/user/repo"
        provider = IacProvider(scan_repository_url=repo_url)
        with mock.patch("builtins.print") as mock_print:
            provider.print_credentials()
            assert any(
                f"Repository: \x1b[33m{repo_url}\x1b[0m" in call.args[0]
                for call in mock_print.call_args_list
            )
            assert any(
                "Scanning remote IaC repository:" in call.args[0]
                for call in mock_print.call_args_list
            )
