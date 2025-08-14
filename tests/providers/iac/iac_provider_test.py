import json
import os
import tempfile
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest

from prowler.lib.check.models import CheckReportIAC
from prowler.providers.iac.iac_provider import IacProvider
from tests.providers.iac.iac_fixtures import (
    DEFAULT_SCAN_PATH,
    SAMPLE_ANOTHER_FAILED_CHECK,
    SAMPLE_ANOTHER_PASSED_CHECK,
    SAMPLE_ANOTHER_SKIPPED_CHECK,
    SAMPLE_CLOUDFORMATION_CHECK,
    SAMPLE_DOCKERFILE_CHECK,
    SAMPLE_FAILED_CHECK,
    SAMPLE_HIGH_SEVERITY_CHECK,
    SAMPLE_KUBERNETES_CHECK,
    SAMPLE_PASSED_CHECK,
    SAMPLE_SKIPPED_CHECK,
    SAMPLE_YAML_CHECK,
    get_empty_trivy_output,
    get_invalid_trivy_output,
    get_sample_trivy_json_output,
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

    def test_iac_provider_process_finding_failed(self):
        """Test processing a failed finding"""
        provider = IacProvider()

        report = provider._process_finding(SAMPLE_FAILED_CHECK, "main.tf", "terraform")

        assert isinstance(report, CheckReportIAC)
        assert report.status == "FAIL"

        assert report.check_metadata.Provider == "iac"
        assert report.check_metadata.CheckID == SAMPLE_FAILED_CHECK["ID"]
        assert report.check_metadata.CheckTitle == SAMPLE_FAILED_CHECK["Title"]
        assert report.check_metadata.Severity == "low"
        assert report.check_metadata.RelatedUrl == SAMPLE_FAILED_CHECK["PrimaryURL"]

    def test_iac_provider_process_finding_passed(self):
        """Test processing a passed finding"""
        provider = IacProvider()

        report = provider._process_finding(SAMPLE_PASSED_CHECK, "main.tf", "terraform")

        assert isinstance(report, CheckReportIAC)
        assert report.status == "FAIL"  # Trivy findings are always FAIL by default

        assert report.check_metadata.Provider == "iac"
        assert report.check_metadata.CheckID == SAMPLE_PASSED_CHECK["ID"]
        assert report.check_metadata.CheckTitle == SAMPLE_PASSED_CHECK["Title"]
        assert report.check_metadata.Severity == "low"

    @patch("subprocess.run")
    def test_iac_provider_run_scan_success(self, mock_subprocess):
        """Test successful IAC scan with Trivy"""
        provider = IacProvider()

        mock_subprocess.return_value = MagicMock(
            stdout=get_sample_trivy_json_output(), stderr=""
        )

        reports = provider.run_scan(
            "/test/directory", ["vuln", "misconfig", "secret"], []
        )

        # Should have 3 misconfigurations from the sample output
        assert len(reports) == 3

        # Check that we have failed reports (Trivy findings are always FAIL by default)
        failed_reports = [r for r in reports if r.status == "FAIL"]
        assert len(failed_reports) == 3

        # Verify subprocess was called correctly
        mock_subprocess.assert_called_once_with(
            [
                "trivy",
                "fs",
                "/test/directory",
                "--format",
                "json",
                "--scanners",
                "vuln,misconfig,secret",
                "--parallel",
                "0",
                "--include-non-failures",
            ],
            capture_output=True,
            text=True,
        )

    @patch("subprocess.run")
    def test_iac_provider_run_scan_empty_output(self, mock_subprocess):
        """Test IAC scan with empty Trivy output"""
        provider = IacProvider()

        mock_subprocess.return_value = MagicMock(
            stdout=get_empty_trivy_output(), stderr=""
        )

        reports = provider.run_scan(
            "/test/directory", ["vuln", "misconfig", "secret"], []
        )
        assert len(reports) == 0

    def test_provider_run_local_scan(self):
        scan_path = "."
        provider = IacProvider(scan_path=scan_path)
        with mock.patch(
            "prowler.providers.iac.iac_provider.IacProvider.run_scan",
        ) as mock_run_scan:
            provider.run()
            mock_run_scan.assert_called_with(
                scan_path, ["vuln", "misconfig", "secret"], []
            )

    @mock.patch.dict(os.environ, {}, clear=True)
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
                mock_clone.assert_called_with(scan_repository_url, None, None, None)
                mock_run_scan.assert_called_with(
                    temp_dir, ["vuln", "misconfig", "secret"], []
                )

    @mock.patch.dict(os.environ, {}, clear=True)
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

    @mock.patch.dict(os.environ, {}, clear=True)
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

    @patch("subprocess.run")
    def test_iac_provider_process_check_medium_severity(self, mock_subprocess):
        """Test processing a medium severity check"""
        provider = IacProvider()

        mock_subprocess.return_value = MagicMock(
            stdout=get_invalid_trivy_output(), stderr=""
        )

        with pytest.raises(SystemExit) as excinfo:
            provider.run_scan("/test/directory", ["all"], [])

        assert excinfo.value.code == 1

    @patch("subprocess.run")
    def test_iac_provider_run_scan_null_output(self, mock_subprocess):
        """Test IAC scan with null Trivy output"""
        provider = IacProvider()

        mock_subprocess.return_value = MagicMock(stdout="null", stderr="")

        with pytest.raises(SystemExit) as exc_info:
            provider.run_scan("/test/directory", ["vuln", "misconfig", "secret"], [])
        assert exc_info.value.code == 1

    def test_iac_provider_process_finding_dockerfile(self):
        """Test processing a Dockerfile finding"""
        provider = IacProvider()

        report = provider._process_finding(
            SAMPLE_DOCKERFILE_CHECK, "Dockerfile", "dockerfile"
        )

        assert isinstance(report, CheckReportIAC)
        assert report.status == "FAIL"
        assert report.check_metadata.ServiceName == "dockerfile"
        assert report.check_metadata.CheckID == SAMPLE_DOCKERFILE_CHECK["ID"]

    def test_iac_provider_process_finding_yaml(self):
        """Test processing a YAML finding"""
        provider = IacProvider()

        report = provider._process_finding(
            SAMPLE_YAML_CHECK, "deployment.yaml", "kubernetes"
        )

        assert isinstance(report, CheckReportIAC)
        assert report.status == "FAIL"  # Trivy findings are always FAIL by default
        assert report.check_metadata.ServiceName == "kubernetes"
        assert report.check_metadata.CheckID == SAMPLE_YAML_CHECK["ID"]

    @patch("subprocess.run")
    def test_run_scan_success_with_failed_and_passed_checks(self, mock_subprocess):
        """Test successful run_scan with both failed and passed checks"""
        provider = IacProvider()

        # Create sample Trivy output with both failed and passed checks
        sample_output = {
            "Results": [
                {
                    "Target": "main.tf",
                    "Type": "terraform",
                    "Misconfigurations": [SAMPLE_FAILED_CHECK, SAMPLE_PASSED_CHECK],
                    "Vulnerabilities": [],
                    "Secrets": [],
                    "Licenses": [],
                }
            ]
        }

        mock_subprocess.return_value = MagicMock(
            stdout=json.dumps(sample_output), stderr=""
        )

        result = provider.run_scan(
            "/test/directory", ["vuln", "misconfig", "secret"], []
        )

        # Verify results
        assert len(result) == 2
        assert all(isinstance(report, CheckReportIAC) for report in result)

        # Check that we have FAIL reports (Trivy findings are always FAIL by default)
        statuses = [report.status for report in result]
        assert all(status == "FAIL" for status in statuses)

    @patch("subprocess.run")
    def test_run_scan_with_skipped_checks(self, mock_subprocess):
        """Test run_scan with skipped checks (muted)"""
        provider = IacProvider()

        # Create sample Trivy output with skipped checks
        sample_output = {
            "Results": [
                {
                    "Target": "main.tf",
                    "Type": "terraform",
                    "Misconfigurations": [SAMPLE_SKIPPED_CHECK],
                    "Vulnerabilities": [],
                    "Secrets": [],
                    "Licenses": [],
                }
            ]
        }

        mock_subprocess.return_value = MagicMock(
            stdout=json.dumps(sample_output), stderr=""
        )

        result = provider.run_scan(
            "/test/directory", ["vuln", "misconfig", "secret"], ["exclude/path"]
        )

        # Verify results
        assert len(result) == 1
        assert isinstance(result[0], CheckReportIAC)
        assert result[0].status == "MUTED"
        assert result[0].muted is True

    @patch("subprocess.run")
    def test_run_scan_empty_results(self, mock_subprocess):
        """Test run_scan with no findings"""
        provider = IacProvider()

        mock_subprocess.return_value = MagicMock(
            stdout=json.dumps({"Results": []}), stderr=""
        )

        result = provider.run_scan(
            "/test/directory", ["vuln", "misconfig", "secret"], []
        )

        # Verify results
        assert len(result) == 0

    @patch("subprocess.run")
    def test_run_scan_multiple_reports(self, mock_subprocess):
        """Test run_scan with multiple reports from different frameworks"""
        provider = IacProvider()

        # Create sample Trivy output with multiple frameworks
        sample_output = {
            "Results": [
                {
                    "Target": "main.tf",
                    "Type": "terraform",
                    "Misconfigurations": [SAMPLE_FAILED_CHECK],
                    "Vulnerabilities": [],
                    "Secrets": [],
                    "Licenses": [],
                },
                {
                    "Target": "deployment.yaml",
                    "Type": "kubernetes",
                    "Misconfigurations": [SAMPLE_PASSED_CHECK],
                    "Vulnerabilities": [],
                    "Secrets": [],
                    "Licenses": [],
                },
            ]
        }

        mock_subprocess.return_value = MagicMock(
            stdout=json.dumps(sample_output), stderr=""
        )

        result = provider.run_scan(
            "/test/directory", ["vuln", "misconfig", "secret"], []
        )

        # Verify results
        assert len(result) == 2
        assert all(isinstance(report, CheckReportIAC) for report in result)

        # Check that we have FAIL reports (Trivy findings are always FAIL by default)
        statuses = [report.status for report in result]
        assert all(status == "FAIL" for status in statuses)

    @patch("subprocess.run")
    def test_run_scan_exception_handling(self, mock_subprocess):
        """Test run_scan exception handling"""
        provider = IacProvider()

        # Make subprocess.run raise an exception
        mock_subprocess.side_effect = Exception("Test exception")

        with pytest.raises(SystemExit) as exc_info:
            provider.run_scan("/test/directory", ["vuln", "misconfig", "secret"], [])

        assert exc_info.value.code == 1

    @patch("subprocess.run")
    def test_run_scan_with_different_frameworks(self, mock_subprocess):
        """Test run_scan with different scanner configurations"""
        provider = IacProvider()

        sample_output = {
            "Results": [
                {
                    "Target": "main.tf",
                    "Type": "terraform",
                    "Misconfigurations": [SAMPLE_PASSED_CHECK],
                    "Vulnerabilities": [],
                    "Secrets": [],
                    "Licenses": [],
                }
            ]
        }

        mock_subprocess.return_value = MagicMock(
            stdout=json.dumps(sample_output), stderr=""
        )

        # Test with specific scanners
        scanners = ["vuln", "misconfig", "secret"]
        result = provider.run_scan("/test/directory", scanners, [])

        # Verify subprocess was called with correct scanners
        mock_subprocess.assert_called_once_with(
            [
                "trivy",
                "fs",
                "/test/directory",
                "--format",
                "json",
                "--scanners",
                ",".join(scanners),
                "--parallel",
                "0",
                "--include-non-failures",
            ],
            capture_output=True,
            text=True,
        )

        # Verify results
        assert len(result) == 1
        assert result[0].status == "FAIL"  # Trivy findings are always FAIL by default

    @patch("subprocess.run")
    def test_run_scan_with_exclude_paths(self, mock_subprocess):
        """Test run_scan with exclude paths"""
        provider = IacProvider()

        sample_output = {
            "Results": [
                {
                    "Target": "main.tf",
                    "Type": "terraform",
                    "Misconfigurations": [SAMPLE_PASSED_CHECK],
                    "Vulnerabilities": [],
                    "Secrets": [],
                    "Licenses": [],
                }
            ]
        }

        mock_subprocess.return_value = MagicMock(
            stdout=json.dumps(sample_output), stderr=""
        )

        # Test with exclude paths
        exclude_paths = ["node_modules", ".git", "vendor"]
        result = provider.run_scan(
            "/test/directory", ["vuln", "misconfig", "secret"], exclude_paths
        )

        # Verify subprocess was called with correct exclude paths
        expected_command = [
            "trivy",
            "fs",
            "/test/directory",
            "--format",
            "json",
            "--scanners",
            "vuln,misconfig,secret",
            "--parallel",
            "0",
            "--include-non-failures",
            "--skip-dirs",
            ",".join(exclude_paths),
        ]
        mock_subprocess.assert_called_once_with(
            expected_command,
            capture_output=True,
            text=True,
        )

        # Verify results
        assert len(result) == 1
        assert result[0].status == "FAIL"  # Trivy findings are always FAIL by default

    @patch("subprocess.run")
    def test_run_scan_all_check_types(self, mock_subprocess):
        """Test run_scan with all types of checks (failed, passed, skipped)"""
        provider = IacProvider()

        sample_output = {
            "Results": [
                {
                    "Target": "main.tf",
                    "Type": "terraform",
                    "Misconfigurations": [
                        SAMPLE_FAILED_CHECK,
                        SAMPLE_HIGH_SEVERITY_CHECK,
                        SAMPLE_PASSED_CHECK,
                        SAMPLE_CLOUDFORMATION_CHECK,
                        SAMPLE_SKIPPED_CHECK,
                    ],
                    "Vulnerabilities": [],
                    "Secrets": [],
                    "Licenses": [],
                }
            ]
        }

        mock_subprocess.return_value = MagicMock(
            stdout=json.dumps(sample_output), stderr=""
        )

        result = provider.run_scan(
            "/test/directory", ["vuln", "misconfig", "secret"], []
        )

        # Verify results
        assert len(result) == 5  # 5 misconfigurations

        # Check status distribution
        statuses = [report.status for report in result]
        assert statuses.count("FAIL") == 4  # 4 regular findings
        assert statuses.count("MUTED") == 1  # 1 skipped finding

        # Check that muted reports have muted=True
        muted_reports = [report for report in result if report.status == "MUTED"]
        assert all(report.muted for report in muted_reports)

    @patch("subprocess.run")
    def test_run_scan_no_reports_returned(self, mock_subprocess):
        """Test run_scan when no reports are returned from registry"""
        provider = IacProvider()

        # Return empty list of reports
        mock_subprocess.return_value = MagicMock(
            stdout=json.dumps({"Results": []}), stderr=""
        )

        result = provider.run_scan(
            "/test/directory", ["vuln", "misconfig", "secret"], []
        )

        # Verify results
        assert len(result) == 0

    @patch("subprocess.run")
    def test_run_scan_multiple_frameworks_with_different_checks(self, mock_subprocess):
        """Test run_scan with multiple frameworks and different types of checks"""
        provider = IacProvider()

        # Create sample Trivy output with multiple frameworks and different check types
        sample_output = {
            "Results": [
                {
                    "Target": "main.tf",
                    "Type": "terraform",
                    "Misconfigurations": [
                        SAMPLE_FAILED_CHECK,
                        SAMPLE_ANOTHER_FAILED_CHECK,
                        SAMPLE_PASSED_CHECK,
                    ],
                    "Vulnerabilities": [],
                    "Secrets": [],
                    "Licenses": [],
                },
                {
                    "Target": "deployment.yaml",
                    "Type": "kubernetes",
                    "Misconfigurations": [
                        SAMPLE_KUBERNETES_CHECK,
                        SAMPLE_ANOTHER_SKIPPED_CHECK,
                    ],
                    "Vulnerabilities": [],
                    "Secrets": [],
                    "Licenses": [],
                },
                {
                    "Target": "template.yaml",
                    "Type": "cloudformation",
                    "Misconfigurations": [
                        SAMPLE_CLOUDFORMATION_CHECK,
                        SAMPLE_ANOTHER_PASSED_CHECK,
                    ],
                    "Vulnerabilities": [],
                    "Secrets": [],
                    "Licenses": [],
                },
            ]
        }

        mock_subprocess.return_value = MagicMock(
            stdout=json.dumps(sample_output), stderr=""
        )

        result = provider.run_scan(
            "/test/directory", ["vuln", "misconfig", "secret"], []
        )

        # Verify results
        assert (
            len(result) == 7
        )  # 3 terraform + 2 kubernetes + 2 cloudformation = 7 total

        # Check status distribution
        statuses = [report.status for report in result]
        assert statuses.count("FAIL") == 6  # 6 regular findings
        assert statuses.count("MUTED") == 1  # 1 skipped finding

    def test_run_method_calls_run_scan(self):
        """Test that the run method calls run_scan with correct parameters"""
        provider = IacProvider(
            scan_path="/custom/path",
            scanners=["vuln", "misconfig"],
            exclude_path=["exclude"],
        )

        with patch.object(provider, "run_scan") as mock_run_scan:
            mock_run_scan.return_value = []
            provider.run()

            mock_run_scan.assert_called_once_with(
                "/custom/path", ["vuln", "misconfig"], ["exclude"]
            )

    @mock.patch("prowler.providers.iac.iac_provider.porcelain.clone")
    @mock.patch("tempfile.mkdtemp", return_value="/tmp/fake-dir")
    def test_clone_repository_no_auth(self, _mock_mkdtemp, mock_clone):
        provider = IacProvider()
        url = "https://github.com/user/repo.git"
        provider._clone_repository(url)
        mock_clone.assert_called_with(url, "/tmp/fake-dir", depth=1)

    @mock.patch("prowler.providers.iac.iac_provider.porcelain.clone")
    @mock.patch("tempfile.mkdtemp", return_value="/tmp/fake-dir")
    def test_clone_repository_with_pat(self, _mock_mkdtemp, mock_clone):
        provider = IacProvider()
        url = "https://github.com/user/repo.git"
        provider._clone_repository(
            url, github_username="user", personal_access_token="token123"
        )
        expected_url = "https://user:token123@github.com/user/repo.git"
        mock_clone.assert_called_with(expected_url, "/tmp/fake-dir", depth=1)

    @mock.patch("prowler.providers.iac.iac_provider.porcelain.clone")
    @mock.patch("tempfile.mkdtemp", return_value="/tmp/fake-dir")
    def test_clone_repository_with_oauth(self, _mock_mkdtemp, mock_clone):
        provider = IacProvider()
        url = "https://github.com/user/repo.git"
        provider._clone_repository(url, oauth_app_token="oauth456")
        expected_url = "https://oauth2:oauth456@github.com/user/repo.git"
        mock_clone.assert_called_with(expected_url, "/tmp/fake-dir", depth=1)
