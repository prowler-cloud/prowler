import json
from unittest.mock import MagicMock, patch

import pytest

from prowler.providers.github_actions.github_actions_provider import (
    GithubActionsProvider,
)


class TestGithubActionsProvider:
    """Test cases for the GitHub Actions Provider"""

    def test_github_actions_provider_init_default(self):
        """Test provider initialization with default values"""
        with patch.object(GithubActionsProvider, "setup_session", return_value=None):
            provider = GithubActionsProvider()

            assert provider.type == "github_actions"
            assert provider.workflow_path == "."
            assert provider.repository_url is None
            assert provider.exclude_workflows == []
            assert provider.auth_method == "No auth"
            assert provider.region == "global"
            assert provider.audited_account == "github_actions"

    def test_github_actions_provider_init_with_repository_url(self):
        """Test provider initialization with repository URL"""
        with patch.object(GithubActionsProvider, "setup_session", return_value=None):
            provider = GithubActionsProvider(
                repository_url="https://github.com/test/repo",
                github_username="testuser",
                personal_access_token="token123",
            )

            assert provider.repository_url == "https://github.com/test/repo"
            assert provider.github_username == "testuser"
            assert provider.personal_access_token == "token123"
            assert provider.auth_method == "Personal Access Token"

    def test_github_actions_provider_init_with_oauth_token(self):
        """Test provider initialization with OAuth token"""
        with patch.object(GithubActionsProvider, "setup_session", return_value=None):
            provider = GithubActionsProvider(
                repository_url="https://github.com/test/repo",
                oauth_app_token="oauth_token123",
            )

            assert provider.oauth_app_token == "oauth_token123"
            assert provider.auth_method == "OAuth App Token"
            assert provider.github_username is None
            assert provider.personal_access_token is None

    def test_process_zizmor_finding(self):
        """Test processing a zizmor finding"""
        with patch.object(GithubActionsProvider, "setup_session", return_value=None):
            provider = GithubActionsProvider()

            # Sample zizmor v1.x+ finding
            finding = {
                "ident": "template-injection",
                "desc": "Template Injection Vulnerability",
                "determinations": {"severity": "high", "confidence": "High"},
                "url": "https://example.com/docs",
            }

            location = {
                "symbolic": {
                    "annotation": "High risk of code execution",
                    "key": {"Local": {"given_path": ".github/workflows/test.yml"}},
                },
                "concrete": {
                    "location": {
                        "start_point": {"row": 10, "column": 5},
                        "end_point": {"row": 10, "column": 15},
                    }
                },
            }

            report = provider._process_zizmor_finding(
                finding, ".github/workflows/test.yml", location
            )

            assert report.resource_name == ".github/workflows/test.yml"
            assert report.status == "FAIL"
            assert "line 10" in report.resource_line_range

            # Check metadata
            assert (
                report.check_metadata.CheckID == "githubactions_template_injection"
            )  # Prefixed with githubactions_
            assert report.check_metadata.Severity == "high"
            assert report.check_metadata.Provider == "github_actions"

    def test_run_scan_no_issues(self):
        """Test scanning when no issues are found"""
        with patch.object(GithubActionsProvider, "setup_session", return_value=None):
            provider = GithubActionsProvider()

            # Mock subprocess to return empty findings (zizmor v1.x+ format)
            mock_process = MagicMock()
            mock_process.stdout = "[]"
            mock_process.stderr = ""
            mock_process.returncode = 0

            with patch("subprocess.run", return_value=mock_process):
                with patch(
                    "prowler.providers.github_actions.github_actions_provider.alive_bar"
                ):
                    reports = provider.run_scan(".", [])

                    assert reports == []

    def test_run_scan_with_findings(self):
        """Test scanning with security findings"""
        with patch.object(GithubActionsProvider, "setup_session", return_value=None):
            provider = GithubActionsProvider()

            # Mock subprocess to return findings (zizmor v1.x+ format)
            mock_output = [
                {
                    "ident": "excessive-permissions",
                    "desc": "Workflow has write-all permissions",
                    "determinations": {"severity": "medium", "confidence": "High"},
                    "url": "https://docs.example.com",
                    "locations": [
                        {
                            "symbolic": {
                                "annotation": "Excessive permissions detected",
                                "key": {
                                    "Local": {"given_path": ".github/workflows/ci.yml"}
                                },
                            },
                            "concrete": {
                                "location": {
                                    "start_point": {"row": 5, "column": 1},
                                    "end_point": {"row": 5, "column": 20},
                                }
                            },
                        }
                    ],
                }
            ]

            mock_process = MagicMock()
            mock_process.stdout = json.dumps(mock_output)
            mock_process.stderr = ""
            mock_process.returncode = 0

            with patch("subprocess.run", return_value=mock_process):
                with patch(
                    "prowler.providers.github_actions.github_actions_provider.alive_bar"
                ):
                    reports = provider.run_scan(".", [])

                    assert len(reports) == 1
                    assert reports[0].resource_name == ".github/workflows/ci.yml"

    def test_run_scan_zizmor_not_found(self):
        """Test error handling when zizmor is not installed"""
        with patch.object(GithubActionsProvider, "setup_session", return_value=None):
            provider = GithubActionsProvider()

            with patch(
                "subprocess.run",
                side_effect=FileNotFoundError("No such file or directory: 'zizmor'"),
            ):
                with patch(
                    "prowler.providers.github_actions.github_actions_provider.alive_bar"
                ):
                    with pytest.raises(SystemExit):
                        provider.run_scan(".", [])

    def test_clone_repository_with_pat(self):
        """Test cloning repository with personal access token"""
        with patch.object(GithubActionsProvider, "setup_session", return_value=None):
            provider = GithubActionsProvider()

            with patch("tempfile.mkdtemp", return_value="/tmp/test"):
                with patch("dulwich.porcelain.clone"):
                    with patch(
                        "prowler.providers.github_actions.github_actions_provider.alive_bar"
                    ):
                        temp_dir = provider._clone_repository(
                            "https://github.com/test/repo",
                            github_username="user",
                            personal_access_token="token",
                        )

                        assert temp_dir == "/tmp/test"

    def test_print_credentials_local_scan(self):
        """Test printing credentials for local scan"""
        with patch.object(GithubActionsProvider, "setup_session", return_value=None):
            provider = GithubActionsProvider(workflow_path="/path/to/workflows")

            with patch(
                "prowler.providers.github_actions.github_actions_provider.print_boxes"
            ) as mock_print:
                provider.print_credentials()

                # Verify print_boxes was called with expected content
                mock_print.assert_called_once()
                args = mock_print.call_args[0]
                assert "/path/to/workflows" in str(args[0])

    def test_print_credentials_remote_scan(self):
        """Test printing credentials for remote repository scan"""
        with patch.object(GithubActionsProvider, "setup_session", return_value=None):
            provider = GithubActionsProvider(
                repository_url="https://github.com/test/repo",
                exclude_workflows=["test*.yml"],
            )

            with patch(
                "prowler.providers.github_actions.github_actions_provider.print_boxes"
            ) as mock_print:
                provider.print_credentials()

                # Verify print_boxes was called with expected content
                mock_print.assert_called_once()
                args = mock_print.call_args[0]
                assert "https://github.com/test/repo" in str(args[0])
                assert "test*.yml" in str(args[0])
