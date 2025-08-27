import json
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest

from prowler.providers.github_action.github_action_provider import GithubActionProvider


class TestGithubActionProvider:
    """Test cases for the GitHub Action Provider"""

    def test_github_action_provider_init_default(self):
        """Test provider initialization with default values"""
        with patch.object(GithubActionProvider, "setup_session", return_value=None):
            provider = GithubActionProvider()
            
            assert provider.type == "github_action"
            assert provider.workflow_path == "."
            assert provider.repository_url is None
            assert provider.exclude_workflows == []
            assert provider.auth_method == "No auth"
            assert provider.region == "global"
            assert provider.audited_account == "github-actions"

    def test_github_action_provider_init_with_repository_url(self):
        """Test provider initialization with repository URL"""
        with patch.object(GithubActionProvider, "setup_session", return_value=None):
            provider = GithubActionProvider(
                repository_url="https://github.com/test/repo",
                github_username="testuser",
                personal_access_token="token123"
            )
            
            assert provider.repository_url == "https://github.com/test/repo"
            assert provider.github_username == "testuser"
            assert provider.personal_access_token == "token123"
            assert provider.auth_method == "Personal Access Token"

    def test_github_action_provider_init_with_oauth_token(self):
        """Test provider initialization with OAuth token"""
        with patch.object(GithubActionProvider, "setup_session", return_value=None):
            provider = GithubActionProvider(
                repository_url="https://github.com/test/repo",
                oauth_app_token="oauth_token123"
            )
            
            assert provider.oauth_app_token == "oauth_token123"
            assert provider.auth_method == "OAuth App Token"
            assert provider.github_username is None
            assert provider.personal_access_token is None

    def test_process_finding(self):
        """Test processing a zizmor finding"""
        with patch.object(GithubActionProvider, "setup_session", return_value=None):
            provider = GithubActionProvider()
            
            # Sample zizmor finding
            finding = {
                "id": "template-injection",
                "title": "Template Injection Vulnerability",
                "level": "HIGH",
                "description": "Potential code injection in workflow",
                "documentation_url": "https://example.com/docs",
                "location": {
                    "line": 10,
                    "column": 5
                },
                "risk": "High risk of code execution",
                "remediation": "Use environment variables instead"
            }
            
            report = provider._process_finding(finding, ".github/workflows/test.yml")
            
            assert report.resource_name == ".github/workflows/test.yml"
            assert report.status == "FAIL"
            assert "line 10, column 5" in report.status_extended
            
            # Check metadata  
            assert report.check_metadata.CheckID == "githubaction_template_injection"  # Prefixed with githubaction_
            assert report.check_metadata.Severity == "high"
            assert report.check_metadata.Provider == "github_action"

    def test_run_scan_no_issues(self):
        """Test scanning when no issues are found"""
        with patch.object(GithubActionProvider, "setup_session", return_value=None):
            provider = GithubActionProvider()
            
            # Mock subprocess to return empty findings
            mock_process = MagicMock()
            mock_process.stdout = '{"findings": {}}'
            mock_process.stderr = ""
            mock_process.returncode = 0
            
            with patch("subprocess.run", return_value=mock_process):
                with patch("prowler.providers.github_action.github_action_provider.alive_bar"):
                    reports = provider.run_scan(".", [])
                    
                    assert reports == []

    def test_run_scan_with_findings(self):
        """Test scanning with security findings"""
        with patch.object(GithubActionProvider, "setup_session", return_value=None):
            provider = GithubActionProvider()
            
            # Mock subprocess to return findings
            mock_output = {
                "findings": {
                    ".github/workflows/ci.yml": [
                        {
                            "id": "excessive-permissions",
                            "title": "Excessive Permissions",
                            "level": "MEDIUM",
                            "description": "Workflow has write-all permissions",
                            "documentation_url": "https://docs.example.com",
                            "location": {"line": 5}
                        }
                    ]
                }
            }
            
            mock_process = MagicMock()
            mock_process.stdout = json.dumps(mock_output)
            mock_process.stderr = ""
            mock_process.returncode = 0
            
            with patch("subprocess.run", return_value=mock_process):
                with patch("prowler.providers.github_action.github_action_provider.alive_bar"):
                    reports = provider.run_scan(".", [])
                    
                    assert len(reports) == 1
                    assert reports[0].resource_name == ".github/workflows/ci.yml"

    def test_run_scan_zizmor_not_found(self):
        """Test error handling when zizmor is not installed"""
        with patch.object(GithubActionProvider, "setup_session", return_value=None):
            provider = GithubActionProvider()
            
            with patch("subprocess.run", side_effect=FileNotFoundError("No such file or directory: 'zizmor'")):
                with patch("prowler.providers.github_action.github_action_provider.alive_bar"):
                    with pytest.raises(SystemExit):
                        provider.run_scan(".", [])

    def test_clone_repository_with_pat(self):
        """Test cloning repository with personal access token"""
        with patch.object(GithubActionProvider, "setup_session", return_value=None):
            provider = GithubActionProvider()
            
            with patch("tempfile.mkdtemp", return_value="/tmp/test"):
                with patch("dulwich.porcelain.clone"):
                    with patch("prowler.providers.github_action.github_action_provider.alive_bar"):
                        temp_dir = provider._clone_repository(
                            "https://github.com/test/repo",
                            github_username="user",
                            personal_access_token="token"
                        )
                        
                        assert temp_dir == "/tmp/test"

    def test_print_credentials_local_scan(self):
        """Test printing credentials for local scan"""
        with patch.object(GithubActionProvider, "setup_session", return_value=None):
            provider = GithubActionProvider(workflow_path="/path/to/workflows")
            
            with patch("prowler.lib.utils.utils.print_boxes") as mock_print:
                provider.print_credentials()
                
                # Verify print_boxes was called with expected content
                mock_print.assert_called_once()
                args = mock_print.call_args[0]
                assert "/path/to/workflows" in str(args[0])

    def test_print_credentials_remote_scan(self):
        """Test printing credentials for remote repository scan"""
        with patch.object(GithubActionProvider, "setup_session", return_value=None):
            provider = GithubActionProvider(
                repository_url="https://github.com/test/repo",
                exclude_workflows=["test*.yml"]
            )
            
            with patch("prowler.lib.utils.utils.print_boxes") as mock_print:
                provider.print_credentials()
                
                # Verify print_boxes was called with expected content
                mock_print.assert_called_once()
                args = mock_print.call_args[0]
                assert "https://github.com/test/repo" in str(args[0])
                assert "test*.yml" in str(args[0])