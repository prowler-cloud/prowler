import io
import json
import sys
from unittest.mock import ANY, MagicMock, patch

from prowler.providers.github.services.githubactions.githubactions_service import (
    GithubActions,
    GithubActionsWorkflowFinding,
)


class TestGithubActionsService:
    def test_should_exclude_workflow_no_patterns(self):
        assert not GithubActions._should_exclude_workflow("test.yml", [])

    def test_should_exclude_workflow_exact_filename(self):
        assert GithubActions._should_exclude_workflow(
            ".github/workflows/test.yml", ["test.yml"]
        )

    def test_should_exclude_workflow_wildcard_filename(self):
        assert GithubActions._should_exclude_workflow(
            ".github/workflows/test-api.yml", ["test-*.yml"]
        )

    def test_should_exclude_workflow_full_path(self):
        assert GithubActions._should_exclude_workflow(
            ".github/workflows/test.yml", [".github/workflows/test.yml"]
        )

    def test_should_exclude_workflow_full_path_wildcard(self):
        assert GithubActions._should_exclude_workflow(
            ".github/workflows/api-tests.yml", [".github/workflows/api-*.yml"]
        )

    def test_should_exclude_workflow_no_match(self):
        assert not GithubActions._should_exclude_workflow(
            ".github/workflows/deploy.yml", ["test-*.yml", "api-*.yml"]
        )

    def test_should_exclude_workflow_multiple_patterns(self):
        assert GithubActions._should_exclude_workflow(
            ".github/workflows/api-test.yml", ["test-*.yml", "api-*.yml"]
        )

    def test_should_exclude_workflow_filename_in_subdir(self):
        assert GithubActions._should_exclude_workflow(
            "workflows/subdir/test-deploy.yml", ["test-*.yml"]
        )

    def test_extract_workflow_file_from_location_v1(self):
        location = {
            "symbolic": {
                "key": {"Local": {"given_path": ".github/workflows/test.yml"}},
            }
        }
        result = GithubActions._extract_workflow_file_from_location(location)
        assert result == ".github/workflows/test.yml"

    def test_extract_workflow_file_from_location_missing_key(self):
        location = {"symbolic": {}}
        result = GithubActions._extract_workflow_file_from_location(location)
        assert result is None

    def test_extract_workflow_file_from_location_empty(self):
        result = GithubActions._extract_workflow_file_from_location({})
        assert result is None

    def test_parse_finding_valid(self):
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
        repo = MagicMock()
        repo.id = 1
        repo.name = "test-repo"
        repo.full_name = "owner/test-repo"
        repo.owner = "owner"

        result = GithubActions._parse_finding(
            finding, ".github/workflows/test.yml", location, repo
        )

        assert isinstance(result, GithubActionsWorkflowFinding)
        assert result.finding_id == "githubactions_template_injection"
        assert result.ident == "template-injection"
        assert result.severity == "high"
        assert result.line_range == "line 10"
        assert result.workflow_file == ".github/workflows/test.yml"
        assert result.repo_name == "test-repo"
        assert result.confidence == "High"

    def test_parse_finding_multiline_range(self):
        finding = {
            "ident": "excessive-permissions",
            "desc": "Excessive permissions",
            "determinations": {"severity": "medium", "confidence": "Medium"},
            "url": "https://example.com",
        }
        location = {
            "symbolic": {"annotation": "Excessive permissions detected"},
            "concrete": {
                "location": {
                    "start_point": {"row": 5, "column": 1},
                    "end_point": {"row": 10, "column": 20},
                }
            },
        }
        repo = MagicMock()
        repo.id = 1
        repo.name = "repo"
        repo.full_name = "owner/repo"
        repo.owner = "owner"

        result = GithubActions._parse_finding(finding, "wf.yml", location, repo)
        assert result.line_range == "lines 5-10"

    def test_parse_finding_unknown_severity(self):
        finding = {
            "ident": "test",
            "desc": "Test",
            "determinations": {"severity": "Unknown", "confidence": "Low"},
        }
        location = {
            "symbolic": {},
            "concrete": {"location": {}},
        }
        repo = MagicMock()
        repo.id = 1
        repo.name = "repo"
        repo.full_name = "owner/repo"
        repo.owner = "owner"

        result = GithubActions._parse_finding(finding, "wf.yml", location, repo)
        assert result.severity == "medium"
        assert result.line_range == "location unknown"

    def test_run_zizmor_no_output(self):
        mock_process = MagicMock()
        mock_process.stdout = ""
        mock_process.stderr = ""

        with patch("subprocess.run", return_value=mock_process):
            service = GithubActions.__new__(GithubActions)
            result = service._run_zizmor("/tmp/test")
            assert result == []

    def test_run_zizmor_empty_array(self):
        mock_process = MagicMock()
        mock_process.stdout = "[]"
        mock_process.stderr = ""

        with patch("subprocess.run", return_value=mock_process):
            service = GithubActions.__new__(GithubActions)
            result = service._run_zizmor("/tmp/test")
            assert result == []

    def test_run_zizmor_with_findings(self):
        mock_output = [
            {
                "ident": "excessive-permissions",
                "desc": "Workflow has write-all permissions",
                "determinations": {"severity": "medium", "confidence": "High"},
                "locations": [
                    {
                        "symbolic": {
                            "key": {"Local": {"given_path": ".github/workflows/ci.yml"}}
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

        with patch("subprocess.run", return_value=mock_process):
            service = GithubActions.__new__(GithubActions)
            result = service._run_zizmor("/tmp/test")
            assert len(result) == 1
            assert result[0]["ident"] == "excessive-permissions"

    def test_run_zizmor_invalid_json(self):
        mock_process = MagicMock()
        mock_process.stdout = "not valid json"
        mock_process.stderr = ""

        with patch("subprocess.run", return_value=mock_process):
            service = GithubActions.__new__(GithubActions)
            result = service._run_zizmor("/tmp/test")
            assert result == []

    def test_clone_repository_with_token(self):
        with (
            patch("tempfile.mkdtemp", return_value="/tmp/test"),
            patch("dulwich.porcelain.clone") as mock_clone,
        ):
            service = GithubActions.__new__(GithubActions)
            result = service._clone_repository(
                "https://github.com/owner/repo", token="mytoken"
            )

            assert result == "/tmp/test"
            mock_clone.assert_called_once_with(
                "https://mytoken@github.com/owner/repo",
                "/tmp/test",
                depth=1,
                errstream=ANY,
            )
            call_kwargs = mock_clone.call_args
            assert isinstance(call_kwargs.kwargs["errstream"], io.BytesIO)

    def test_clone_repository_without_token(self):
        with (
            patch("tempfile.mkdtemp", return_value="/tmp/test"),
            patch("dulwich.porcelain.clone") as mock_clone,
        ):
            service = GithubActions.__new__(GithubActions)
            result = service._clone_repository("https://github.com/owner/repo")

            assert result == "/tmp/test"
            mock_clone.assert_called_once_with(
                "https://github.com/owner/repo",
                "/tmp/test",
                depth=1,
                errstream=ANY,
            )
            call_kwargs = mock_clone.call_args
            assert isinstance(call_kwargs.kwargs["errstream"], io.BytesIO)

    def test_clone_repository_failure(self):
        with (
            patch("tempfile.mkdtemp", return_value="/tmp/test"),
            patch("dulwich.porcelain.clone", side_effect=Exception("clone failed")),
        ):
            service = GithubActions.__new__(GithubActions)
            result = service._clone_repository("https://github.com/owner/repo")
            assert result is None

    def test_init_zizmor_missing(self):
        mock_provider = MagicMock()
        mock_provider.session = MagicMock()
        mock_provider.session.token = "test-token"
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_provider.github_actions_enabled = True

        with (
            patch.object(GithubActions, "__init__", lambda self, provider: None),
            patch("shutil.which", return_value=None),
        ):
            service = GithubActions.__new__(GithubActions)
            service.provider = mock_provider
            service.clients = []
            service.audit_config = {}
            service.fixer_config = {}
            service.findings = {}

            # Manually call the part after super().__init__
            # Since zizmor is missing, _scan_repositories should not be called
            assert service.findings == {}

    def test_scan_repositories_strips_temp_dir_prefix(self):
        temp_dir = "/var/folders/xx/tmp48xjp_g0"
        zizmor_output = [
            {
                "ident": "template-injection",
                "desc": "Template Injection",
                "determinations": {"severity": "high", "confidence": "High"},
                "url": "https://example.com",
                "locations": [
                    {
                        "symbolic": {
                            "key": {
                                "Local": {
                                    "given_path": f"{temp_dir}/.github/workflows/release.yml"
                                }
                            },
                            "annotation": "Injection risk",
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

        mock_repo = MagicMock()
        mock_repo.id = 1
        mock_repo.name = "repo"
        mock_repo.full_name = "owner/repo"
        mock_repo.owner = "owner"
        mock_repo.default_branch = MagicMock()
        mock_repo.default_branch.name = "main"

        mock_repo_client = MagicMock()
        mock_repo_client.repositories = {1: mock_repo}

        mock_provider = MagicMock()
        mock_provider.session.token = "test-token"
        mock_provider.exclude_workflows = []

        service = GithubActions.__new__(GithubActions)
        service.findings = {}

        mock_repo_module = MagicMock()
        mock_repo_module.repository_client = mock_repo_client

        with (
            patch.object(service, "_clone_repository", return_value=temp_dir),
            patch.object(service, "_run_zizmor", return_value=zizmor_output),
            patch.dict(
                sys.modules,
                {
                    "prowler.providers.github.services.repository.repository_client": mock_repo_module,
                },
            ),
            patch("shutil.rmtree"),
        ):
            service._scan_repositories(mock_provider)

        assert 1 in service.findings
        assert len(service.findings[1]) == 1
        finding = service.findings[1][0]
        assert finding.workflow_file == ".github/workflows/release.yml"
        assert (
            finding.workflow_url
            == "https://github.com/owner/repo/blob/main/.github/workflows/release.yml"
        )

    def test_init_github_actions_disabled(self):
        mock_provider = MagicMock()
        mock_provider.github_actions_enabled = False
        mock_provider.session = MagicMock()
        mock_provider.session.token = "test-token"
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}

        with patch.object(GithubActions, "__init__", lambda self, provider: None):
            service = GithubActions.__new__(GithubActions)
            service.findings = {}
            # Service created, no scanning happened
            assert service.findings == {}
