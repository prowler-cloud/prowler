from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import requests
from github import GithubException, RateLimitExceededException

from prowler.providers.github.services.repository.repository_service import (
    Branch,
    Repo,
    Repository,
)
from tests.providers.github.github_fixtures import set_mocked_github_provider


def mock_list_repositories(_):
    return {
        1: Repo(
            id=1,
            name="repo1",
            owner="account-name",
            full_name="account-name/repo1",
            default_branch=Branch(
                name="main",
                protected=True,
                default_branch=True,
                require_pull_request=True,
                approval_count=2,
                required_linear_history=True,
                allow_force_pushes=True,
                branch_deletion=True,
                status_checks=True,
                enforce_admins=True,
                require_code_owner_reviews=True,
                require_signed_commits=True,
                conversation_resolution=True,
            ),
            private=False,
            securitymd=True,
            codeowners_exists=True,
            secret_scanning_enabled=True,
            archived=False,
            pushed_at=datetime.now(timezone.utc),
            delete_branch_on_merge=True,
            dependabot_alerts_enabled=True,
        ),
    }


@patch(
    "prowler.providers.github.services.repository.repository_service.Repository._list_repositories",
    new=mock_list_repositories,
)
class Test_Repository_Service:
    def test_get_client(self):
        repository_service = Repository(set_mocked_github_provider())
        assert repository_service.clients[0].__class__.__name__ == "Github"

    def test_get_service(self):
        repository_service = Repository(set_mocked_github_provider())
        assert repository_service.__class__.__name__ == "Repository"

    def test_list_repositories(self):
        repository_service = Repository(set_mocked_github_provider())
        assert len(repository_service.repositories) == 1
        assert repository_service.repositories[1].name == "repo1"
        assert repository_service.repositories[1].full_name == "account-name/repo1"
        assert repository_service.repositories[1].private is False
        assert repository_service.repositories[1].default_branch.name == "main"
        assert repository_service.repositories[1].securitymd
        assert repository_service.repositories[1].default_branch.required_linear_history
        assert repository_service.repositories[1].default_branch.require_pull_request
        assert repository_service.repositories[1].default_branch.allow_force_pushes
        assert repository_service.repositories[1].default_branch.branch_deletion
        assert repository_service.repositories[1].default_branch.status_checks
        assert repository_service.repositories[1].default_branch.enforce_admins
        assert repository_service.repositories[1].delete_branch_on_merge
        assert repository_service.repositories[1].default_branch.conversation_resolution
        assert repository_service.repositories[1].default_branch.approval_count == 2
        assert repository_service.repositories[1].codeowners_exists is True
        assert (
            repository_service.repositories[1].default_branch.require_code_owner_reviews
            is True
        )
        assert repository_service.repositories[1].secret_scanning_enabled is True
        assert (
            repository_service.repositories[1].default_branch.require_signed_commits
            is True
        )
        assert repository_service.repositories[1].archived is False
        assert repository_service.repositories[1].pushed_at is not None


class Test_Repository_FileExists:
    def setup_method(self):
        self.repository = Repository(set_mocked_github_provider())
        self.mock_repo = MagicMock()

    def test_file_exists_returns_true(self):
        self.mock_repo.get_contents.return_value = object()
        assert self.repository._file_exists(self.mock_repo, "somefile.txt") is True

    def test_file_not_found_returns_false(self):
        self.mock_repo.get_contents.side_effect = Exception("404 Not Found")
        assert self.repository._file_exists(self.mock_repo, "nofile.txt") is False

    def test_other_error_returns_none_and_logs(self):
        self.mock_repo.get_contents.side_effect = Exception("Some other error")
        with patch(
            "prowler.providers.github.services.repository.repository_service.logger"
        ) as mock_logger:
            assert self.repository._file_exists(self.mock_repo, "errorfile.txt") is None
            assert mock_logger.error.called


class Test_Repository_GraphQL:
    def setup_method(self):
        self.mock_repo1 = MagicMock()
        self.mock_repo1.id = 1
        self.mock_repo1.name = "repo1"
        self.mock_repo1.owner.login = "owner1"
        self.mock_repo1.full_name = "owner1/repo1"
        self.mock_repo1.default_branch = "main"
        self.mock_repo1.private = False
        self.mock_repo1.archived = False
        self.mock_repo1.pushed_at = datetime.now(timezone.utc)
        self.mock_repo1.delete_branch_on_merge = False
        self.mock_repo1.security_and_analysis = None
        self.mock_repo1.get_contents.side_effect = [None, None, None]
        self.mock_repo1.get_branch.side_effect = Exception("404 Not Found")
        self.mock_repo1.get_dependabot_alerts.side_effect = Exception("403 Forbidden")

    def test_no_scoping_uses_graphql(self):
        """Test that no scoping triggers the GraphQL discovery method successfully"""
        provider = set_mocked_github_provider()
        provider.repositories = []
        provider.organizations = []

        with patch.object(Repository, "__init__", lambda x, y: None):
            repository_service = Repository(provider)
            mock_client = MagicMock()
            repository_service.clients = [mock_client]
            repository_service.provider = provider

            with patch.object(
                repository_service,
                "_get_accessible_repos_graphql",
                return_value=["owner1/repo1"],
            ) as mock_graphql_call:
                mock_client.get_repo.return_value = self.mock_repo1

                repos = repository_service._list_repositories()

                assert len(repos) == 1
                assert 1 in repos
                assert repos[1].name == "repo1"

                mock_graphql_call.assert_called_once()
                mock_client.get_repo.assert_called_once_with("owner1/repo1")

    def test_graphql_call_api_error(self):
        """Test that an error during the GraphQL call is handled gracefully"""
        provider = set_mocked_github_provider()
        provider.repositories = []
        provider.organizations = []

        with patch.object(Repository, "__init__", lambda x, y: None):
            repository_service = Repository(provider)
            repository_service.clients = [MagicMock()]
            repository_service.provider = provider

            with patch(
                "requests.post",
                side_effect=requests.exceptions.RequestException("API Error"),
            ):
                with patch(
                    "prowler.providers.github.services.repository.repository_service.logger"
                ) as mock_logger:

                    repos = repository_service._list_repositories()

                    assert len(repos) == 0
                    mock_logger.error.assert_called_once()

                    log_output = str(mock_logger.error.call_args)
                    assert "RequestException" in log_output
                    assert "API Error" in log_output

    def test_graphql_returns_empty_list(self):
        """Test the case where GraphQL returns no repositories"""
        provider = set_mocked_github_provider()
        provider.repositories = []
        provider.organizations = []

        with patch.object(Repository, "__init__", lambda x, y: None):
            repository_service = Repository(provider)
            repository_service.clients = [MagicMock()]
            repository_service.provider = provider

            with patch.object(
                repository_service, "_get_accessible_repos_graphql", return_value=[]
            ):
                with patch(
                    "prowler.providers.github.services.repository.repository_service.logger"
                ) as mock_logger:

                    repos = repository_service._list_repositories()

                    assert len(repos) == 0
                    mock_logger.warning.assert_called_with(
                        "Could not find any accessible repositories with the provided token."
                    )


class Test_Repository_Scoping:
    def setup_method(self):
        self.mock_repo1 = MagicMock()
        self.mock_repo1.id = 1
        self.mock_repo1.name = "repo1"
        self.mock_repo1.owner.login = "owner1"
        self.mock_repo1.full_name = "owner1/repo1"
        self.mock_repo1.default_branch = "main"
        self.mock_repo1.private = False
        self.mock_repo1.archived = False
        self.mock_repo1.pushed_at = datetime.now(timezone.utc)
        self.mock_repo1.delete_branch_on_merge = True
        self.mock_repo1.security_and_analysis = None
        self.mock_repo1.get_contents.side_effect = [None, None, None]
        self.mock_repo1.get_branch.side_effect = Exception("404 Not Found")
        self.mock_repo1.get_dependabot_alerts.side_effect = Exception("404 Not Found")

        self.mock_repo2 = MagicMock()
        self.mock_repo2.id = 2
        self.mock_repo2.name = "repo2"
        self.mock_repo2.owner.login = "owner2"
        self.mock_repo2.full_name = "owner2/repo2"
        self.mock_repo2.default_branch = "main"
        self.mock_repo2.private = False
        self.mock_repo2.archived = False
        self.mock_repo2.pushed_at = datetime.now(timezone.utc)
        self.mock_repo2.delete_branch_on_merge = True
        self.mock_repo2.security_and_analysis = None
        self.mock_repo2.get_contents.side_effect = [None, None, None]
        self.mock_repo2.get_branch.side_effect = Exception("404 Not Found")
        self.mock_repo2.get_dependabot_alerts.side_effect = Exception("404 Not Found")

    def test_combined_repository_and_organization_scoping(self):
        """Test that both repository and organization scoping can be used together"""
        provider = set_mocked_github_provider()
        provider.repositories = ["owner1/repo1"]
        provider.organizations = ["org2"]

        mock_client = MagicMock()
        # Repository lookup
        mock_client.get_repo.return_value = self.mock_repo1
        # Organization lookup
        mock_org = MagicMock()
        mock_org.get_repos.return_value = [self.mock_repo2]
        mock_client.get_organization.return_value = mock_org

        with patch(
            "prowler.providers.github.services.repository.repository_service.GithubService.__init__"
        ):
            repository_service = Repository(provider)
            repository_service.clients = [mock_client]
            repository_service.provider = provider

            repos = repository_service._list_repositories()

            assert len(repos) == 2
            assert 1 in repos
            assert 2 in repos
            assert repos[1].name == "repo1"
            assert repos[2].name == "repo2"
            mock_client.get_repo.assert_called_once_with("owner1/repo1")
            mock_client.get_organization.assert_called_once_with("org2")


class Test_Repository_Validation:
    def setup_method(self):
        self.repository = Repository(set_mocked_github_provider())

    def test_validate_repository_format_valid(self):
        """Test repository format validation with valid formats"""
        # Valid formats
        assert self.repository._validate_repository_format("owner/repo") is True
        assert self.repository._validate_repository_format("my-org/my-repo") is True
        assert (
            self.repository._validate_repository_format("user123/project_name") is True
        )
        assert self.repository._validate_repository_format("org/repo.name") is True

    def test_validate_repository_format_invalid(self):
        """Test repository format validation with invalid formats"""
        # Invalid formats
        assert self.repository._validate_repository_format("") is False
        assert self.repository._validate_repository_format("no-slash") is False
        assert self.repository._validate_repository_format("too/many/slashes") is False
        assert self.repository._validate_repository_format("/missing-owner") is False
        assert self.repository._validate_repository_format("missing-repo/") is False


class Test_Repository_ErrorHandling:
    def setup_method(self):
        self.mock_repo1 = MagicMock()
        self.mock_repo1.id = 1
        self.mock_repo1.name = "repo1"
        self.mock_repo1.owner.login = "owner1"
        self.mock_repo1.full_name = "owner1/repo1"
        self.mock_repo1.default_branch = "main"
        self.mock_repo1.private = False
        self.mock_repo1.archived = False
        self.mock_repo1.pushed_at = datetime.now(timezone.utc)
        self.mock_repo1.delete_branch_on_merge = True
        self.mock_repo1.security_and_analysis = None
        self.mock_repo1.get_contents.return_value = None
        self.mock_repo1.get_branch.side_effect = Exception("404 Not Found")
        self.mock_repo1.get_dependabot_alerts.side_effect = Exception("404 Not Found")

    def test_github_api_error_handling(self):
        """Test that GitHub API errors are handled properly"""
        provider = set_mocked_github_provider()
        provider.repositories = ["owner/repo1"]
        provider.organizations = []

        mock_client = MagicMock()
        mock_client.get_repo.side_effect = GithubException(403, "Forbidden", None)

        with patch(
            "prowler.providers.github.services.repository.repository_service.GithubService.__init__"
        ):
            repository_service = Repository(provider)
            repository_service.clients = [mock_client]
            repository_service.provider = provider

            with patch(
                "prowler.providers.github.lib.service.service.logger"
            ) as mock_logger:
                repos = repository_service._list_repositories()

                # Should be empty due to API error
                assert len(repos) == 0
                # Should log specific error message
                mock_logger.error.assert_called()
                # Check if Access denied message was logged
                log_messages = [str(call) for call in mock_logger.error.call_args_list]
                assert any("Access denied" in msg for msg in log_messages)

    def test_rate_limit_error_handling(self):
        """Test that rate limit errors are logged appropriately"""
        provider = set_mocked_github_provider()
        provider.repositories = ["owner/repo1"]
        provider.organizations = []

        mock_client = MagicMock()
        mock_client.get_repo.side_effect = RateLimitExceededException(
            429, "Rate limit exceeded", None
        )

        with patch(
            "prowler.providers.github.services.repository.repository_service.GithubService.__init__"
        ):
            repository_service = Repository(provider)
            repository_service.clients = [mock_client]
            repository_service.provider = provider

            with patch(
                "prowler.providers.github.lib.service.service.logger"
            ) as mock_logger:
                # Rate limit errors should be caught and logged at the outer level
                repos = repository_service._list_repositories()

                # Should be empty due to rate limit error
                assert len(repos) == 0
                # Should log rate limit error
                mock_logger.error.assert_called()
                assert "Rate limit exceeded" in str(mock_logger.error.call_args)
