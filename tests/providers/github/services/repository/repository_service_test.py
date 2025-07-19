from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

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
        self.mock_repo1.get_contents.return_value = None
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
        self.mock_repo2.get_contents.return_value = None
        self.mock_repo2.get_branch.side_effect = Exception("404 Not Found")
        self.mock_repo2.get_dependabot_alerts.side_effect = Exception("404 Not Found")

    def test_no_repository_scoping(self):
        """Test that all repositories are returned when no scoping is specified"""
        provider = set_mocked_github_provider()
        provider.repositories = []
        provider.organizations = []

        mock_client = MagicMock()
        mock_user = MagicMock()
        mock_user.get_repos.return_value = [self.mock_repo1, self.mock_repo2]
        mock_client.get_user.return_value = mock_user

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

    def test_specific_repository_scoping(self):
        """Test that only specified repositories are returned"""
        provider = set_mocked_github_provider()
        provider.repositories = ["owner1/repo1"]
        provider.organizations = []

        mock_client = MagicMock()
        mock_client.get_repo.return_value = self.mock_repo1

        with patch(
            "prowler.providers.github.services.repository.repository_service.GithubService.__init__"
        ):
            repository_service = Repository(provider)
            repository_service.clients = [mock_client]
            repository_service.provider = provider

            repos = repository_service._list_repositories()

            assert len(repos) == 1
            assert 1 in repos
            assert repos[1].name == "repo1"
            assert repos[1].full_name == "owner1/repo1"
            mock_client.get_repo.assert_called_once_with("owner1/repo1")

    def test_multiple_repository_scoping(self):
        """Test that multiple specified repositories are returned"""
        provider = set_mocked_github_provider()
        provider.repositories = ["owner1/repo1", "owner2/repo2"]
        provider.organizations = []

        mock_client = MagicMock()
        mock_client.get_repo.side_effect = [self.mock_repo1, self.mock_repo2]

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
            assert mock_client.get_repo.call_count == 2

    def test_invalid_repository_format(self):
        """Test that invalid repository formats are skipped with warning"""
        provider = set_mocked_github_provider()
        provider.repositories = ["invalid-repo-name", "owner/valid-repo"]
        provider.organizations = []

        mock_client = MagicMock()
        mock_client.get_repo.return_value = self.mock_repo1

        with patch(
            "prowler.providers.github.services.repository.repository_service.GithubService.__init__"
        ):
            repository_service = Repository(provider)
            repository_service.clients = [mock_client]
            repository_service.provider = provider

            with patch(
                "prowler.providers.github.services.repository.repository_service.logger"
            ) as mock_logger:
                repos = repository_service._list_repositories()

                # Should only have the valid repository
                assert len(repos) == 1
                assert 1 in repos
                # Should log warning for invalid format
                assert mock_logger.warning.call_count >= 1
                # Check that at least one warning is about invalid format
                warning_calls = [
                    call[0][0] for call in mock_logger.warning.call_args_list
                ]
                assert any(
                    "should be in 'owner/repo-name' format" in call
                    for call in warning_calls
                )

    def test_repository_not_found(self):
        """Test that inaccessible repositories are skipped with warning"""
        provider = set_mocked_github_provider()
        provider.repositories = ["owner/nonexistent-repo"]
        provider.organizations = []

        mock_client = MagicMock()
        mock_client.get_repo.side_effect = Exception("404 Not Found")

        with patch(
            "prowler.providers.github.services.repository.repository_service.GithubService.__init__"
        ):
            repository_service = Repository(provider)
            repository_service.clients = [mock_client]
            repository_service.provider = provider

            repos = repository_service._list_repositories()

            # Should be empty since repository wasn't found
            assert len(repos) == 0

    def test_organization_scoping(self):
        """Test that repositories from specified organizations are returned"""
        provider = set_mocked_github_provider()
        provider.repositories = []
        provider.organizations = ["org1"]

        mock_client = MagicMock()
        mock_org = MagicMock()
        mock_org.get_repos.return_value = [self.mock_repo1]
        mock_client.get_organization.return_value = mock_org

        with patch(
            "prowler.providers.github.services.repository.repository_service.GithubService.__init__"
        ):
            repository_service = Repository(provider)
            repository_service.clients = [mock_client]
            repository_service.provider = provider

            repos = repository_service._list_repositories()

            assert len(repos) == 1
            assert 1 in repos
            assert repos[1].name == "repo1"
            mock_client.get_organization.assert_called_once_with("org1")

    def test_organization_as_user_fallback(self):
        """Test that organization scoping falls back to user when organization not found"""
        provider = set_mocked_github_provider()
        provider.repositories = []
        provider.organizations = ["user1"]

        mock_client = MagicMock()
        # Organization lookup fails
        mock_client.get_organization.side_effect = GithubException(
            404, "Not Found", None
        )
        # User lookup succeeds
        mock_user = MagicMock()
        mock_user.get_repos.return_value = [self.mock_repo1]
        mock_client.get_user.return_value = mock_user

        # Create service without calling the parent constructor
        repository_service = Repository.__new__(Repository)
        repository_service.clients = [mock_client]
        repository_service.provider = provider

        with patch(
            "prowler.providers.github.services.repository.repository_service.logger"
        ) as mock_logger:
            repos = repository_service._list_repositories()

            assert len(repos) == 1
            assert 1 in repos
            assert repos[1].name == "repo1"
            mock_client.get_organization.assert_called_once_with("user1")
            mock_client.get_user.assert_called_once_with("user1")
            # Should log info about trying as user
            mock_logger.info.assert_called()

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

        # Security test - prevent injection
        assert self.repository._validate_repository_format("owner;rm -rf/repo") is False
        assert self.repository._validate_repository_format("owner$echo/repo") is False


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
                "prowler.providers.github.services.repository.repository_service.logger"
            ) as mock_logger:
                repos = repository_service._list_repositories()

                # Should be empty due to API error
                assert len(repos) == 0
                # Should log specific error message
                mock_logger.warning.assert_called()
                # Check if Access denied message was logged (could be in warning or error calls)
                log_messages = [
                    str(call)
                    for call in mock_logger.warning.call_args_list
                    + mock_logger.error.call_args_list
                ]
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
                "prowler.providers.github.services.repository.repository_service.logger"
            ) as mock_logger:
                # Rate limit errors should be caught and logged at the outer level
                repos = repository_service._list_repositories()

                # Should be empty due to rate limit error
                assert len(repos) == 0
                # Should log rate limit error
                mock_logger.error.assert_called()
                assert "Rate limit exceeded" in str(mock_logger.error.call_args)
