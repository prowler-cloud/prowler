from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

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
