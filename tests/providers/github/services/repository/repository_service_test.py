from unittest.mock import patch

from prowler.providers.github.services.repository.repository_service import (
    Repo,
    Repository,
)
from tests.providers.github.github_fixtures import set_mocked_github_provider


def mock_list_repositories(_):
    return {
        1: Repo(
            id=1,
            name="repo1",
            full_name="account-name/repo1",
            default_branch_protection=True,
            default_branch="main",
            private=False,
            securitymd=True,
            require_pull_request=True,
            required_linear_history=True,
            allow_force_pushes=True,
            approval_count=2,
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
        assert repository_service.repositories[1].default_branch == "main"
        assert repository_service.repositories[1].securitymd
        assert repository_service.repositories[1].required_linear_history
        assert repository_service.repositories[1].require_pull_request
        assert repository_service.repositories[1].allow_force_pushes
        assert repository_service.repositories[1].approval_count == 2
