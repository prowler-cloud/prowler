from unittest.mock import patch

from prowler.providers.github.services.repository.repository_service import (
    Protection,
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
            private=False,
            default_branch="main",
            default_branch_protection=Protection(
                require_pull_request=True,
                approval_count=2,
                linear_history=True,
                allow_force_push=False,
                allow_branch_deletion=False,
                enforce_status_checks=True,
                enforce_admins=True,
                conversation_resolution=True,
            ),
            securitymd=True,
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
        assert repository_service.repositories[1].default_branch == "main"
        # Default branch protection
        assert repository_service.repositories[
            1
        ].default_branch_protection.require_pull_request
        assert (
            repository_service.repositories[1].default_branch_protection.approval_count
            == 2
        )
        assert repository_service.repositories[
            1
        ].default_branch_protection.linear_history
        assert not repository_service.repositories[
            1
        ].default_branch_protection.allow_force_push
        assert not repository_service.repositories[
            1
        ].default_branch_protection.allow_branch_deletion
        assert repository_service.repositories[
            1
        ].default_branch_protection.enforce_status_checks
        assert repository_service.repositories[
            1
        ].default_branch_protection.enforce_admins
        assert repository_service.repositories[
            1
        ].default_branch_protection.conversation_resolution
        # Repo
        assert repository_service.repositories[1].securitymd
        assert repository_service.repositories[1].delete_branch_on_merge