from unittest import mock

from prowler.providers.github.services.repository.repository_service import Repo
from tests.providers.github.github_fixtures import set_mocked_github_provider


class Test_repository_default_branch_requires_signed_commits:
    def test_no_repositories(self):
        repository_client = mock.MagicMock
        repository_client.repositories = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_default_branch_requires_signed_commits.repository_default_branch_requires_signed_commits.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_default_branch_requires_signed_commits.repository_default_branch_requires_signed_commits import (
                repository_default_branch_requires_signed_commits,
            )

            check = repository_default_branch_requires_signed_commits()
            result = check.execute()
            assert len(result) == 0

    def test_signed_commits_not_required(self):
        repository_client = mock.MagicMock
        repo_name = "repo1"
        default_branch = "main"
        repository_client.repositories = {
            1: Repo(
                id=1,
                name=repo_name,
                owner="account-name",
                full_name="account-name/repo1",
                private=False,
                default_branch=default_branch,
                require_signed_commits=False,
                securitymd=True,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_default_branch_requires_signed_commits.repository_default_branch_requires_signed_commits.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_default_branch_requires_signed_commits.repository_default_branch_requires_signed_commits import (
                repository_default_branch_requires_signed_commits,
            )

            check = repository_default_branch_requires_signed_commits()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == repo_name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Repository {repo_name} does not require signed commits on default branch ({default_branch})."
            )

    def test_signed_commits_required(self):
        repository_client = mock.MagicMock
        repo_name = "repo2"
        default_branch = "main"
        repository_client.repositories = {
            2: Repo(
                id=2,
                name=repo_name,
                owner="account-name",
                full_name="account-name/repo2",
                private=False,
                default_branch=default_branch,
                require_signed_commits=True,
                securitymd=True,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_default_branch_requires_signed_commits.repository_default_branch_requires_signed_commits.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_default_branch_requires_signed_commits.repository_default_branch_requires_signed_commits import (
                repository_default_branch_requires_signed_commits,
            )

            check = repository_default_branch_requires_signed_commits()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 2
            assert result[0].resource_name == repo_name
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Repository {repo_name} does require signed commits on default branch ({default_branch})."
            )
