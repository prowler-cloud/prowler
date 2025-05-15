from unittest import mock

from prowler.providers.github.services.repository.repository_service import Repo
from tests.providers.github.github_fixtures import set_mocked_github_provider


class Test_repository_has_codeowners_file:
    def test_no_repositories(self):
        repository_client = mock.MagicMock
        repository_client.repositories = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_has_codeowners_file.repository_has_codeowners_file.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_has_codeowners_file.repository_has_codeowners_file import (
                repository_has_codeowners_file,
            )

            check = repository_has_codeowners_file()
            result = check.execute()
            assert len(result) == 0

    def test_one_repository_no_codeowners(self):
        repository_client = mock.MagicMock
        repo_name = "repo1"
        repository_client.repositories = {
            1: Repo(
                id=1,
                name=repo_name,
                full_name="account-name/repo1",
                default_branch="main",
                private=False,
                securitymd=True,
                require_pull_request=False,
                approval_count=0,
                codeowners_exists=False,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_has_codeowners_file.repository_has_codeowners_file.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_has_codeowners_file.repository_has_codeowners_file import (
                repository_has_codeowners_file,
            )

            check = repository_has_codeowners_file()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == repo_name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Repository {repo_name} does not have a CODEOWNERS file."
            )

    def test_one_repository_with_codeowners(self):
        repository_client = mock.MagicMock
        repo_name = "repo2"
        repository_client.repositories = {
            2: Repo(
                id=2,
                name=repo_name,
                full_name="account-name/repo2",
                default_branch="main",
                private=False,
                securitymd=True,
                require_pull_request=False,
                approval_count=0,
                codeowners_exists=True,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_has_codeowners_file.repository_has_codeowners_file.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_has_codeowners_file.repository_has_codeowners_file import (
                repository_has_codeowners_file,
            )

            check = repository_has_codeowners_file()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 2
            assert result[0].resource_name == repo_name
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Repository {repo_name} does have a CODEOWNERS file."
            )
