from unittest import mock

from prowler.providers.github.services.repository.repository_service import Repo
from tests.providers.github.github_fixtures import set_mocked_github_provider


class Test_repository_branch_delete_on_merge_enabled_test:
    def test_no_repositories(self):
        repository_client = mock.MagicMock
        repository_client.repositories = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_branch_delete_on_merge_enabled.repository_branch_delete_on_merge_enabled.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_branch_delete_on_merge_enabled.repository_branch_delete_on_merge_enabled import (
                repository_branch_delete_on_merge_enabled,
            )

            check = repository_branch_delete_on_merge_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_branch_deletion_disabled(self):
        repository_client = mock.MagicMock
        repo_name = "repo1"
        repository_client.repositories = {
            1: Repo(
                id=1,
                name=repo_name,
                owner="account-name",
                full_name="account-name/repo1",
                default_branch="main",
                private=False,
                securitymd=False,
                delete_branch_on_merge=False,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_branch_delete_on_merge_enabled.repository_branch_delete_on_merge_enabled.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_branch_delete_on_merge_enabled.repository_branch_delete_on_merge_enabled import (
                repository_branch_delete_on_merge_enabled,
            )

            check = repository_branch_delete_on_merge_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == "repo1"
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Repository {repo_name} does not delete branches on merge."
            )

    def test_branch_deletion_enabled(self):
        repository_client = mock.MagicMock
        repo_name = "repo1"
        repository_client.repositories = {
            1: Repo(
                id=1,
                name=repo_name,
                owner="account-name",
                full_name="account-name/repo1",
                default_branch="main",
                private=False,
                securitymd=True,
                delete_branch_on_merge=True,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_branch_delete_on_merge_enabled.repository_branch_delete_on_merge_enabled.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_branch_delete_on_merge_enabled.repository_branch_delete_on_merge_enabled import (
                repository_branch_delete_on_merge_enabled,
            )

            check = repository_branch_delete_on_merge_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == "repo1"
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Repository {repo_name} does delete branches on merge."
            )
