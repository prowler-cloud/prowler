from unittest import mock

from prowler.providers.github.services.repository.repository_service import Repo
from tests.providers.github.github_fixtures import set_mocked_github_provider


class Test_repository_code_changes_multi_approval_requirement:
    def test_no_repositories(self):
        repository_client = mock.MagicMock
        repository_client.repositories = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_code_changes_multi_approval_requirement.repository_code_changes_multi_approval_requirement.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_code_changes_multi_approval_requirement.repository_code_changes_multi_approval_requirement import (
                repository_code_changes_multi_approval_requirement,
            )

            check = repository_code_changes_multi_approval_requirement()
            result = check.execute()
            assert len(result) == 0

    def test_repository_no_require_pull_request(self):
        repository_client = mock.MagicMock
        repo_name = "repo1"
        repository_client.repositories = {
            1: Repo(
                id=1,
                name=repo_name,
                full_name="account-name/repo1",
                default_branch="main",
                private=False,
                securitymd=False,
                require_pull_request=False,
                approval_count=0,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_code_changes_multi_approval_requirement.repository_code_changes_multi_approval_requirement.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_code_changes_multi_approval_requirement.repository_code_changes_multi_approval_requirement import (
                repository_code_changes_multi_approval_requirement,
            )

            check = repository_code_changes_multi_approval_requirement()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == "repo1"
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Repository {repo_name} does not enforce at least 2 approvals for code changes."
            )

    def test_repository_no_approvals(self):
        repository_client = mock.MagicMock
        repo_name = "repo1"
        repository_client.repositories = {
            1: Repo(
                id=1,
                name=repo_name,
                full_name="account-name/repo1",
                default_branch="master",
                private=False,
                securitymd=False,
                require_pull_request=True,
                approval_count=0,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_code_changes_multi_approval_requirement.repository_code_changes_multi_approval_requirement.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_code_changes_multi_approval_requirement.repository_code_changes_multi_approval_requirement import (
                repository_code_changes_multi_approval_requirement,
            )

            check = repository_code_changes_multi_approval_requirement()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == "repo1"
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Repository {repo_name} does not enforce at least 2 approvals for code changes."
            )

    def test_repository_two_approvals(self):
        repository_client = mock.MagicMock
        repo_name = "repo1"
        repository_client.repositories = {
            1: Repo(
                id=1,
                name=repo_name,
                full_name="account-name/repo1",
                default_branch="master",
                private=False,
                securitymd=True,
                require_pull_request=True,
                approval_count=2,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_code_changes_multi_approval_requirement.repository_code_changes_multi_approval_requirement.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_code_changes_multi_approval_requirement.repository_code_changes_multi_approval_requirement import (
                repository_code_changes_multi_approval_requirement,
            )

            check = repository_code_changes_multi_approval_requirement()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == "repo1"
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Repository {repo_name} does enforce at least 2 approvals for code changes."
            )
