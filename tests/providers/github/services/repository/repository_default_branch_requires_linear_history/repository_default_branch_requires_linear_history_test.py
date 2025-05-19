from datetime import datetime, timezone
from unittest import mock

from prowler.providers.github.services.repository.repository_service import Repo
from tests.providers.github.github_fixtures import set_mocked_github_provider


class Test_repository_default_branch_requires_linear_history_test:
    def test_no_repositories(self):
        repository_client = mock.MagicMock
        repository_client.repositories = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_default_branch_requires_linear_history.repository_default_branch_requires_linear_history.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_default_branch_requires_linear_history.repository_default_branch_requires_linear_history import (
                repository_default_branch_requires_linear_history,
            )

            check = repository_default_branch_requires_linear_history()
            result = check.execute()
            assert len(result) == 0

    def test_linear_history_disabled(self):
        repository_client = mock.MagicMock
        repo_name = "repo1"
        repo_full_name = "account-name/repo1"
        default_branch = "main"
        repository_client.repositories = {
            1: Repo(
                id=1,
                name=repo_name,
                full_name=repo_full_name,
                default_branch=default_branch,
                required_linear_history=False,
                private=False,
                securitymd=False,
                archived=False,
                pushed_at=datetime.now(timezone.utc),
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_default_branch_requires_linear_history.repository_default_branch_requires_linear_history.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_default_branch_requires_linear_history.repository_default_branch_requires_linear_history import (
                repository_default_branch_requires_linear_history,
            )

            check = repository_default_branch_requires_linear_history()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == repo_name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Repository {repo_full_name} does not require linear history on default branch ({default_branch})."
            )

    def test_linear_history_enabled(self):
        repository_client = mock.MagicMock
        repo_name = "repo1"
        repo_full_name = "account-name/repo1"
        default_branch = "main"
        repository_client.repositories = {
            1: Repo(
                id=1,
                name=repo_name,
                full_name=repo_full_name,
                private=False,
                default_branch=default_branch,
                required_linear_history=True,
                securitymd=True,
                archived=False,
                pushed_at=datetime.now(timezone.utc),
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_default_branch_requires_linear_history.repository_default_branch_requires_linear_history.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_default_branch_requires_linear_history.repository_default_branch_requires_linear_history import (
                repository_default_branch_requires_linear_history,
            )

            check = repository_default_branch_requires_linear_history()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == repo_name
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Repository {repo_full_name} does require linear history on default branch ({default_branch})."
            )
