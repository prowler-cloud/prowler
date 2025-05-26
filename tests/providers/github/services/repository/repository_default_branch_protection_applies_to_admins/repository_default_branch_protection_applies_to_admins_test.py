from datetime import datetime, timezone
from unittest import mock

from prowler.providers.github.services.repository.repository_service import Repo
from tests.providers.github.github_fixtures import set_mocked_github_provider


class Test_repository_default_branch_protection_applies_to_admins_test:
    def test_no_repositories(self):
        repository_client = mock.MagicMock
        repository_client.repositories = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_default_branch_protection_applies_to_admins.repository_default_branch_protection_applies_to_admins.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_default_branch_protection_applies_to_admins.repository_default_branch_protection_applies_to_admins import (
                repository_default_branch_protection_applies_to_admins,
            )

            check = repository_default_branch_protection_applies_to_admins()
            result = check.execute()
            assert len(result) == 0

    def test_enforce_status_checks_disabled(self):
        repository_client = mock.MagicMock
        repo_name = "repo1"
        default_branch = "main"
        repository_client.repositories = {
            1: Repo(
                id=1,
                name=repo_name,
                owner="account-name",
                full_name="account-name/repo1",
                default_branch=default_branch,
                private=False,
                securitymd=False,
                enforce_admins=False,
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
                "prowler.providers.github.services.repository.repository_default_branch_protection_applies_to_admins.repository_default_branch_protection_applies_to_admins.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_default_branch_protection_applies_to_admins.repository_default_branch_protection_applies_to_admins import (
                repository_default_branch_protection_applies_to_admins,
            )

            check = repository_default_branch_protection_applies_to_admins()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == "repo1"
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Repository {repo_name} does not enforce administrators to be subject to the same branch protection rules as other users."
            )

    def test_enforce_status_checks_enabled(self):
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
                enforce_admins=True,
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
                "prowler.providers.github.services.repository.repository_default_branch_protection_applies_to_admins.repository_default_branch_protection_applies_to_admins.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_default_branch_protection_applies_to_admins.repository_default_branch_protection_applies_to_admins import (
                repository_default_branch_protection_applies_to_admins,
            )

            check = repository_default_branch_protection_applies_to_admins()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == "repo1"
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Repository {repo_name} does enforce administrators to be subject to the same branch protection rules as other users."
            )
