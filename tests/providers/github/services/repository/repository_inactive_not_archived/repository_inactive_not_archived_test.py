from datetime import datetime, timedelta, timezone
from unittest import mock

from prowler.providers.github.services.repository.repository_service import Repo
from tests.providers.github.github_fixtures import set_mocked_github_provider


class Test_repository_inactive_not_archived:
    def test_no_repositories(self):
        repository_client = mock.MagicMock
        repository_client.repositories = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_inactive_not_archived.repository_inactive_not_archived.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_inactive_not_archived.repository_inactive_not_archived import (
                repository_inactive_not_archived,
            )

            check = repository_inactive_not_archived()
            result = check.execute()
            assert len(result) == 0

    def test_repository_active_not_archived(self):
        repository_client = mock.MagicMock
        repo_name = "test-repo"
        repo_full_name = "account-name/test-repo"
        default_branch = "main"
        now = datetime.now(timezone.utc)
        recent_activity = now - timedelta(days=30)  # 1 month ago

        repository_client.repositories = {
            1: Repo(
                id=1,
                name=repo_name,
                full_name=repo_full_name,
                private=False,
                default_branch=default_branch,
                archived=False,
                pushed_at=recent_activity,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_inactive_not_archived.repository_inactive_not_archived.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_inactive_not_archived.repository_inactive_not_archived import (
                repository_inactive_not_archived,
            )

            check = repository_inactive_not_archived()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == repo_name
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Repository {repo_full_name} has been active within the last 6 months."
            )

    def test_repository_inactive_not_archived(self):
        repository_client = mock.MagicMock
        repo_name = "test-repo"
        repo_full_name = "account-name/test-repo"
        default_branch = "main"
        now = datetime.now(timezone.utc)
        old_activity = now - timedelta(days=200)  # ~6.5 months ago

        repository_client.repositories = {
            1: Repo(
                id=1,
                name=repo_name,
                full_name=repo_full_name,
                private=False,
                default_branch=default_branch,
                archived=False,
                pushed_at=old_activity,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_inactive_not_archived.repository_inactive_not_archived.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_inactive_not_archived.repository_inactive_not_archived import (
                repository_inactive_not_archived,
            )

            check = repository_inactive_not_archived()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == repo_name
            assert result[0].status == "FAIL"
            assert "has been inactive for" in result[0].status_extended
            assert "and is not archived" in result[0].status_extended

    def test_repository_inactive_but_archived(self):
        repository_client = mock.MagicMock
        repo_name = "test-repo"
        repo_full_name = "account-name/test-repo"
        default_branch = "main"
        now = datetime.now(timezone.utc)
        old_activity = now - timedelta(days=200)  # ~6.5 months ago

        repository_client.repositories = {
            1: Repo(
                id=1,
                name=repo_name,
                full_name=repo_full_name,
                default_branch=default_branch,
                private=False,
                archived=True,
                pushed_at=old_activity,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_inactive_not_archived.repository_inactive_not_archived.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_inactive_not_archived.repository_inactive_not_archived import (
                repository_inactive_not_archived,
            )

            check = repository_inactive_not_archived()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == repo_name
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Repository {repo_full_name} is properly archived."
            )
