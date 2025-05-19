from datetime import datetime, timezone
from unittest import mock

from prowler.providers.github.services.repository.repository_service import Repo
from tests.providers.github.github_fixtures import set_mocked_github_provider


class Test_repository_sensitive_data_scanner_enabled:
    def test_no_repositories(self):
        repository_client = mock.MagicMock
        repository_client.repositories = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_sensitive_data_scanner_enabled.repository_sensitive_data_scanner_enabled.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_sensitive_data_scanner_enabled.repository_sensitive_data_scanner_enabled import (
                repository_sensitive_data_scanner_enabled,
            )

            check = repository_sensitive_data_scanner_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_one_repository_no_secret_scanning(self):
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
                secret_scanning_enabled=False,
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
                "prowler.providers.github.services.repository.repository_sensitive_data_scanner_enabled.repository_sensitive_data_scanner_enabled.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_sensitive_data_scanner_enabled.repository_sensitive_data_scanner_enabled import (
                repository_sensitive_data_scanner_enabled,
            )

            check = repository_sensitive_data_scanner_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == repo_name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Repository {repo_name} does not have secret scanning enabled to detect sensitive data."
            )

    def test_one_repository_with_secret_scanning(self):
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
                secret_scanning_enabled=True,
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
                "prowler.providers.github.services.repository.repository_sensitive_data_scanner_enabled.repository_sensitive_data_scanner_enabled.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_sensitive_data_scanner_enabled.repository_sensitive_data_scanner_enabled import (
                repository_sensitive_data_scanner_enabled,
            )

            check = repository_sensitive_data_scanner_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 2
            assert result[0].resource_name == repo_name
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Repository {repo_name} has secret scanning enabled to detect sensitive data."
            )
