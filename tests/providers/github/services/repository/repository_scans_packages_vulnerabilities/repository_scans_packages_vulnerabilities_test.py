from unittest import mock

from prowler.providers.github.services.repository.repository_service import Repo
from tests.providers.github.github_fixtures import set_mocked_github_provider


class Test_repository_scans_packages_vulnerabilities:
    def test_no_repositories(self):
        repository_client = mock.MagicMock
        repository_client.repositories = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_github_provider(),
        ), mock.patch(
            "prowler.providers.github.services.repository.repository_scans_packages_vulnerabilities.repository_scans_packages_vulnerabilities.repository_client",
            new=repository_client,
        ):
            from prowler.providers.github.services.repository.repository_scans_packages_vulnerabilities.repository_scans_packages_vulnerabilities import (
                repository_scans_packages_vulnerabilities,
            )

            check = repository_scans_packages_vulnerabilities()
            result = check.execute()
            assert len(result) == 0

    def test_one_repository_dependabot_disabled(self):
        repository_client = mock.MagicMock
        repo_name = "repo1"
        repository_client.repositories = {
            1: Repo(
                id=1,
                name=repo_name,
                full_name="account-name/repo1",
                default_branch="main",
                private=False,
                dependabot_enabled=False,
            ),
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_github_provider(),
        ), mock.patch(
            "prowler.providers.github.services.repository.repository_scans_packages_vulnerabilities.repository_scans_packages_vulnerabilities.repository_client",
            new=repository_client,
        ):
            from prowler.providers.github.services.repository.repository_scans_packages_vulnerabilities.repository_scans_packages_vulnerabilities import (
                repository_scans_packages_vulnerabilities,
            )

            check = repository_scans_packages_vulnerabilities()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == "repo1"
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Repository {repo_name} does not scan vulnerabilities in used packages."
            )

    def test_one_repository_dependabot_enabled(self):
        repository_client = mock.MagicMock
        repo_name = "repo1"
        repository_client.repositories = {
            1: Repo(
                id=1,
                name=repo_name,
                full_name="account-name/repo1",
                default_branch="main",
                private=False,
                dependabot_enabled=True,
            ),
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_github_provider(),
        ), mock.patch(
            "prowler.providers.github.services.repository.repository_scans_packages_vulnerabilities.repository_scans_packages_vulnerabilities.repository_client",
            new=repository_client,
        ):
            from prowler.providers.github.services.repository.repository_scans_packages_vulnerabilities.repository_scans_packages_vulnerabilities import (
                repository_scans_packages_vulnerabilities,
            )

            check = repository_scans_packages_vulnerabilities()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == "repo1"
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Repository {repo_name} does scan vulnerabilities in used packages."
            )
