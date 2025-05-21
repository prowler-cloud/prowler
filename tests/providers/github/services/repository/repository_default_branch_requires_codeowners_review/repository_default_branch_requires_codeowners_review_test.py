from datetime import datetime, timezone
from unittest import mock

from prowler.providers.github.services.repository.repository_service import Repo
from tests.providers.github.github_fixtures import set_mocked_github_provider


class Test_repository_default_branch_requires_codeowners_review:
    def test_no_repositories(self):
        repository_client = mock.MagicMock
        repository_client.repositories = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_default_branch_requires_codeowners_review.repository_default_branch_requires_codeowners_review.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_default_branch_requires_codeowners_review.repository_default_branch_requires_codeowners_review import (
                repository_default_branch_requires_codeowners_review,
            )

            check = repository_default_branch_requires_codeowners_review()
            result = check.execute()
            assert len(result) == 0

    def test_one_repository_no_codeowner_approval(self):
        repository_client = mock.MagicMock
        repo_name = "repo1"
        repo_full_name = "account-name/repo1"
        repository_client.repositories = {
            1: Repo(
                id=1,
                name=repo_name,
                full_name=repo_full_name,
                default_branch="main",
                private=False,
                securitymd=True,
                require_pull_request=False,
                approval_count=0,
                require_code_owner_reviews=False,
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
                "prowler.providers.github.services.repository.repository_default_branch_requires_codeowners_review.repository_default_branch_requires_codeowners_review.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_default_branch_requires_codeowners_review.repository_default_branch_requires_codeowners_review import (
                repository_default_branch_requires_codeowners_review,
            )

            check = repository_default_branch_requires_codeowners_review()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == repo_name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Repository {repo_full_name} does not require code owner approval for changes to owned code."
            )

    def test_one_repository_with_codeowner_approval(self):
        repository_client = mock.MagicMock
        repo_name = "repo2"
        repo_full_name = "account-name/repo2"
        repository_client.repositories = {
            2: Repo(
                id=2,
                name=repo_name,
                full_name=repo_full_name,
                default_branch="main",
                private=False,
                securitymd=True,
                require_pull_request=False,
                approval_count=0,
                require_code_owner_reviews=True,
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
                "prowler.providers.github.services.repository.repository_default_branch_requires_codeowners_review.repository_default_branch_requires_codeowners_review.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_default_branch_requires_codeowners_review.repository_default_branch_requires_codeowners_review import (
                repository_default_branch_requires_codeowners_review,
            )

            check = repository_default_branch_requires_codeowners_review()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 2
            assert result[0].resource_name == repo_name
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Repository {repo_full_name} requires code owner approval for changes to owned code."
            )
