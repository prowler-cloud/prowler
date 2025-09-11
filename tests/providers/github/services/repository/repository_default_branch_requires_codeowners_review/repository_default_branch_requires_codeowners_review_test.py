from datetime import datetime, timezone
from unittest import mock

from prowler.providers.github.services.repository.repository_service import Branch, Repo
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
        repository_client.repositories = {
            1: Repo(
                id=1,
                name=repo_name,
                owner="account-name",
                full_name="account-name/repo1",
                default_branch=Branch(
                    name="main",
                    protected=False,
                    default_branch=True,
                    require_pull_request=False,
                    approval_count=0,
                    required_linear_history=False,
                    allow_force_pushes=True,
                    branch_deletion=True,
                    status_checks=False,
                    enforce_admins=False,
                    require_code_owner_reviews=False,
                    require_signed_commits=False,
                    conversation_resolution=False,
                ),
                private=False,
                archived=False,
                pushed_at=datetime.now(timezone.utc),
                securitymd=True,
                codeowners_exists=False,
                secret_scanning_enabled=False,
                dependabot_alerts_enabled=False,
                delete_branch_on_merge=False,
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
                == f"Repository {repo_name} does not require code owner approval for changes to owned code."
            )

    def test_one_repository_with_codeowner_approval(self):
        repository_client = mock.MagicMock
        repo_name = "repo2"
        repository_client.repositories = {
            2: Repo(
                id=2,
                name=repo_name,
                owner="account-name",
                full_name="account-name/repo2",
                default_branch=Branch(
                    name="main",
                    protected=True,
                    default_branch=True,
                    require_pull_request=True,
                    approval_count=1,
                    required_linear_history=True,
                    allow_force_pushes=False,
                    branch_deletion=False,
                    status_checks=True,
                    enforce_admins=True,
                    require_code_owner_reviews=True,
                    require_signed_commits=True,
                    conversation_resolution=True,
                ),
                private=False,
                archived=False,
                pushed_at=datetime.now(timezone.utc),
                securitymd=True,
                codeowners_exists=True,
                secret_scanning_enabled=True,
                dependabot_alerts_enabled=True,
                delete_branch_on_merge=True,
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
                == f"Repository {repo_name} requires code owner approval for changes to owned code."
            )
