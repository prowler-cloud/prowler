from datetime import datetime, timezone
from unittest import mock

from prowler.providers.github.services.repository.repository_service import Branch, Repo
from tests.providers.github.github_fixtures import set_mocked_github_provider


class Test_repository_default_branch_dismiss_stale_reviews_enabled:
    def test_no_repositories(self):
        repository_client = mock.MagicMock
        repository_client.repositories = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_default_branch_dismiss_stale_reviews_enabled.repository_default_branch_dismiss_stale_reviews_enabled.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_default_branch_dismiss_stale_reviews_enabled.repository_default_branch_dismiss_stale_reviews_enabled import (
                repository_default_branch_dismiss_stale_reviews_enabled,
            )

            check = repository_default_branch_dismiss_stale_reviews_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_dismiss_stale_reviews_disabled(self):
        repository_client = mock.MagicMock
        repo_name = "repo1"
        default_branch = "main"
        repository_client.repositories = {
            1: Repo(
                id=1,
                name=repo_name,
                owner="account-name",
                full_name="account-name/repo1",
                default_branch=Branch(
                    name=default_branch,
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
                    dismiss_stale_reviews=False,
                ),
                private=False,
                archived=False,
                pushed_at=datetime.now(timezone.utc),
                securitymd=False,
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
                "prowler.providers.github.services.repository.repository_default_branch_dismiss_stale_reviews_enabled.repository_default_branch_dismiss_stale_reviews_enabled.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_default_branch_dismiss_stale_reviews_enabled.repository_default_branch_dismiss_stale_reviews_enabled import (
                repository_default_branch_dismiss_stale_reviews_enabled,
            )

            check = repository_default_branch_dismiss_stale_reviews_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == "repo1"
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Repository {repo_name} does not dismiss stale pull request approvals when new commits are pushed on default branch ({default_branch})."
            )

    def test_dismiss_stale_reviews_enabled(self):
        repository_client = mock.MagicMock
        repo_name = "repo1"
        default_branch = "main"
        repository_client.repositories = {
            1: Repo(
                id=1,
                name=repo_name,
                owner="account-name",
                full_name="account-name/repo1",
                default_branch=Branch(
                    name=default_branch,
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
                    dismiss_stale_reviews=True,
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
                "prowler.providers.github.services.repository.repository_default_branch_dismiss_stale_reviews_enabled.repository_default_branch_dismiss_stale_reviews_enabled.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_default_branch_dismiss_stale_reviews_enabled.repository_default_branch_dismiss_stale_reviews_enabled import (
                repository_default_branch_dismiss_stale_reviews_enabled,
            )

            check = repository_default_branch_dismiss_stale_reviews_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == "repo1"
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Repository {repo_name} does dismiss stale pull request approvals when new commits are pushed on default branch ({default_branch})."
            )

    def test_dismiss_stale_reviews_none(self):
        repository_client = mock.MagicMock
        repository_client.repositories = {
            1: Repo(
                id=1,
                name="repo1",
                owner="account-name",
                full_name="account-name/repo1",
                default_branch=Branch(
                    name="main",
                    protected=None,
                    default_branch=True,
                    require_pull_request=None,
                    approval_count=None,
                    required_linear_history=None,
                    allow_force_pushes=None,
                    branch_deletion=None,
                    status_checks=None,
                    enforce_admins=None,
                    require_code_owner_reviews=None,
                    require_signed_commits=None,
                    conversation_resolution=None,
                    dismiss_stale_reviews=None,
                ),
                private=False,
                archived=False,
                pushed_at=datetime.now(timezone.utc),
                securitymd=False,
                codeowners_exists=False,
                secret_scanning_enabled=None,
                dependabot_alerts_enabled=None,
                delete_branch_on_merge=False,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_default_branch_dismiss_stale_reviews_enabled.repository_default_branch_dismiss_stale_reviews_enabled.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_default_branch_dismiss_stale_reviews_enabled.repository_default_branch_dismiss_stale_reviews_enabled import (
                repository_default_branch_dismiss_stale_reviews_enabled,
            )

            check = repository_default_branch_dismiss_stale_reviews_enabled()
            result = check.execute()
            assert len(result) == 0
