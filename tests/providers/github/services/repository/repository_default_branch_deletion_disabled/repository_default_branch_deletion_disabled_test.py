from datetime import datetime, timezone
from unittest import mock

from prowler.providers.github.services.repository.repository_service import Branch, Repo
from tests.providers.github.github_fixtures import set_mocked_github_provider


class Test_repository_default_branch_deletion_disabled_test:
    def test_no_repositories(self):
        repository_client = mock.MagicMock
        repository_client.repositories = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_default_branch_deletion_disabled.repository_default_branch_deletion_disabled.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_default_branch_deletion_disabled.repository_default_branch_deletion_disabled import (
                repository_default_branch_deletion_disabled,
            )

            check = repository_default_branch_deletion_disabled()
            result = check.execute()
            assert len(result) == 0

    def test_allow_branch_deletion_enabled(self):
        repository_client = mock.MagicMock
        repo_name = "repo1"
        default_branch = Branch(
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
        )
        now = datetime.now(timezone.utc)

        repository_client.repositories = {
            1: Repo(
                id=1,
                name=repo_name,
                owner="account-name",
                full_name="account-name/repo1",
                default_branch=default_branch,
                private=False,
                archived=False,
                pushed_at=now,
                default_branch_deletion=True,
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
                "prowler.providers.github.services.repository.repository_default_branch_deletion_disabled.repository_default_branch_deletion_disabled.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_default_branch_deletion_disabled.repository_default_branch_deletion_disabled import (
                repository_default_branch_deletion_disabled,
            )

            check = repository_default_branch_deletion_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == repo_name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Repository {repo_name} does allow default branch deletion."
            )

    def test_allow_branch_deletion_disabled(self):
        repository_client = mock.MagicMock
        repo_name = "repo1"
        default_branch = Branch(
            name="main",
            protected=False,
            default_branch=True,
            require_pull_request=False,
            approval_count=0,
            required_linear_history=False,
            allow_force_pushes=True,
            branch_deletion=False,
            status_checks=False,
            enforce_admins=False,
            require_code_owner_reviews=False,
            require_signed_commits=False,
            conversation_resolution=False,
        )
        now = datetime.now(timezone.utc)

        repository_client.repositories = {
            1: Repo(
                id=1,
                name=repo_name,
                owner="account-name",
                full_name="account-name/repo1",
                default_branch=default_branch,
                private=False,
                archived=False,
                pushed_at=now,
                default_branch_deletion=False,
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
                "prowler.providers.github.services.repository.repository_default_branch_deletion_disabled.repository_default_branch_deletion_disabled.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_default_branch_deletion_disabled.repository_default_branch_deletion_disabled import (
                repository_default_branch_deletion_disabled,
            )

            check = repository_default_branch_deletion_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == repo_name
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Repository {repo_name} does deny default branch deletion."
            )
