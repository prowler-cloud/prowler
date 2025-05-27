from datetime import datetime, timedelta, timezone
from unittest import mock

from prowler.providers.github.services.repository.repository_service import Branch, Repo
from tests.providers.github.github_fixtures import set_mocked_github_provider


class Test_repository_inactive_not_archived:
    def test_no_repositories(self):
        repository_client = mock.MagicMock
        repository_client.repositories = {}
        repository_client.audit_config = {}

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
        default_branch = "main"
        now = datetime.now(timezone.utc)
        recent_activity = now - timedelta(days=30)  # 30 days ago

        repository_client.repositories = {
            1: Repo(
                id=1,
                name=repo_name,
                owner="account-name",
                full_name="account-name/test-repo",
                private=False,
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
                ),
                archived=False,
                pushed_at=recent_activity,
                securitymd=False,
                codeowners_exists=False,
                secret_scanning_enabled=False,
                dependabot_alerts_enabled=False,
                delete_branch_on_merge=False,
            ),
        }
        repository_client.audit_config = {}

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
                == f"Repository {repo_name} has been active within the last 180 days (30 days ago)."
            )

    def test_repository_inactive_not_archived(self):
        repository_client = mock.MagicMock
        repo_name = "test-repo"
        default_branch = "main"
        now = datetime.now(timezone.utc)
        old_activity = now - timedelta(days=200)  # 200 days ago

        repository_client.repositories = {
            1: Repo(
                id=1,
                name=repo_name,
                owner="account-name",
                full_name="account-name/test-repo",
                private=False,
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
                ),
                archived=False,
                pushed_at=old_activity,
                securitymd=False,
                codeowners_exists=False,
                secret_scanning_enabled=False,
                dependabot_alerts_enabled=False,
                delete_branch_on_merge=False,
            ),
        }
        repository_client.audit_config = {}

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
            assert "has been inactive for 200 days" in result[0].status_extended
            assert "and is not archived" in result[0].status_extended

    def test_repository_inactive_but_archived(self):
        repository_client = mock.MagicMock
        repo_name = "test-repo"
        default_branch = "main"
        now = datetime.now(timezone.utc)
        old_activity = now - timedelta(days=200)  # 200 days ago

        repository_client.repositories = {
            1: Repo(
                id=1,
                name=repo_name,
                owner="account-name",
                full_name="account-name/test-repo",
                private=False,
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
                ),
                archived=True,
                pushed_at=old_activity,
                securitymd=False,
                codeowners_exists=False,
                secret_scanning_enabled=False,
                dependabot_alerts_enabled=False,
                delete_branch_on_merge=False,
            ),
        }
        repository_client.audit_config = {}

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
                == f"Repository {repo_name} is properly archived."
            )

    def test_custom_days_threshold(self):
        repository_client = mock.MagicMock
        repo_name = "test-repo"
        default_branch = "main"
        now = datetime.now(timezone.utc)
        old_activity = now - timedelta(days=50)

        repository_client.repositories = {
            1: Repo(
                id=1,
                name=repo_name,
                owner="account-name",
                full_name="account-name/test-repo",
                private=False,
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
                ),
                archived=False,
                pushed_at=old_activity,
                securitymd=False,
                codeowners_exists=False,
                secret_scanning_enabled=False,
                dependabot_alerts_enabled=False,
                delete_branch_on_merge=False,
            ),
        }
        repository_client.audit_config = {"inactive_not_archived_days_threshold": 40}

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
            assert "has been inactive for 50 days" in result[0].status_extended
            assert "and is not archived" in result[0].status_extended
