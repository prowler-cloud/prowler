from datetime import datetime, timezone
from unittest import mock

from prowler.providers.github.services.repository.repository_service import Branch, Repo
from tests.providers.github.github_fixtures import set_mocked_github_provider


class Test_repository_default_branch_status_checks_required_test:
    def test_no_repositories(self):
        repository_client = mock.MagicMock
        repository_client.repositories = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_default_branch_status_checks_required.repository_default_branch_status_checks_required.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_default_branch_status_checks_required.repository_default_branch_status_checks_required import (
                repository_default_branch_status_checks_required,
            )

            check = repository_default_branch_status_checks_required()
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
                status_checks=False,
                archived=False,
                pushed_at=datetime.now(timezone.utc),
                private=False,
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
                "prowler.providers.github.services.repository.repository_default_branch_status_checks_required.repository_default_branch_status_checks_required.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_default_branch_status_checks_required.repository_default_branch_status_checks_required import (
                repository_default_branch_status_checks_required,
            )

            check = repository_default_branch_status_checks_required()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == "repo1"
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Repository {repo_name} does not enforce status checks."
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
                default_branch=Branch(
                    name=default_branch,
                    protected=False,
                    default_branch=True,
                    require_pull_request=False,
                    approval_count=0,
                    required_linear_history=False,
                    allow_force_pushes=True,
                    branch_deletion=True,
                    status_checks=True,
                    enforce_admins=False,
                    require_code_owner_reviews=False,
                    require_signed_commits=False,
                    conversation_resolution=False,
                ),
                status_checks=True,
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
                "prowler.providers.github.services.repository.repository_default_branch_status_checks_required.repository_default_branch_status_checks_required.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_default_branch_status_checks_required.repository_default_branch_status_checks_required import (
                repository_default_branch_status_checks_required,
            )

            check = repository_default_branch_status_checks_required()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == "repo1"
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Repository {repo_name} does enforce status checks."
            )
