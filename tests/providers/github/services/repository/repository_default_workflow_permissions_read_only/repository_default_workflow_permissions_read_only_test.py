from datetime import datetime, timezone
from unittest import mock

from prowler.providers.github.services.repository.repository_service import Branch, Repo
from tests.providers.github.github_fixtures import set_mocked_github_provider

CHECK_CLIENT_PATH = "prowler.providers.github.services.repository.repository_default_workflow_permissions_read_only.repository_default_workflow_permissions_read_only.repository_client"


class Test_repository_default_workflow_permissions_read_only:
    """Unit tests for the repository_default_workflow_permissions_read_only check."""

    def _build_repo(self, default_workflow_permissions):
        """Create a Repo instance with the provided default workflow permissions state."""
        default_branch = Branch(
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
        )
        return Repo(
            id=1,
            name="repo1",
            owner="account-name",
            full_name="account-name/repo1",
            default_workflow_permissions=default_workflow_permissions,
            default_branch=default_branch,
            private=False,
            archived=False,
            pushed_at=datetime.now(timezone.utc),
            securitymd=True,
            codeowners_exists=True,
            secret_scanning_enabled=True,
            dependabot_alerts_enabled=True,
            delete_branch_on_merge=False,
        )

    def _run_check(self, repositories):
        """Execute the check against the provided repositories."""
        repository_client = mock.MagicMock
        repository_client.repositories = repositories

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(CHECK_CLIENT_PATH, new=repository_client),
        ):
            from prowler.providers.github.services.repository.repository_default_workflow_permissions_read_only.repository_default_workflow_permissions_read_only import (
                repository_default_workflow_permissions_read_only,
            )

            check = repository_default_workflow_permissions_read_only()
            return check.execute()

    def test_no_repositories(self):
        """Test that no findings are reported when there are no repositories."""
        assert len(self._run_check({})) == 0

    def test_default_workflow_permissions_unknown(self):
        """Test that no finding is reported when the setting could not be read."""
        assert len(self._run_check({1: self._build_repo(None)})) == 0

    def test_default_workflow_permissions_read(self):
        """Test that a read-only default GITHUB_TOKEN passes the check."""
        result = self._run_check({1: self._build_repo("read")})

        assert len(result) == 1
        assert result[0].resource_id == 1
        assert result[0].resource_name == "repo1"
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "Repository repo1 grants workflows a read-only default GITHUB_TOKEN."
        )

    def test_default_workflow_permissions_write(self):
        """Test that a write-capable default GITHUB_TOKEN fails the check."""
        result = self._run_check({1: self._build_repo("write")})

        assert len(result) == 1
        assert result[0].resource_id == 1
        assert result[0].resource_name == "repo1"
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "Repository repo1 grants workflows a default GITHUB_TOKEN with write permissions."
        )
