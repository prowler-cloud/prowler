from datetime import datetime, timezone
from unittest import mock

from prowler.providers.github.services.repository.repository_service import Branch, Repo
from tests.providers.github.github_fixtures import set_mocked_github_provider


class Test_repository_immutable_releases_enabled:
    """Unit tests for the repository_immutable_releases_enabled check."""

    def _build_repo(self, immutable_releases_enabled):
        """Create a Repo instance with the provided immutable releases state."""
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
            immutable_releases_enabled=immutable_releases_enabled,
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

    def test_no_repositories(self):
        repository_client = mock.MagicMock
        repository_client.repositories = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_immutable_releases_enabled.repository_immutable_releases_enabled.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_immutable_releases_enabled.repository_immutable_releases_enabled import (
                repository_immutable_releases_enabled,
            )

            check = repository_immutable_releases_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_immutable_releases_enabled(self):
        repository_client = mock.MagicMock
        repository_client.repositories = {1: self._build_repo(True)}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_immutable_releases_enabled.repository_immutable_releases_enabled.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_immutable_releases_enabled.repository_immutable_releases_enabled import (
                repository_immutable_releases_enabled,
            )

            check = repository_immutable_releases_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Repository repo1 has immutable releases enabled."
            )

    def test_immutable_releases_disabled(self):
        repository_client = mock.MagicMock
        repository_client.repositories = {1: self._build_repo(False)}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_immutable_releases_enabled.repository_immutable_releases_enabled.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_immutable_releases_enabled.repository_immutable_releases_enabled import (
                repository_immutable_releases_enabled,
            )

            check = repository_immutable_releases_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Repository repo1 does not have immutable releases enabled."
            )

    def test_immutable_releases_unknown(self):
        repository_client = mock.MagicMock
        repository_client.repositories = {1: self._build_repo(None)}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_immutable_releases_enabled.repository_immutable_releases_enabled.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_immutable_releases_enabled.repository_immutable_releases_enabled import (
                repository_immutable_releases_enabled,
            )

            check = repository_immutable_releases_enabled()
            result = check.execute()
            assert len(result) == 0
