from datetime import datetime, timezone
from unittest import mock

from prowler.providers.github.services.repository.repository_service import (
    Branch,
    Repo,
    Ruleset,
)
from tests.providers.github.github_fixtures import set_mocked_github_provider


def make_repo(name, archived=False, rulesets=None, branch_protected=False):
    return Repo(
        id=1,
        name=name,
        owner="account-name",
        full_name=f"account-name/{name}",
        default_branch=Branch(
            name="main",
            protected=branch_protected,
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
        archived=archived,
        pushed_at=datetime.now(timezone.utc),
        securitymd=False,
        codeowners_exists=False,
        secret_scanning_enabled=False,
        dependabot_alerts_enabled=False,
        delete_branch_on_merge=False,
        rulesets=rulesets or [],
    )


class Test_repository_ruleset_dismisses_stale_reviews:
    def test_no_repositories(self):
        repository_client = mock.MagicMock
        repository_client.repositories = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_ruleset_dismisses_stale_reviews.repository_ruleset_dismisses_stale_reviews.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_ruleset_dismisses_stale_reviews.repository_ruleset_dismisses_stale_reviews import (
                repository_ruleset_dismisses_stale_reviews,
            )

            check = repository_ruleset_dismisses_stale_reviews()
            result = check.execute()
            assert len(result) == 0

    def test_archived_repository(self):
        repository_client = mock.MagicMock
        repo_name = "repo1"
        repository_client.repositories = {
            1: make_repo(repo_name, archived=True),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_ruleset_dismisses_stale_reviews.repository_ruleset_dismisses_stale_reviews.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_ruleset_dismisses_stale_reviews.repository_ruleset_dismisses_stale_reviews import (
                repository_ruleset_dismisses_stale_reviews,
            )

            check = repository_ruleset_dismisses_stale_reviews()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert result[0].resource_name == repo_name
            assert "archived" in result[0].status_extended

    def test_active_ruleset_with_dismiss_stale_reviews_pass(self):
        repository_client = mock.MagicMock
        repo_name = "repo1"
        ruleset = Ruleset(
            id=1,
            name="default-branch-ruleset",
            target="branch",
            enforcement="active",
            dismiss_stale_reviews_on_push=True,
            require_code_owner_review=False,
            required_approving_review_count=1,
            require_last_push_approval=False,
        )
        repository_client.repositories = {
            1: make_repo(repo_name, rulesets=[ruleset]),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_ruleset_dismisses_stale_reviews.repository_ruleset_dismisses_stale_reviews.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_ruleset_dismisses_stale_reviews.repository_ruleset_dismisses_stale_reviews import (
                repository_ruleset_dismisses_stale_reviews,
            )

            check = repository_ruleset_dismisses_stale_reviews()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_name == repo_name
            assert "default-branch-ruleset" in result[0].status_extended

    def test_active_ruleset_without_dismiss_stale_reviews_fail(self):
        repository_client = mock.MagicMock
        repo_name = "repo1"
        ruleset = Ruleset(
            id=1,
            name="default-branch-ruleset",
            target="branch",
            enforcement="active",
            dismiss_stale_reviews_on_push=False,
            require_code_owner_review=False,
            required_approving_review_count=1,
            require_last_push_approval=False,
        )
        repository_client.repositories = {
            1: make_repo(repo_name, rulesets=[ruleset]),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_ruleset_dismisses_stale_reviews.repository_ruleset_dismisses_stale_reviews.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_ruleset_dismisses_stale_reviews.repository_ruleset_dismisses_stale_reviews import (
                repository_ruleset_dismisses_stale_reviews,
            )

            check = repository_ruleset_dismisses_stale_reviews()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_name == repo_name
            assert "none enforce" in result[0].status_extended

    def test_no_ruleset_no_branch_protection_fail(self):
        repository_client = mock.MagicMock
        repo_name = "repo1"
        repository_client.repositories = {
            1: make_repo(repo_name, rulesets=[], branch_protected=False),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_ruleset_dismisses_stale_reviews.repository_ruleset_dismisses_stale_reviews.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_ruleset_dismisses_stale_reviews.repository_ruleset_dismisses_stale_reviews import (
                repository_ruleset_dismisses_stale_reviews,
            )

            check = repository_ruleset_dismisses_stale_reviews()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_name == repo_name
            assert "no branch protection" in result[0].status_extended

    def test_legacy_branch_protection_manual(self):
        repository_client = mock.MagicMock
        repo_name = "repo1"
        repository_client.repositories = {
            1: make_repo(repo_name, rulesets=[], branch_protected=True),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.repository.repository_ruleset_dismisses_stale_reviews.repository_ruleset_dismisses_stale_reviews.repository_client",
                new=repository_client,
            ),
        ):
            from prowler.providers.github.services.repository.repository_ruleset_dismisses_stale_reviews.repository_ruleset_dismisses_stale_reviews import (
                repository_ruleset_dismisses_stale_reviews,
            )

            check = repository_ruleset_dismisses_stale_reviews()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert result[0].resource_name == repo_name
            assert "legacy" in result[0].status_extended
