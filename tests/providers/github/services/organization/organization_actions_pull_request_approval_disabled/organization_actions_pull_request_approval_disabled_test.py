from unittest import mock

from prowler.providers.github.services.organization.organization_service import Org
from tests.providers.github.github_fixtures import set_mocked_github_provider

CHECK_CLIENT_PATH = "prowler.providers.github.services.organization.organization_actions_pull_request_approval_disabled.organization_actions_pull_request_approval_disabled.organization_client"


class Test_organization_actions_pull_request_approval_disabled:
    """Unit tests for the organization_actions_pull_request_approval_disabled check."""

    def _run_check(self, organizations):
        """Execute the check against the provided organizations."""
        organization_client = mock.MagicMock
        organization_client.organizations = organizations

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(CHECK_CLIENT_PATH, new=organization_client),
        ):
            from prowler.providers.github.services.organization.organization_actions_pull_request_approval_disabled.organization_actions_pull_request_approval_disabled import (
                organization_actions_pull_request_approval_disabled,
            )

            check = organization_actions_pull_request_approval_disabled()
            return check.execute()

    def test_no_organizations(self):
        """Test that no findings are reported when there are no organizations."""
        assert len(self._run_check({})) == 0

    def test_pull_request_approval_unknown(self):
        """Test that no finding is reported when the setting could not be read."""
        organizations = {
            1: Org(
                id=1, name="test-organization", can_approve_pull_request_reviews=None
            )
        }

        assert len(self._run_check(organizations)) == 0

    def test_pull_request_approval_disabled(self):
        """Test that an organization not allowing workflow approvals passes the check."""
        organizations = {
            1: Org(
                id=1, name="test-organization", can_approve_pull_request_reviews=False
            )
        }
        result = self._run_check(organizations)

        assert len(result) == 1
        assert result[0].resource_id == 1
        assert result[0].resource_name == "test-organization"
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "Organization test-organization does not allow GitHub Actions to approve pull requests."
        )

    def test_pull_request_approval_enabled(self):
        """Test that an organization allowing workflow approvals fails the check."""
        organizations = {
            1: Org(
                id=1, name="test-organization", can_approve_pull_request_reviews=True
            )
        }
        result = self._run_check(organizations)

        assert len(result) == 1
        assert result[0].resource_id == 1
        assert result[0].resource_name == "test-organization"
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "Organization test-organization allows GitHub Actions to approve pull requests."
        )
