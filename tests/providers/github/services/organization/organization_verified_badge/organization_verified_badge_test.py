from unittest import mock

from prowler.providers.github.services.organization.organization_service import Org
from tests.providers.github.github_fixtures import set_mocked_github_provider


class Test_organization_verified_badge:
    def test_no_organizations(self):
        organization_client = mock.MagicMock
        organization_client.organizations = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_verified_badge.organization_verified_badge.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_verified_badge.organization_verified_badge import (
                organization_verified_badge,
            )

            check = organization_verified_badge()
            result = check.execute()
            assert len(result) == 0

    def test_organization_not_verified(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=False,
                is_verified=False,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_verified_badge.organization_verified_badge.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_verified_badge.organization_verified_badge import (
                organization_verified_badge,
            )

            check = organization_verified_badge()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == "test-organization"
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Organization {org_name} does not have a verified badge."
            )

    def test_organization_verified(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=True,
                is_verified=True,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_verified_badge.organization_verified_badge.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_verified_badge.organization_verified_badge import (
                organization_verified_badge,
            )

            check = organization_verified_badge()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == "test-organization"
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Organization {org_name} has a verified badge."
            )

    def test_organization_verified_status_none(self):
        """Test when is_verified status is None (e.g., API permission issue)"""
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=True,
                is_verified=None,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_verified_badge.organization_verified_badge.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_verified_badge.organization_verified_badge import (
                organization_verified_badge,
            )

            check = organization_verified_badge()
            result = check.execute()
            # Should not generate a finding when status is None
            assert len(result) == 0
