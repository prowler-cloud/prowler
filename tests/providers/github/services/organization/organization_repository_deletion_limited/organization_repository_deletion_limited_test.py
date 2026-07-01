from unittest import mock

from prowler.providers.github.services.organization.organization_service import Org
from tests.providers.github.github_fixtures import set_mocked_github_provider


class Test_organization_repository_deletion_limited:
    def test_no_organizations(self):
        organization_client = mock.MagicMock
        organization_client.organizations = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_repository_deletion_limited.organization_repository_deletion_limited.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_repository_deletion_limited.organization_repository_deletion_limited import (
                organization_repository_deletion_limited,
            )

            check = organization_repository_deletion_limited()
            result = check.execute()
            assert len(result) == 0

    def test_repository_deletion_disabled(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=None,
                members_can_delete_repositories=False,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_repository_deletion_limited.organization_repository_deletion_limited.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_repository_deletion_limited.organization_repository_deletion_limited import (
                organization_repository_deletion_limited,
            )

            check = organization_repository_deletion_limited()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_name == org_name
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Organization {org_name} restricts repository deletion/transfer to trusted users."
            )

    def test_repository_deletion_enabled(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=None,
                members_can_delete_repositories=True,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_repository_deletion_limited.organization_repository_deletion_limited.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_repository_deletion_limited.organization_repository_deletion_limited import (
                organization_repository_deletion_limited,
            )

            check = organization_repository_deletion_limited()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_name == org_name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Organization {org_name} allows members to delete/transfer repositories."
            )

    def test_repository_deletion_setting_not_available(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=None,
                members_can_delete_repositories=None,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_repository_deletion_limited.organization_repository_deletion_limited.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_repository_deletion_limited.organization_repository_deletion_limited import (
                organization_repository_deletion_limited,
            )

            check = organization_repository_deletion_limited()
            result = check.execute()
            assert len(result) == 0

    def test_multiple_organizations_mixed_settings(self):
        organization_client = mock.MagicMock
        org_name_1 = "test-organization-1"
        org_name_2 = "test-organization-2"
        org_name_3 = "test-organization-3"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name_1,
                mfa_required=None,
                members_can_delete_repositories=False,
            ),
            2: Org(
                id=2,
                name=org_name_2,
                mfa_required=None,
                members_can_delete_repositories=True,
            ),
            3: Org(
                id=3,
                name=org_name_3,
                mfa_required=None,
                members_can_delete_repositories=None,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_repository_deletion_limited.organization_repository_deletion_limited.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_repository_deletion_limited.organization_repository_deletion_limited import (
                organization_repository_deletion_limited,
            )

            check = organization_repository_deletion_limited()
            result = check.execute()
            assert len(result) == 2

            # Find results by organization name
            results_by_name = {r.resource_name: r for r in result}

            assert org_name_1 in results_by_name
            assert results_by_name[org_name_1].status == "PASS"

            assert org_name_2 in results_by_name
            assert results_by_name[org_name_2].status == "FAIL"

            # org_name_3 should not be in results because setting is None
            assert org_name_3 not in results_by_name
