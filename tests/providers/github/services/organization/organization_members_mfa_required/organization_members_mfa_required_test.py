from unittest import mock

from prowler.providers.github.services.organization.organization_service import Org
from tests.providers.github.github_fixtures import set_mocked_github_provider


class Test_organization_members_mfa_required:
    def test_no_organizations(self):
        organization_client = mock.MagicMock
        organization_client.organizations = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_members_mfa_required.organization_members_mfa_required.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_members_mfa_required.organization_members_mfa_required import (
                organization_members_mfa_required,
            )

            check = organization_members_mfa_required()
            result = check.execute()
            assert len(result) == 0

    def test_organization_mfa_disabled(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=False,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_members_mfa_required.organization_members_mfa_required.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_members_mfa_required.organization_members_mfa_required import (
                organization_members_mfa_required,
            )

            check = organization_members_mfa_required()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == "test-organization"
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Organization {org_name} does not require members to have two-factor authentication enabled."
            )

    def test_one_organization_securitymd(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=True,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_members_mfa_required.organization_members_mfa_required.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_members_mfa_required.organization_members_mfa_required import (
                organization_members_mfa_required,
            )

            check = organization_members_mfa_required()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == "test-organization"
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Organization {org_name} does require members to have two-factor authentication enabled."
            )
