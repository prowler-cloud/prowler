from unittest import mock

from prowler.providers.mongodbatlas.services.organizations.organizations_service import (
    Organization,
    OrganizationSettings,
)
from tests.providers.mongodbatlas.mongodbatlas_fixtures import (
    ORG_ID,
    set_mocked_mongodbatlas_provider,
)


class Test_organizations_mfa_required:
    def test_no_organizations(self):
        organizations_client = mock.MagicMock
        organizations_client.organizations = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_mongodbatlas_provider(),
            ),
            mock.patch(
                "prowler.providers.mongodbatlas.services.organizations.organizations_mfa_required.organizations_mfa_required.organizations_client",
                new=organizations_client,
            ),
        ):

            from prowler.providers.mongodbatlas.services.organizations.organizations_mfa_required.organizations_mfa_required import (
                organizations_mfa_required,
            )

            check = organizations_mfa_required()
            result = check.execute()
            assert len(result) == 0

    def test_organizations_mfa_required(self):
        organizations_client = mock.MagicMock
        org_name = "Test Organization"
        organizations_client.organizations = {
            ORG_ID: Organization(
                id=ORG_ID,
                name=org_name,
                settings=OrganizationSettings(
                    api_access_list_required=False,
                    ip_access_list_enabled=False,
                    ip_access_list=[],
                    multi_factor_auth_required=True,
                    security_contact=None,
                    max_service_account_secret_validity_in_hours=None,
                ),
                location="global",
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_mongodbatlas_provider(),
            ),
            mock.patch(
                "prowler.providers.mongodbatlas.services.organizations.organizations_mfa_required.organizations_mfa_required.organizations_client",
                new=organizations_client,
            ),
        ):

            from prowler.providers.mongodbatlas.services.organizations.organizations_mfa_required.organizations_mfa_required import (
                organizations_mfa_required,
            )

            check = organizations_mfa_required()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == ORG_ID
            assert result[0].resource_name == org_name
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Organization {org_name} requires users to set up Multi-Factor Authentication (MFA) before accessing the organization."
            )

    def test_organizations_mfa_not_required(self):
        organizations_client = mock.MagicMock
        org_name = "Test Organization"
        organizations_client.organizations = {
            ORG_ID: Organization(
                id=ORG_ID,
                name=org_name,
                settings=OrganizationSettings(
                    api_access_list_required=False,
                    ip_access_list_enabled=False,
                    ip_access_list=[],
                    multi_factor_auth_required=False,
                    security_contact=None,
                    max_service_account_secret_validity_in_hours=None,
                ),
                location="global",
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_mongodbatlas_provider(),
            ),
            mock.patch(
                "prowler.providers.mongodbatlas.services.organizations.organizations_mfa_required.organizations_mfa_required.organizations_client",
                new=organizations_client,
            ),
        ):

            from prowler.providers.mongodbatlas.services.organizations.organizations_mfa_required.organizations_mfa_required import (
                organizations_mfa_required,
            )

            check = organizations_mfa_required()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == ORG_ID
            assert result[0].resource_name == org_name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Organization {org_name} does not require users to set up Multi-Factor Authentication (MFA) before accessing the organization."
            )
