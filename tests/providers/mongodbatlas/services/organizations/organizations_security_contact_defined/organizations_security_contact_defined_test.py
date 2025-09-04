from unittest import mock

from prowler.providers.mongodbatlas.services.organizations.organizations_service import (
    Organization,
    OrganizationSettings,
)
from tests.providers.mongodbatlas.mongodbatlas_fixtures import (
    ORG_ID,
    set_mocked_mongodbatlas_provider,
)


class Test_organizations_security_contact_defined:
    def test_no_organizations(self):
        organizations_client = mock.MagicMock
        organizations_client.organizations = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_mongodbatlas_provider(),
            ),
            mock.patch(
                "prowler.providers.mongodbatlas.services.organizations.organizations_security_contact_defined.organizations_security_contact_defined.organizations_client",
                new=organizations_client,
            ),
        ):

            from prowler.providers.mongodbatlas.services.organizations.organizations_security_contact_defined.organizations_security_contact_defined import (
                organizations_security_contact_defined,
            )

            check = organizations_security_contact_defined()
            result = check.execute()
            assert len(result) == 0

    def test_organizations_security_contact_defined(self):
        organizations_client = mock.MagicMock
        org_name = "Test Organization"
        security_contact = "security@example.com"
        organizations_client.organizations = {
            ORG_ID: Organization(
                id=ORG_ID,
                name=org_name,
                settings=OrganizationSettings(
                    api_access_list_required=False,
                    ip_access_list_enabled=False,
                    ip_access_list=[],
                    multi_factor_auth_required=False,
                    security_contact=security_contact,
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
                "prowler.providers.mongodbatlas.services.organizations.organizations_security_contact_defined.organizations_security_contact_defined.organizations_client",
                new=organizations_client,
            ),
        ):

            from prowler.providers.mongodbatlas.services.organizations.organizations_security_contact_defined.organizations_security_contact_defined import (
                organizations_security_contact_defined,
            )

            check = organizations_security_contact_defined()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == ORG_ID
            assert result[0].resource_name == org_name
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Organization {org_name} has a security contact defined: {security_contact}"
            )

    def test_organizations_security_contact_not_defined(self):
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
                "prowler.providers.mongodbatlas.services.organizations.organizations_security_contact_defined.organizations_security_contact_defined.organizations_client",
                new=organizations_client,
            ),
        ):

            from prowler.providers.mongodbatlas.services.organizations.organizations_security_contact_defined.organizations_security_contact_defined import (
                organizations_security_contact_defined,
            )

            check = organizations_security_contact_defined()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == ORG_ID
            assert result[0].resource_name == org_name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Organization {org_name} does not have a security contact defined to receive security-related notifications."
            )
