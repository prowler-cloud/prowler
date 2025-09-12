from unittest import mock

from prowler.providers.mongodbatlas.services.organizations.organizations_service import (
    Organization,
    OrganizationSettings,
)
from tests.providers.mongodbatlas.mongodbatlas_fixtures import (
    ORG_ID,
    set_mocked_mongodbatlas_provider,
)


class Test_organizations_service_account_secrets_expiration:
    def test_no_organizations(self):
        organizations_client = mock.MagicMock
        organizations_client.organizations = {}
        organizations_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_mongodbatlas_provider(),
            ),
            mock.patch(
                "prowler.providers.mongodbatlas.services.organizations.organizations_service_account_secrets_expiration.organizations_service_account_secrets_expiration.organizations_client",
                new=organizations_client,
            ),
        ):

            from prowler.providers.mongodbatlas.services.organizations.organizations_service_account_secrets_expiration.organizations_service_account_secrets_expiration import (
                organizations_service_account_secrets_expiration,
            )

            check = organizations_service_account_secrets_expiration()
            result = check.execute()
            assert len(result) == 0

    def test_organizations_service_account_secrets_expiration_valid(self):
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
                    max_service_account_secret_validity_in_hours=8,
                ),
                location="global",
            )
        }
        organizations_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_mongodbatlas_provider(),
            ),
            mock.patch(
                "prowler.providers.mongodbatlas.services.organizations.organizations_service_account_secrets_expiration.organizations_service_account_secrets_expiration.organizations_client",
                new=organizations_client,
            ),
        ):

            from prowler.providers.mongodbatlas.services.organizations.organizations_service_account_secrets_expiration.organizations_service_account_secrets_expiration import (
                organizations_service_account_secrets_expiration,
            )

            check = organizations_service_account_secrets_expiration()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == ORG_ID
            assert result[0].resource_name == org_name
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Organization {org_name} has a maximum period expiration of 8 hours for Admin API Service Account secrets, which is within the recommended threshold of 8 hours."
            )

    def test_organizations_service_account_secrets_expiration_invalid(self):
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
                    max_service_account_secret_validity_in_hours=24,
                ),
                location="global",
            )
        }
        organizations_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_mongodbatlas_provider(),
            ),
            mock.patch(
                "prowler.providers.mongodbatlas.services.organizations.organizations_service_account_secrets_expiration.organizations_service_account_secrets_expiration.organizations_client",
                new=organizations_client,
            ),
        ):

            from prowler.providers.mongodbatlas.services.organizations.organizations_service_account_secrets_expiration.organizations_service_account_secrets_expiration import (
                organizations_service_account_secrets_expiration,
            )

            check = organizations_service_account_secrets_expiration()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == ORG_ID
            assert result[0].resource_name == org_name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Organization {org_name} has a maximum period expiration of 24 hours for Admin API Service Account secrets, which exceeds the recommended threshold of 8 hours."
            )

    def test_organizations_service_account_secrets_expiration_not_configured(self):
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
        organizations_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_mongodbatlas_provider(),
            ),
            mock.patch(
                "prowler.providers.mongodbatlas.services.organizations.organizations_service_account_secrets_expiration.organizations_service_account_secrets_expiration.organizations_client",
                new=organizations_client,
            ),
        ):

            from prowler.providers.mongodbatlas.services.organizations.organizations_service_account_secrets_expiration.organizations_service_account_secrets_expiration import (
                organizations_service_account_secrets_expiration,
            )

            check = organizations_service_account_secrets_expiration()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == ORG_ID
            assert result[0].resource_name == org_name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Organization {org_name} does not have a maximum period expiration configured for Admin API Service Account secrets."
            )

    def test_organizations_service_account_secrets_expiration_custom_threshold(self):
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
                    max_service_account_secret_validity_in_hours=12,
                ),
                location="global",
            )
        }
        organizations_client.audit_config = {
            "max_service_account_secret_validity_hours": 24
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_mongodbatlas_provider(),
            ),
            mock.patch(
                "prowler.providers.mongodbatlas.services.organizations.organizations_service_account_secrets_expiration.organizations_service_account_secrets_expiration.organizations_client",
                new=organizations_client,
            ),
        ):

            from prowler.providers.mongodbatlas.services.organizations.organizations_service_account_secrets_expiration.organizations_service_account_secrets_expiration import (
                organizations_service_account_secrets_expiration,
            )

            check = organizations_service_account_secrets_expiration()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == ORG_ID
            assert result[0].resource_name == org_name
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Organization {org_name} has a maximum period expiration of 12 hours for Admin API Service Account secrets, which is within the recommended threshold of 24 hours."
            )
