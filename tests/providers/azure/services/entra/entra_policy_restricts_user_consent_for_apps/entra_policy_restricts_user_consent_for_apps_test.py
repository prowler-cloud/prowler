from unittest import mock
from uuid import uuid4

from tests.providers.azure.azure_fixtures import DOMAIN, set_mocked_azure_provider


class Test_entra_policy_restricts_user_consent_for_apps:
    def test_entra_no_tenants(self):
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_policy_restricts_user_consent_for_apps.entra_policy_restricts_user_consent_for_apps.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_policy_restricts_user_consent_for_apps.entra_policy_restricts_user_consent_for_apps import (
                entra_policy_restricts_user_consent_for_apps,
            )

            entra_client.authorization_policy = {}

            check = entra_policy_restricts_user_consent_for_apps()
            result = check.execute()
            assert len(result) == 0

    def test_entra_tenant_empty(self):
        entra_client = mock.MagicMock
        id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_policy_restricts_user_consent_for_apps.entra_policy_restricts_user_consent_for_apps.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_policy_restricts_user_consent_for_apps.entra_policy_restricts_user_consent_for_apps import (
                entra_policy_restricts_user_consent_for_apps,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                AuthorizationPolicy,
            )

            # Policy with no default user role permissions
            entra_client.authorization_policy = {
                DOMAIN: AuthorizationPolicy(
                    id=id,
                    name="Authorization Policy",
                    description="Default policy",
                    guest_invite_settings="none",
                    guest_user_role_id=uuid4(),
                )
            }

            check = entra_policy_restricts_user_consent_for_apps()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Authorization Policy"
            assert result[0].resource_id == id
            assert (
                result[0].status_extended
                == "Entra allows users to consent apps accessing company data on their behalf"
            )

    def test_entra_tenant_no_default_user_role_permissions(self):
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_policy_restricts_user_consent_for_apps.entra_policy_restricts_user_consent_for_apps.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_policy_restricts_user_consent_for_apps.entra_policy_restricts_user_consent_for_apps import (
                entra_policy_restricts_user_consent_for_apps,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                AuthorizationPolicy,
            )

            auth_policy = AuthorizationPolicy(
                id=str(uuid4()),
                name="Authorization Policy",
                description="Authorization Policy Description",
                guest_invite_settings="none",
                guest_user_role_id=uuid4(),
            )

            entra_client.authorization_policy = {DOMAIN: auth_policy}

            check = entra_policy_restricts_user_consent_for_apps()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Authorization Policy"
            assert result[0].resource_id == auth_policy.id
            assert (
                result[0].status_extended
                == "Entra allows users to consent apps accessing company data on their behalf"
            )

    def test_entra_tenant_no_consent(self):
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_policy_restricts_user_consent_for_apps.entra_policy_restricts_user_consent_for_apps.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_policy_restricts_user_consent_for_apps.entra_policy_restricts_user_consent_for_apps import (
                entra_policy_restricts_user_consent_for_apps,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                AuthorizationPolicy,
                DefaultUserRolePermissions,
            )

            auth_policy = AuthorizationPolicy(
                id=str(uuid4()),
                name="Authorization Policy",
                description="Authorization Policy Description",
                default_user_role_permissions=DefaultUserRolePermissions(
                    permission_grant_policies_assigned=[]
                ),
                guest_invite_settings="none",
                guest_user_role_id=uuid4(),
            )

            entra_client.authorization_policy = {DOMAIN: auth_policy}

            check = entra_policy_restricts_user_consent_for_apps()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Authorization Policy"
            assert result[0].resource_id == auth_policy.id
            assert (
                result[0].status_extended
                == "Entra does not allow users to consent apps accessing company data on their behalf"
            )

    def test_entra_tenant_legacy_consent(self):
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_policy_restricts_user_consent_for_apps.entra_policy_restricts_user_consent_for_apps.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_policy_restricts_user_consent_for_apps.entra_policy_restricts_user_consent_for_apps import (
                entra_policy_restricts_user_consent_for_apps,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                AuthorizationPolicy,
                DefaultUserRolePermissions,
            )

            auth_policy = AuthorizationPolicy(
                id=str(uuid4()),
                name="Authorization Policy",
                description="Authorization Policy Description",
                default_user_role_permissions=DefaultUserRolePermissions(
                    permission_grant_policies_assigned=[
                        "ManagePermissionGrantsForSelf.microsoft-user-default-legacy"
                    ]
                ),
                guest_invite_settings="none",
                guest_user_role_id=uuid4(),
            )

            entra_client.authorization_policy = {DOMAIN: auth_policy}

            check = entra_policy_restricts_user_consent_for_apps()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Authorization Policy"
            assert result[0].resource_id == auth_policy.id
            assert (
                result[0].status_extended
                == "Entra allows users to consent apps accessing company data on their behalf"
            )
