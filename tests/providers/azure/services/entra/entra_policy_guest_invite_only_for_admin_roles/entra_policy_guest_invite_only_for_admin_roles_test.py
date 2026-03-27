from unittest import mock
from uuid import uuid4

from tests.providers.azure.azure_fixtures import DOMAIN, set_mocked_azure_provider


class Test_entra_policy_guest_invite_only_for_admin_roles:
    def test_entra_no_tenants(self):
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_policy_guest_invite_only_for_admin_roles.entra_policy_guest_invite_only_for_admin_roles.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_policy_guest_invite_only_for_admin_roles.entra_policy_guest_invite_only_for_admin_roles import (
                entra_policy_guest_invite_only_for_admin_roles,
            )

            entra_client.authorization_policy = {}

            check = entra_policy_guest_invite_only_for_admin_roles()
            result = check.execute()
            assert len(result) == 0

    def test_entra_empty_tenant(self):
        entra_client = mock.MagicMock
        id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_policy_guest_invite_only_for_admin_roles.entra_policy_guest_invite_only_for_admin_roles.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_policy_guest_invite_only_for_admin_roles.entra_policy_guest_invite_only_for_admin_roles import (
                entra_policy_guest_invite_only_for_admin_roles,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                AuthorizationPolicy,
                DefaultUserRolePermissions,
            )

            # Policy with default settings (everyone can invite guests)
            entra_client.authorization_policy = {
                DOMAIN: AuthorizationPolicy(
                    id=id,
                    name="Authorization Policy",
                    description="Default policy",
                    default_user_role_permissions=DefaultUserRolePermissions(),
                    guest_invite_settings="everyone",
                    guest_user_role_id=uuid4(),
                )
            }

            check = entra_policy_guest_invite_only_for_admin_roles()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Authorization Policy"
            assert result[0].resource_id == id
            assert (
                result[0].status_extended
                == "Guest invitations are not restricted to users with specific administrative roles only."
            )

    def test_entra_tenant_policy_allow_invites_from_everyone(self):
        entra_client = mock.MagicMock
        id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_policy_guest_invite_only_for_admin_roles.entra_policy_guest_invite_only_for_admin_roles.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_policy_guest_invite_only_for_admin_roles.entra_policy_guest_invite_only_for_admin_roles import (
                entra_policy_guest_invite_only_for_admin_roles,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                AuthorizationPolicy,
                DefaultUserRolePermissions,
            )

            entra_client.authorization_policy = {
                DOMAIN: AuthorizationPolicy(
                    id=id,
                    name="TestPolicy",
                    description="TestPolicyDescription",
                    default_user_role_permissions=DefaultUserRolePermissions(),
                    guest_invite_settings="everyone",
                    guest_user_role_id=uuid4(),
                )
            }

            check = entra_policy_guest_invite_only_for_admin_roles()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "Guest invitations are not restricted to users with specific administrative roles only."
            )
            assert result[0].resource_name == "TestPolicy"
            assert result[0].resource_id == id
            assert result[0].subscription == f"Tenant: {DOMAIN}"

    def test_entra_tenant_policy_allow_invites_from_admins(self):
        entra_client = mock.MagicMock
        id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_policy_guest_invite_only_for_admin_roles.entra_policy_guest_invite_only_for_admin_roles.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_policy_guest_invite_only_for_admin_roles.entra_policy_guest_invite_only_for_admin_roles import (
                entra_policy_guest_invite_only_for_admin_roles,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                AuthorizationPolicy,
                DefaultUserRolePermissions,
            )

            entra_client.authorization_policy = {
                DOMAIN: AuthorizationPolicy(
                    id=id,
                    name="TestPolicy",
                    description="TestPolicyDescription",
                    default_user_role_permissions=DefaultUserRolePermissions(),
                    guest_invite_settings="adminsAndGuestInviters",
                    guest_user_role_id=uuid4(),
                )
            }

            check = entra_policy_guest_invite_only_for_admin_roles()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "Guest invitations are restricted to users with specific administrative roles only."
            )
            assert result[0].resource_name == "TestPolicy"
            assert result[0].resource_id == id
            assert result[0].subscription == f"Tenant: {DOMAIN}"

    def test_entra_tenant_policy_allow_invites_from_none(self):
        entra_client = mock.MagicMock
        id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_policy_guest_invite_only_for_admin_roles.entra_policy_guest_invite_only_for_admin_roles.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_policy_guest_invite_only_for_admin_roles.entra_policy_guest_invite_only_for_admin_roles import (
                entra_policy_guest_invite_only_for_admin_roles,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                AuthorizationPolicy,
                DefaultUserRolePermissions,
            )

            entra_client.authorization_policy = {
                DOMAIN: AuthorizationPolicy(
                    id=id,
                    name="TestPolicy",
                    description="TestPolicyDescription",
                    default_user_role_permissions=DefaultUserRolePermissions(),
                    guest_invite_settings="none",
                    guest_user_role_id=uuid4(),
                )
            }

            check = entra_policy_guest_invite_only_for_admin_roles()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "Guest invitations are restricted to users with specific administrative roles only."
            )
            assert result[0].resource_name == "TestPolicy"
            assert result[0].resource_id == id
            assert result[0].subscription == f"Tenant: {DOMAIN}"
