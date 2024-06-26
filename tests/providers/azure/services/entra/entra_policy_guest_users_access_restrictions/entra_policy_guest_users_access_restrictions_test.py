from unittest import mock
from uuid import UUID, uuid4

from tests.providers.azure.azure_fixtures import DOMAIN, set_mocked_azure_provider


class Test_entra_policy_guest_users_access_restrictions:
    def test_entra_no_tenants(self):
        entra_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.entra.entra_policy_guest_users_access_restrictions.entra_policy_guest_users_access_restrictions.entra_client",
            new=entra_client,
        ):
            from prowler.providers.azure.services.entra.entra_policy_guest_users_access_restrictions.entra_policy_guest_users_access_restrictions import (
                entra_policy_guest_users_access_restrictions,
            )

            entra_client.authorization_policy = {}

            check = entra_policy_guest_users_access_restrictions()
            result = check.execute()
            assert len(result) == 0

    def test_entra_tenant_empty(self):
        entra_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.entra.entra_policy_guest_users_access_restrictions.entra_policy_guest_users_access_restrictions.entra_client",
            new=entra_client,
        ):
            from prowler.providers.azure.services.entra.entra_policy_guest_users_access_restrictions.entra_policy_guest_users_access_restrictions import (
                entra_policy_guest_users_access_restrictions,
            )

            entra_client.authorization_policy = {DOMAIN: {}}

            check = entra_policy_guest_users_access_restrictions()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Authorization Policy"
            assert result[0].resource_id == "authorizationPolicy"
            assert (
                result[0].status_extended
                == "Guest user access is not restricted to properties and memberships of their own directory objects"
            )

    def test_entra_tenant_policy_access_same_as_member(self):
        entra_client = mock.MagicMock
        id = str(uuid4())

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.entra.entra_policy_guest_users_access_restrictions.entra_policy_guest_users_access_restrictions.entra_client",
            new=entra_client,
        ):
            from prowler.providers.azure.services.entra.entra_policy_guest_users_access_restrictions.entra_policy_guest_users_access_restrictions import (
                entra_policy_guest_users_access_restrictions,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                AuthorizationPolicy,
            )

            entra_client.authorization_policy = {
                DOMAIN: AuthorizationPolicy(
                    id=id,
                    name="Authorization Policy",
                    description="",
                    default_user_role_permissions=None,
                    guest_invite_settings=None,
                    guest_user_role_id=UUID("a0b1b346-4d3e-4e8b-98f8-753987be4970"),
                )
            }

            check = entra_policy_guest_users_access_restrictions()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Authorization Policy"
            assert result[0].resource_id == id
            assert (
                result[0].status_extended
                == "Guest user access is not restricted to properties and memberships of their own directory objects"
            )

    def test_entra_tenant_policy_limited_access(self):
        entra_client = mock.MagicMock
        id = str(uuid4())

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.entra.entra_policy_guest_users_access_restrictions.entra_policy_guest_users_access_restrictions.entra_client",
            new=entra_client,
        ):
            from prowler.providers.azure.services.entra.entra_policy_guest_users_access_restrictions.entra_policy_guest_users_access_restrictions import (
                entra_policy_guest_users_access_restrictions,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                AuthorizationPolicy,
            )

            entra_client.authorization_policy = {
                DOMAIN: AuthorizationPolicy(
                    id=id,
                    name="Authorization Policy",
                    description="",
                    default_user_role_permissions=None,
                    guest_invite_settings=None,
                    guest_user_role_id=UUID("10dae51f-b6af-4016-8d66-8c2a99b929b3"),
                )
            }

            check = entra_policy_guest_users_access_restrictions()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Authorization Policy"
            assert result[0].resource_id == id
            assert (
                result[0].status_extended
                == "Guest user access is not restricted to properties and memberships of their own directory objects"
            )

    def test_entra_tenant_policy_access_restricted(self):
        entra_client = mock.MagicMock
        id = str(uuid4())

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.entra.entra_policy_guest_users_access_restrictions.entra_policy_guest_users_access_restrictions.entra_client",
            new=entra_client,
        ):
            from prowler.providers.azure.services.entra.entra_policy_guest_users_access_restrictions.entra_policy_guest_users_access_restrictions import (
                entra_policy_guest_users_access_restrictions,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                AuthorizationPolicy,
            )

            entra_client.authorization_policy = {
                DOMAIN: AuthorizationPolicy(
                    id=id,
                    name="Authorization Policy",
                    description="",
                    default_user_role_permissions=None,
                    guest_invite_settings=None,
                    guest_user_role_id=UUID("2af84b1e-32c8-42b7-82bc-daa82404023b"),
                )
            }

            check = entra_policy_guest_users_access_restrictions()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Authorization Policy"
            assert result[0].resource_id == id
            assert (
                result[0].status_extended
                == "Guest user access is restricted to properties and memberships of their own directory objects"
            )
