from unittest import mock
from uuid import uuid4

from tests.providers.azure.azure_fixtures import DOMAIN, set_mocked_azure_provider


class Test_entra_policy_ensure_default_user_cannot_create_apps:
    def test_entra_no_tenants(self):
        entra_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.entra.entra_policy_ensure_default_user_cannot_create_apps.entra_policy_ensure_default_user_cannot_create_apps.entra_client",
            new=entra_client,
        ):
            from prowler.providers.azure.services.entra.entra_policy_ensure_default_user_cannot_create_apps.entra_policy_ensure_default_user_cannot_create_apps import (
                entra_policy_ensure_default_user_cannot_create_apps,
            )

            entra_client.authorization_policy = {}

            check = entra_policy_ensure_default_user_cannot_create_apps()
            result = check.execute()
            assert len(result) == 0

    def test_entra_tenant_empty(self):
        entra_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.entra.entra_policy_ensure_default_user_cannot_create_apps.entra_policy_ensure_default_user_cannot_create_apps.entra_client",
            new=entra_client,
        ):
            from prowler.providers.azure.services.entra.entra_policy_ensure_default_user_cannot_create_apps.entra_policy_ensure_default_user_cannot_create_apps import (
                entra_policy_ensure_default_user_cannot_create_apps,
            )

            entra_client.authorization_policy = {DOMAIN: {}}

            check = entra_policy_ensure_default_user_cannot_create_apps()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Authorization Policy"
            assert result[0].resource_id == "authorizationPolicy"
            assert (
                result[0].status_extended
                == "App creation is not disabled for non-admin users."
            )

    def test_entra_default_user_role_permissions_not_allowed_to_create_apps(self):
        id = str(uuid4())
        entra_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.entra.entra_policy_ensure_default_user_cannot_create_apps.entra_policy_ensure_default_user_cannot_create_apps.entra_client",
            new=entra_client,
        ):
            from prowler.providers.azure.services.entra.entra_policy_ensure_default_user_cannot_create_apps.entra_policy_ensure_default_user_cannot_create_apps import (
                entra_policy_ensure_default_user_cannot_create_apps,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                AuthorizationPolicy,
            )

            entra_client.authorization_policy = {
                DOMAIN: AuthorizationPolicy(
                    id=id,
                    name="Test",
                    description="Test",
                    default_user_role_permissions=mock.MagicMock(
                        allowed_to_create_apps=False
                    ),
                    guest_invite_settings="none",
                    guest_user_role_id=None,
                )
            }

            check = entra_policy_ensure_default_user_cannot_create_apps()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "App creation is disabled for non-admin users."
            )
            assert result[0].resource_name == "Test"
            assert result[0].resource_id == id
            assert result[0].subscription == f"Tenant: {DOMAIN}"

    def test_entra_default_user_role_permissions_allowed_to_create_apps(self):
        id = str(uuid4())
        entra_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.entra.entra_policy_ensure_default_user_cannot_create_apps.entra_policy_ensure_default_user_cannot_create_apps.entra_client",
            new=entra_client,
        ):
            from prowler.providers.azure.services.entra.entra_policy_ensure_default_user_cannot_create_apps.entra_policy_ensure_default_user_cannot_create_apps import (
                entra_policy_ensure_default_user_cannot_create_apps,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                AuthorizationPolicy,
            )

            entra_client.authorization_policy = {
                DOMAIN: AuthorizationPolicy(
                    id=id,
                    name="Test",
                    description="Test",
                    default_user_role_permissions=mock.MagicMock(
                        allowed_to_create_apps=True
                    ),
                    guest_invite_settings="none",
                    guest_user_role_id=None,
                )
            }

            check = entra_policy_ensure_default_user_cannot_create_apps()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "App creation is not disabled for non-admin users."
            )
            assert result[0].resource_name == "Test"
            assert result[0].resource_id == id
            assert result[0].subscription == f"Tenant: {DOMAIN}"
