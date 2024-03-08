from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.entra.entra_service import AuthorizationPolicy


class Test_entra_policy_ensure_default_user_cannot_create_apps:
    def test_entra_no_authorization_policy(self):
        entra_client = mock.MagicMock
        entra_client.authorization_policy = {}

        with mock.patch(
            "prowler.providers.azure.services.entra.entra_policy_ensure_default_user_cannot_create_tenants.entra_policy_ensure_default_user_cannot_create_tenants.entra_client",
            new=entra_client,
        ):
            from prowler.providers.azure.services.entra.entra_policy_ensure_default_user_cannot_create_tenants.entra_policy_ensure_default_user_cannot_create_tenants import (
                entra_policy_ensure_default_user_cannot_create_tenants,
            )

            check = entra_policy_ensure_default_user_cannot_create_tenants()
            result = check.execute()
            assert len(result) == 0

    def test_entra_default_user_role_permissions_not_allowed_to_create_apps(self):
        id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.authorization_policy = {
            "test.com": AuthorizationPolicy(
                id=id,
                name="Test",
                description="Test",
                default_user_role_permissions=mock.MagicMock(
                    allowed_to_create_apps=False
                ),
            )
        }

        with mock.patch(
            "prowler.providers.azure.services.entra.entra_policy_ensure_default_user_cannot_create_apps.entra_policy_ensure_default_user_cannot_create_apps.entra_client",
            new=entra_client,
        ):
            from prowler.providers.azure.services.entra.entra_policy_ensure_default_user_cannot_create_apps.entra_policy_ensure_default_user_cannot_create_apps import (
                entra_policy_ensure_default_user_cannot_create_apps,
            )

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
            assert result[0].subscription == "All from tenant 'test.com'"

    def test_entra_default_user_role_permissions_allowed_to_create_apps(self):
        id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.authorization_policy = {
            "test.com": AuthorizationPolicy(
                id=id,
                name="Test",
                description="Test",
                default_user_role_permissions=mock.MagicMock(
                    allowed_to_create_apps=True
                ),
            )
        }

        with mock.patch(
            "prowler.providers.azure.services.entra.entra_policy_ensure_default_user_cannot_create_apps.entra_policy_ensure_default_user_cannot_create_apps.entra_client",
            new=entra_client,
        ):
            from prowler.providers.azure.services.entra.entra_policy_ensure_default_user_cannot_create_apps.entra_policy_ensure_default_user_cannot_create_apps import (
                entra_policy_ensure_default_user_cannot_create_apps,
            )

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
            assert result[0].subscription == "All from tenant 'test.com'"
