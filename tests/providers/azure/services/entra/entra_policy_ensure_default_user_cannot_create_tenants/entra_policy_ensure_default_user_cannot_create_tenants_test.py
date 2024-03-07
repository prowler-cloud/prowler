from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.entra.entra_service import AuthorizationPolicy


class Test_entra_policy_ensure_default_user_cannot_create_tenants:
    def test_entra_no_authorization_policy(self):
        entra_client = mock.MagicMock
        entra_client.authorization_policy = None

        with mock.patch(
            "prowler.providers.azure.services.entra.entra_policy_ensure_default_user_cannot_create_tenants.entra_policy_ensure_default_user_cannot_create_tenants.entra_client",
            new=entra_client,
        ):
            from prowler.providers.azure.services.entra.entra_policy_ensure_default_user_cannot_create_tenants.entra_policy_ensure_default_user_cannot_create_tenants import (
                entra_policy_ensure_default_user_cannot_create_tenants,
            )

            check = entra_policy_ensure_default_user_cannot_create_tenants()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Tenants creation is not disabled for non-admin users."
            )
            assert result[0].resource_name == "Default Authorization Policy"
            assert result[0].resource_id == "Default Authorization Policy"
            assert result[0].subscription == "All"

    def test_entra_default_user_role_permissions_not_allowed_to_create_tenants(self):
        id = str(uuid4())
        auth_policy = AuthorizationPolicy(
            id=id,
            name="Test",
            description="Test",
            default_user_role_permissions=mock.MagicMock(
                allowed_to_create_tenants=False
            ),
        )

        entra_client = mock.MagicMock
        entra_client.authorization_policy = auth_policy

        with mock.patch(
            "prowler.providers.azure.services.entra.entra_policy_ensure_default_user_cannot_create_tenants.entra_policy_ensure_default_user_cannot_create_tenants.entra_client",
            new=entra_client,
        ):
            from prowler.providers.azure.services.entra.entra_policy_ensure_default_user_cannot_create_tenants.entra_policy_ensure_default_user_cannot_create_tenants import (
                entra_policy_ensure_default_user_cannot_create_tenants,
            )

            check = entra_policy_ensure_default_user_cannot_create_tenants()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Tenants creation is disabled for non-admin users."
            )
            assert result[0].resource_name == "Test"
            assert result[0].resource_id == id
            assert result[0].subscription == "All"

    def test_entra_default_user_role_permissions_allowed_to_create_tenants(self):
        id = str(uuid4())
        auth_policy = AuthorizationPolicy(
            id=id,
            name="Test",
            description="Test",
            default_user_role_permissions=mock.MagicMock(
                allowed_to_create_tenants=True
            ),
        )

        entra_client = mock.MagicMock
        entra_client.authorization_policy = auth_policy

        with mock.patch(
            "prowler.providers.azure.services.entra.entra_policy_ensure_default_user_cannot_create_tenants.entra_policy_ensure_default_user_cannot_create_tenants.entra_client",
            new=entra_client,
        ):
            from prowler.providers.azure.services.entra.entra_policy_ensure_default_user_cannot_create_tenants.entra_policy_ensure_default_user_cannot_create_tenants import (
                entra_policy_ensure_default_user_cannot_create_tenants,
            )

            check = entra_policy_ensure_default_user_cannot_create_tenants()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Tenants creation is not disabled for non-admin users."
            )
            assert result[0].resource_name == "Test"
            assert result[0].resource_id == id
            assert result[0].subscription == "All"
