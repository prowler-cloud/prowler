from unittest import mock
from uuid import uuid4

from prowler.providers.microsoft365.services.entra.entra_service import (
    AuthorizationPolicy,
    DefaultUserRolePermissions,
)
from tests.providers.microsoft365.microsoft365_fixtures import (
    set_mocked_microsoft365_provider,
)


class Test_entra_authpolicy_ensure_default_user_cannot_create_tenants:
    def test_entra_empty_tenant(self):
        entra_client = mock.MagicMock
        entra_client.authorization_policy = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_authpolicy_ensure_default_user_cannot_create_tenants.entra_authpolicy_ensure_default_user_cannot_create_tenants.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_authpolicy_ensure_default_user_cannot_create_tenants.entra_authpolicy_ensure_default_user_cannot_create_tenants import (
                entra_authpolicy_ensure_default_user_cannot_create_tenants,
            )

            check = entra_authpolicy_ensure_default_user_cannot_create_tenants()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Tenant creation is not disabled for non-admin users."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Authorization Policy"
            assert result[0].resource_id == "authorizationPolicy"
            assert result[0].location == "global"

    def test_entra_default_user_role_permissions_allowed_to_create_tenants(self):
        id = str(uuid4())
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_authpolicy_ensure_default_user_cannot_create_tenants.entra_authpolicy_ensure_default_user_cannot_create_tenants.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_authpolicy_ensure_default_user_cannot_create_tenants.entra_authpolicy_ensure_default_user_cannot_create_tenants import (
                entra_authpolicy_ensure_default_user_cannot_create_tenants,
            )

            entra_client.authorization_policy = AuthorizationPolicy(
                id=id,
                name="Test",
                description="Test",
                default_user_role_permissions=DefaultUserRolePermissions(
                    allowed_to_create_tenants=True
                ),
            )

            check = entra_authpolicy_ensure_default_user_cannot_create_tenants()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Tenant creation is not disabled for non-admin users."
            )
            assert result[0].resource == entra_client.authorization_policy.dict()
            assert result[0].resource_name == "Test"
            assert result[0].resource_id == id
            assert result[0].location == "global"

    def test_entra_default_user_role_permissions_not_allowed_to_create_tenants(self):
        id = str(uuid4())
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_authpolicy_ensure_default_user_cannot_create_tenants.entra_authpolicy_ensure_default_user_cannot_create_tenants.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_authpolicy_ensure_default_user_cannot_create_tenants.entra_authpolicy_ensure_default_user_cannot_create_tenants import (
                entra_authpolicy_ensure_default_user_cannot_create_tenants,
            )

            entra_client.authorization_policy = AuthorizationPolicy(
                id=id,
                name="Test",
                description="Test",
                default_user_role_permissions=DefaultUserRolePermissions(
                    allowed_to_create_tenants=False
                ),
            )

            check = entra_authpolicy_ensure_default_user_cannot_create_tenants()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Tenant creation is disabled for non-admin users."
            )
            assert result[0].resource == entra_client.authorization_policy.dict()
            assert result[0].resource_name == "Test"
            assert result[0].resource_id == id
            assert result[0].location == "global"
