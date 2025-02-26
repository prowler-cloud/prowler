from unittest import mock
from uuid import uuid4

from prowler.providers.microsoft365.services.entra.entra_service import (
    DefaultUserRolePermissions,
)
from tests.providers.microsoft365.microsoft365_fixtures import (
    DOMAIN,
    set_mocked_microsoft365_provider,
)


class Test_entra_thirdparty_integrated_apps_not_allowed:
    def test_entra_no_authorization_policy(self):
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_thirdparty_integrated_apps_not_allowed.entra_thirdparty_integrated_apps_not_allowed.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_thirdparty_integrated_apps_not_allowed.entra_thirdparty_integrated_apps_not_allowed import (
                entra_thirdparty_integrated_apps_not_allowed,
            )

            entra_client.authorization_policy = None

            check = entra_thirdparty_integrated_apps_not_allowed()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource == {}
            assert result[0].resource_name == "Authorization Policy"
            assert result[0].resource_id == "authorizationPolicy"
            assert result[0].status_extended == "Authorization Policy was not found."
            assert result[0].location == "global"

    def test_entra_default_user_role_permissions_not_allowed_to_create_apps(self):
        id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_thirdparty_integrated_apps_not_allowed.entra_thirdparty_integrated_apps_not_allowed.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_service import (
                AuthorizationPolicy,
            )
            from prowler.providers.microsoft365.services.entra.entra_thirdparty_integrated_apps_not_allowed.entra_thirdparty_integrated_apps_not_allowed import (
                entra_thirdparty_integrated_apps_not_allowed,
            )

            role_permissions = DefaultUserRolePermissions(allowed_to_create_apps=False)
            entra_client.authorization_policy = AuthorizationPolicy(
                id=id,
                name="Test",
                description="Test",
                default_user_role_permissions=role_permissions,
            )

            check = entra_thirdparty_integrated_apps_not_allowed()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "App creation is disabled for non-admin users."
            )
            assert result[0].resource == {
                "id": id,
                "name": "Test",
                "description": "Test",
                "default_user_role_permissions": role_permissions,
            }
            assert result[0].resource_name == "Test"
            assert result[0].resource_id == id
            assert result[0].location == "global"

    def test_entra_default_user_role_permissions_allowed_to_create_apps(self):
        id = str(uuid4())
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_thirdparty_integrated_apps_not_allowed.entra_thirdparty_integrated_apps_not_allowed.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_service import (
                AuthorizationPolicy,
            )
            from prowler.providers.microsoft365.services.entra.entra_thirdparty_integrated_apps_not_allowed.entra_thirdparty_integrated_apps_not_allowed import (
                entra_thirdparty_integrated_apps_not_allowed,
            )

            role_permissions = DefaultUserRolePermissions(allowed_to_create_apps=True)
            entra_client.authorization_policy = AuthorizationPolicy(
                id=id,
                name="Test",
                description="Test",
                default_user_role_permissions=role_permissions,
            )

            check = entra_thirdparty_integrated_apps_not_allowed()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "App creation is not disabled for non-admin users."
            )
            assert result[0].resource == {
                "id": id,
                "name": "Test",
                "description": "Test",
                "default_user_role_permissions": role_permissions,
            }
            assert result[0].resource_name == "Test"
            assert result[0].resource_id == id
            assert result[0].location == "global"
