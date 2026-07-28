from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    AuthorizationPolicy,
    DefaultUserRolePermissions,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider


class Test_entra_policy_default_user_cannot_create_security_groups:
    def test_users_can_create_security_groups(self):
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_policy_default_user_cannot_create_security_groups.entra_policy_default_user_cannot_create_security_groups.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_policy_default_user_cannot_create_security_groups.entra_policy_default_user_cannot_create_security_groups import (
                entra_policy_default_user_cannot_create_security_groups,
            )

            entra_client.authorization_policy = AuthorizationPolicy(
                id="authorizationPolicy",
                name="Authorization Policy",
                description="",
                default_user_role_permissions=DefaultUserRolePermissions(
                    allowed_to_create_security_groups=True,
                ),
            )

            check = entra_policy_default_user_cannot_create_security_groups()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Non-admin users are allowed to create security groups."
            )
            assert result[0].resource_id == "authorizationPolicy"
            assert result[0].resource_name == "Authorization Policy"

    def test_authorization_policy_none(self):
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_policy_default_user_cannot_create_security_groups.entra_policy_default_user_cannot_create_security_groups.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_policy_default_user_cannot_create_security_groups.entra_policy_default_user_cannot_create_security_groups import (
                entra_policy_default_user_cannot_create_security_groups,
            )

            entra_client.authorization_policy = None

            result = entra_policy_default_user_cannot_create_security_groups().execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "authorizationPolicy"

    def test_users_cannot_create_security_groups(self):
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_policy_default_user_cannot_create_security_groups.entra_policy_default_user_cannot_create_security_groups.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_policy_default_user_cannot_create_security_groups.entra_policy_default_user_cannot_create_security_groups import (
                entra_policy_default_user_cannot_create_security_groups,
            )

            entra_client.authorization_policy = AuthorizationPolicy(
                id="authorizationPolicy",
                name="Authorization Policy",
                description="",
                default_user_role_permissions=DefaultUserRolePermissions(
                    allowed_to_create_security_groups=False,
                ),
            )

            check = entra_policy_default_user_cannot_create_security_groups()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Non-admin users are not allowed to create security groups."
            )
