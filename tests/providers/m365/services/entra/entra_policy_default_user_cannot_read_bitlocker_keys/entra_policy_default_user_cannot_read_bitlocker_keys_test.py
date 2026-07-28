from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    AuthorizationPolicy,
    DefaultUserRolePermissions,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider


class Test_entra_policy_default_user_cannot_read_bitlocker_keys:
    def test_users_can_read_bitlocker_keys(self):
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_policy_default_user_cannot_read_bitlocker_keys.entra_policy_default_user_cannot_read_bitlocker_keys.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_policy_default_user_cannot_read_bitlocker_keys.entra_policy_default_user_cannot_read_bitlocker_keys import (
                entra_policy_default_user_cannot_read_bitlocker_keys,
            )

            entra_client.authorization_policy = AuthorizationPolicy(
                id="authorizationPolicy",
                name="Authorization Policy",
                description="",
                default_user_role_permissions=DefaultUserRolePermissions(
                    allowed_to_read_bitlocker_keys_for_owned_device=True,
                ),
            )

            check = entra_policy_default_user_cannot_read_bitlocker_keys()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Non-admin users are allowed to read BitLocker keys for their owned devices."
            )

    def test_authorization_policy_none(self):
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_policy_default_user_cannot_read_bitlocker_keys.entra_policy_default_user_cannot_read_bitlocker_keys.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_policy_default_user_cannot_read_bitlocker_keys.entra_policy_default_user_cannot_read_bitlocker_keys import (
                entra_policy_default_user_cannot_read_bitlocker_keys,
            )

            entra_client.authorization_policy = None

            result = entra_policy_default_user_cannot_read_bitlocker_keys().execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_users_cannot_read_bitlocker_keys(self):
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_policy_default_user_cannot_read_bitlocker_keys.entra_policy_default_user_cannot_read_bitlocker_keys.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_policy_default_user_cannot_read_bitlocker_keys.entra_policy_default_user_cannot_read_bitlocker_keys import (
                entra_policy_default_user_cannot_read_bitlocker_keys,
            )

            entra_client.authorization_policy = AuthorizationPolicy(
                id="authorizationPolicy",
                name="Authorization Policy",
                description="",
                default_user_role_permissions=DefaultUserRolePermissions(
                    allowed_to_read_bitlocker_keys_for_owned_device=False,
                ),
            )

            check = entra_policy_default_user_cannot_read_bitlocker_keys()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Non-admin users are not allowed to read BitLocker keys for their owned devices."
            )
