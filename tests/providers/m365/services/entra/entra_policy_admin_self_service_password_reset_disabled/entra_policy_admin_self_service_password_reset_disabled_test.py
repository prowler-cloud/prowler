from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    AuthorizationPolicy,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider


class Test_entra_policy_admin_self_service_password_reset_disabled:
    def test_no_auth_policy(self):
        """When authorization_policy is None, the check returns a MANUAL finding."""
        entra_client = mock.MagicMock()
        entra_client.authorization_policy = None

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_policy_admin_self_service_password_reset_disabled.entra_policy_admin_self_service_password_reset_disabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_policy_admin_self_service_password_reset_disabled.entra_policy_admin_self_service_password_reset_disabled import (
                entra_policy_admin_self_service_password_reset_disabled,
            )

            check = entra_policy_admin_self_service_password_reset_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "Cannot evaluate" in result[0].status_extended
            assert "Policy.Read.All" in result[0].status_extended
            assert result[0].resource_name == "Authorization Policy"
            assert result[0].resource_id == "authorizationPolicy"

    def test_auth_policy_sspr_none(self):
        """When allowed_to_use_sspr is None, the check returns a MANUAL finding."""
        entra_client = mock.MagicMock()
        entra_client.authorization_policy = AuthorizationPolicy(
            id="authorizationPolicy",
            name="Authorization Policy",
            description="",
            default_user_role_permissions=None,
            guest_invite_settings=None,
            guest_user_role_id=None,
            allowed_to_use_sspr=None,
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_policy_admin_self_service_password_reset_disabled.entra_policy_admin_self_service_password_reset_disabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_policy_admin_self_service_password_reset_disabled.entra_policy_admin_self_service_password_reset_disabled import (
                entra_policy_admin_self_service_password_reset_disabled,
            )

            check = entra_policy_admin_self_service_password_reset_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "Cannot evaluate" in result[0].status_extended
            assert result[0].resource_name == "Authorization Policy"
            assert result[0].resource_id == "authorizationPolicy"

    def test_sspr_enabled_fail(self):
        """When allowed_to_use_sspr is True, the check returns FAIL."""
        entra_client = mock.MagicMock()
        entra_client.authorization_policy = AuthorizationPolicy(
            id="authorizationPolicy",
            name="Authorization Policy",
            description="",
            default_user_role_permissions=None,
            guest_invite_settings=None,
            guest_user_role_id=None,
            allowed_to_use_sspr=True,
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_policy_admin_self_service_password_reset_disabled.entra_policy_admin_self_service_password_reset_disabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_policy_admin_self_service_password_reset_disabled.entra_policy_admin_self_service_password_reset_disabled import (
                entra_policy_admin_self_service_password_reset_disabled,
            )

            check = entra_policy_admin_self_service_password_reset_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Self-Service Password Reset (SSPR) is enabled for administrators."
            )
            assert result[0].resource_id == "authorizationPolicy"
            assert result[0].resource_name == "Authorization Policy"
            assert result[0].location == "global"

    def test_sspr_disabled_pass(self):
        """When allowed_to_use_sspr is False, the check returns PASS."""
        entra_client = mock.MagicMock()
        entra_client.authorization_policy = AuthorizationPolicy(
            id="authorizationPolicy",
            name="Authorization Policy",
            description="",
            default_user_role_permissions=None,
            guest_invite_settings=None,
            guest_user_role_id=None,
            allowed_to_use_sspr=False,
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_policy_admin_self_service_password_reset_disabled.entra_policy_admin_self_service_password_reset_disabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_policy_admin_self_service_password_reset_disabled.entra_policy_admin_self_service_password_reset_disabled import (
                entra_policy_admin_self_service_password_reset_disabled,
            )

            check = entra_policy_admin_self_service_password_reset_disabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Self-Service Password Reset (SSPR) is disabled for administrators."
            )
            assert result[0].resource_id == "authorizationPolicy"
            assert result[0].resource_name == "Authorization Policy"
            assert result[0].location == "global"
