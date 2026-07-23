from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    AuthenticationMethodsPolicySettings,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_authentication_method_system_preferred_mfa_enabled.entra_authentication_method_system_preferred_mfa_enabled"


class Test_entra_authentication_method_system_preferred_mfa_enabled:
    def _run(self, settings):
        entra_client = mock.MagicMock
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_authentication_method_system_preferred_mfa_enabled.entra_authentication_method_system_preferred_mfa_enabled import (
                entra_authentication_method_system_preferred_mfa_enabled,
            )

            entra_client.authentication_methods_policy_settings = settings
            return entra_authentication_method_system_preferred_mfa_enabled().execute()

    def test_no_settings(self):
        assert self._run(None) == []

    def test_enabled_all_users(self):
        result = self._run(
            AuthenticationMethodsPolicySettings(
                system_preferred_mfa_state="enabled",
                system_preferred_mfa_include_targets=["all_users"],
            )
        )
        assert result[0].status == "PASS"

    def test_enabled_not_all_users(self):
        result = self._run(
            AuthenticationMethodsPolicySettings(
                system_preferred_mfa_state="enabled",
                system_preferred_mfa_include_targets=["some-group-id"],
            )
        )
        assert result[0].status == "FAIL"

    def test_disabled(self):
        result = self._run(
            AuthenticationMethodsPolicySettings(
                system_preferred_mfa_state="disabled",
                system_preferred_mfa_include_targets=["all_users"],
            )
        )
        assert result[0].status == "FAIL"
