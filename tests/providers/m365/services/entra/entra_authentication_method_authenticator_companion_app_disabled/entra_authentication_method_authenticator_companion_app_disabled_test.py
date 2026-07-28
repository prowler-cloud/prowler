from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    AuthenticationMethodsPolicySettings,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_authentication_method_authenticator_companion_app_disabled.entra_authentication_method_authenticator_companion_app_disabled"


class Test_entra_authentication_method_authenticator_companion_app_disabled:
    def _run(self, settings):
        entra_client = mock.MagicMock
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_authentication_method_authenticator_companion_app_disabled.entra_authentication_method_authenticator_companion_app_disabled import (
                entra_authentication_method_authenticator_companion_app_disabled,
            )

            entra_client.authentication_methods_policy_settings = settings
            return (
                entra_authentication_method_authenticator_companion_app_disabled().execute()
            )

    def test_no_settings(self):
        assert self._run(None) == []

    def test_disabled(self):
        result = self._run(
            AuthenticationMethodsPolicySettings(
                authenticator_companion_app_state="disabled"
            )
        )
        assert result[0].status == "PASS"

    def test_enabled(self):
        result = self._run(
            AuthenticationMethodsPolicySettings(
                authenticator_companion_app_state="enabled"
            )
        )
        assert result[0].status == "FAIL"
