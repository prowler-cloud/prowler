from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    AuthenticationMethodsPolicySettings,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_authentication_method_authenticator_show_context.entra_authentication_method_authenticator_show_context"


class Test_entra_authentication_method_authenticator_show_context:
    def _run(self, settings):
        entra_client = mock.MagicMock
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_authentication_method_authenticator_show_context.entra_authentication_method_authenticator_show_context import (
                entra_authentication_method_authenticator_show_context,
            )

            entra_client.authentication_methods_policy_settings = settings
            return entra_authentication_method_authenticator_show_context().execute()

    def test_no_settings(self):
        assert self._run(None) == []

    def test_both_enabled(self):
        result = self._run(
            AuthenticationMethodsPolicySettings(
                authenticator_state="enabled",
                authenticator_display_app_information_state="enabled",
                authenticator_display_location_information_state="enabled",
            )
        )
        assert result[0].status == "PASS"

    def test_location_disabled(self):
        result = self._run(
            AuthenticationMethodsPolicySettings(
                authenticator_state="enabled",
                authenticator_display_app_information_state="enabled",
                authenticator_display_location_information_state="disabled",
            )
        )
        assert result[0].status == "FAIL"

    def test_context_enabled_but_authenticator_disabled(self):
        result = self._run(
            AuthenticationMethodsPolicySettings(
                authenticator_state="disabled",
                authenticator_display_app_information_state="enabled",
                authenticator_display_location_information_state="enabled",
            )
        )
        assert result[0].status == "FAIL"
