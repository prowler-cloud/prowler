from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    PASSWORD_RULE_SETTINGS_TEMPLATE_ID,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_password_protection_lockout_threshold_limited.entra_password_protection_lockout_threshold_limited"


class Test_entra_password_protection_lockout_threshold_limited:
    def _run(self, directory_settings):
        entra_client = mock.MagicMock
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_password_protection_lockout_threshold_limited.entra_password_protection_lockout_threshold_limited import (
                entra_password_protection_lockout_threshold_limited,
            )

            entra_client.directory_settings = directory_settings
            return entra_password_protection_lockout_threshold_limited().execute()

    def test_template_absent(self):
        assert len(self._run({})) == 0

    def test_within_limit(self):
        result = self._run(
            {PASSWORD_RULE_SETTINGS_TEMPLATE_ID: {"LockoutThreshold": "10"}}
        )
        assert result[0].status == "PASS"

    def test_exceeds_limit(self):
        result = self._run(
            {PASSWORD_RULE_SETTINGS_TEMPLATE_ID: {"LockoutThreshold": "20"}}
        )
        assert result[0].status == "FAIL"
