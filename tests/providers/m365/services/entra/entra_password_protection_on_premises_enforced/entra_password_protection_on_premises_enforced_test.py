from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    PASSWORD_RULE_SETTINGS_TEMPLATE_ID,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_password_protection_on_premises_enforced.entra_password_protection_on_premises_enforced"


class Test_entra_password_protection_on_premises_enforced:
    def _run(self, directory_settings):
        entra_client = mock.MagicMock
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_password_protection_on_premises_enforced.entra_password_protection_on_premises_enforced import (
                entra_password_protection_on_premises_enforced,
            )

            entra_client.directory_settings = directory_settings
            return entra_password_protection_on_premises_enforced().execute()

    def test_template_absent(self):
        assert self._run({})[0].status == "FAIL"

    def test_enabled_and_enforced(self):
        result = self._run(
            {
                PASSWORD_RULE_SETTINGS_TEMPLATE_ID: {
                    "EnableBannedPasswordCheckOnPremises": "True",
                    "BannedPasswordCheckOnPremisesMode": "Enforced",
                }
            }
        )
        assert result[0].status == "PASS"

    def test_audit_mode(self):
        result = self._run(
            {
                PASSWORD_RULE_SETTINGS_TEMPLATE_ID: {
                    "EnableBannedPasswordCheckOnPremises": "True",
                    "BannedPasswordCheckOnPremisesMode": "Audit",
                }
            }
        )
        assert result[0].status == "FAIL"
