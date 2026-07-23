from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    PASSWORD_RULE_SETTINGS_TEMPLATE_ID,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_password_protection_custom_banned_list_enforced.entra_password_protection_custom_banned_list_enforced"


class Test_entra_password_protection_custom_banned_list_enforced:
    def _run(self, directory_settings):
        entra_client = mock.MagicMock
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_password_protection_custom_banned_list_enforced.entra_password_protection_custom_banned_list_enforced import (
                entra_password_protection_custom_banned_list_enforced,
            )

            entra_client.directory_settings = directory_settings
            return entra_password_protection_custom_banned_list_enforced().execute()

    def test_template_absent(self):
        result = self._run({})
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_enforced_with_list(self):
        result = self._run(
            {
                PASSWORD_RULE_SETTINGS_TEMPLATE_ID: {
                    "EnableBannedPasswordCheck": "True",
                    "BannedPasswordList": "contoso\nproduct",
                }
            }
        )
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_enforced_but_empty(self):
        result = self._run(
            {
                PASSWORD_RULE_SETTINGS_TEMPLATE_ID: {
                    "EnableBannedPasswordCheck": "True",
                    "BannedPasswordList": "",
                }
            }
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_not_enforced(self):
        result = self._run(
            {
                PASSWORD_RULE_SETTINGS_TEMPLATE_ID: {
                    "EnableBannedPasswordCheck": "False",
                    "BannedPasswordList": "contoso",
                }
            }
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
