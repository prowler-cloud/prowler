from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.defender.defender_priority_account_protection_enabled.defender_priority_account_protection_enabled"


def _settings(enabled):
    from prowler.providers.m365.services.defender.defender_service import (
        EmailTenantSettings,
    )

    return EmailTenantSettings(priority_account_protection_enabled=enabled)


class Test_defender_priority_account_protection_enabled:
    def _run(self, settings):
        defender_client = mock.MagicMock()
        defender_client.audited_domain = DOMAIN
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.defender_client", new=defender_client),
        ):
            from prowler.providers.m365.services.defender.defender_priority_account_protection_enabled.defender_priority_account_protection_enabled import (
                defender_priority_account_protection_enabled,
            )

            defender_client.email_tenant_settings = settings
            return defender_priority_account_protection_enabled().execute()

    def test_no_settings(self):
        assert self._run(None) == []

    def test_enabled(self):
        result = self._run(_settings(True))
        assert result[0].status == "PASS"

    def test_disabled(self):
        result = self._run(_settings(False))
        assert result[0].status == "FAIL"
