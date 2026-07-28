from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.admincenter.admincenter_forms_phishing_protection_enabled.admincenter_forms_phishing_protection_enabled"


def _make_settings(enabled):
    from prowler.providers.m365.services.admincenter.admincenter_service import (
        FormsSettings,
    )

    return FormsSettings(in_org_forms_phishing_scan_enabled=enabled)


class Test_admincenter_forms_phishing_protection_enabled:
    def _run(self, settings):
        admincenter_client = mock.MagicMock()
        admincenter_client.audited_domain = DOMAIN
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.admincenter_client", new=admincenter_client
            ),
        ):
            from prowler.providers.m365.services.admincenter.admincenter_forms_phishing_protection_enabled.admincenter_forms_phishing_protection_enabled import (
                admincenter_forms_phishing_protection_enabled,
            )

            admincenter_client.forms_settings = settings
            return admincenter_forms_phishing_protection_enabled().execute()

    def test_no_settings(self):
        assert self._run(None) == []

    def test_enabled(self):
        result = self._run(_make_settings(True))
        assert result[0].status == "PASS"

    def test_disabled(self):
        result = self._run(_make_settings(False))
        assert result[0].status == "FAIL"
