from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.admincenter.admincenter_office_store_apps_restricted.admincenter_office_store_apps_restricted"


def _make_settings(office_store_enabled, app_and_services_trial_enabled):
    from prowler.providers.m365.services.admincenter.admincenter_service import (
        AppsAndServicesSettings,
    )

    return AppsAndServicesSettings(
        office_store_enabled=office_store_enabled,
        app_and_services_trial_enabled=app_and_services_trial_enabled,
    )


class Test_admincenter_office_store_apps_restricted:
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
            from prowler.providers.m365.services.admincenter.admincenter_office_store_apps_restricted.admincenter_office_store_apps_restricted import (
                admincenter_office_store_apps_restricted,
            )

            admincenter_client.apps_and_services_settings = settings
            return admincenter_office_store_apps_restricted().execute()

    def test_no_settings(self):
        assert self._run(None) == []

    def test_both_disabled(self):
        result = self._run(_make_settings(False, False))
        assert result[0].status == "PASS"

    def test_store_enabled(self):
        result = self._run(_make_settings(True, False))
        assert result[0].status == "FAIL"
