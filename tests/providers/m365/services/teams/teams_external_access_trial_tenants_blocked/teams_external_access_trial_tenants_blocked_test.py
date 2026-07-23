from unittest import mock

from prowler.providers.m365.services.teams.teams_service import UserSettings
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.teams.teams_external_access_trial_tenants_blocked.teams_external_access_trial_tenants_blocked"


class Test_teams_external_access_trial_tenants_blocked:
    def _run(self, user_settings):
        teams_client = mock.MagicMock()
        teams_client.audited_domain = DOMAIN
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_microsoft_teams"
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.teams_client", new=teams_client),
        ):
            from prowler.providers.m365.services.teams.teams_external_access_trial_tenants_blocked.teams_external_access_trial_tenants_blocked import (
                teams_external_access_trial_tenants_blocked,
            )

            teams_client.user_settings = user_settings
            return teams_external_access_trial_tenants_blocked().execute()

    def test_no_user_settings(self):
        assert self._run(None) == []

    def test_trial_tenants_blocked(self):
        result = self._run(UserSettings(external_access_with_trial_tenants="Blocked"))
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "External access with Teams trial-only tenants is blocked."
        )

    def test_trial_tenants_allowed(self):
        result = self._run(UserSettings(external_access_with_trial_tenants="Allowed"))
        assert len(result) == 1
        assert result[0].status == "FAIL"
