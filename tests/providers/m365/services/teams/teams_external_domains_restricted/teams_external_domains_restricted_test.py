from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_teams_external_domains_restricted:
    def test_no_user_settings(self):
        teams_client = mock.MagicMock()
        teams_client.audited_tenant = "audited_tenant"
        teams_client.audited_domain = DOMAIN
        teams_client.user_settings = None

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_microsoft_teams"
            ),
            mock.patch(
                "prowler.providers.m365.services.teams.teams_external_domains_restricted.teams_external_domains_restricted.teams_client",
                new=teams_client,
            ),
        ):
            from prowler.providers.m365.services.teams.teams_external_domains_restricted.teams_external_domains_restricted import (
                teams_external_domains_restricted,
            )

            check = teams_external_domains_restricted()
            result = check.execute()
            assert len(result) == 0

    def test_external_domains_allowed(self):
        teams_client = mock.MagicMock()
        teams_client.audited_tenant = "audited_tenant"
        teams_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_microsoft_teams"
            ),
            mock.patch(
                "prowler.providers.m365.services.teams.teams_external_domains_restricted.teams_external_domains_restricted.teams_client",
                new=teams_client,
            ),
        ):
            from prowler.providers.m365.services.teams.teams_external_domains_restricted.teams_external_domains_restricted import (
                teams_external_domains_restricted,
            )
            from prowler.providers.m365.services.teams.teams_service import UserSettings

            teams_client.user_settings = UserSettings(
                allow_external_access=True,
            )

            check = teams_external_domains_restricted()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == "Users can access external domains."
            assert result[0].resource == teams_client.user_settings.dict()
            assert result[0].resource_name == "Teams User Settings"
            assert result[0].resource_id == "userSettings"
            assert result[0].location == "global"

    def test_external_domains_restricted(self):
        teams_client = mock.MagicMock()
        teams_client.audited_tenant = "audited_tenant"
        teams_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_microsoft_teams"
            ),
            mock.patch(
                "prowler.providers.m365.services.teams.teams_external_domains_restricted.teams_external_domains_restricted.teams_client",
                new=teams_client,
            ),
        ):
            from prowler.providers.m365.services.teams.teams_external_domains_restricted.teams_external_domains_restricted import (
                teams_external_domains_restricted,
            )
            from prowler.providers.m365.services.teams.teams_service import UserSettings

            teams_client.user_settings = UserSettings(
                allow_external_access=False,
            )

            check = teams_external_domains_restricted()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == "Users can not access external domains."
            assert result[0].resource == teams_client.user_settings.dict()
            assert result[0].resource_name == "Teams User Settings"
            assert result[0].resource_id == "userSettings"
            assert result[0].location == "global"
