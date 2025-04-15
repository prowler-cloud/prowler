from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_teams_email_sending_to_channel_disabled:
    def test_email_sending_to_channel_no_restricted(self):
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
                "prowler.providers.m365.services.teams.teams_email_sending_to_channel_disabled.teams_email_sending_to_channel_disabled.teams_client",
                new=teams_client,
            ),
        ):
            from prowler.providers.m365.services.teams.teams_email_sending_to_channel_disabled.teams_email_sending_to_channel_disabled import (
                teams_email_sending_to_channel_disabled,
            )
            from prowler.providers.m365.services.teams.teams_service import (
                CloudStorageSettings,
                TeamsSettings,
            )

            teams_client.teams_settings = TeamsSettings(
                cloud_storage_settings=CloudStorageSettings(
                    allow_box=True,
                    allow_drop_box=True,
                    allow_egnyte=True,
                    allow_google_drive=True,
                    allow_share_file=True,
                ),
                allow_email_into_channel=True,
            )

            check = teams_email_sending_to_channel_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Users can send emails to channel email addresses."
            )
            assert (
                result[0].resource
                == teams_client.teams_settings.cloud_storage_settings.dict()
            )
            assert result[0].resource_name == "Teams Settings"
            assert result[0].resource_id == "teamsSettings"
            assert result[0].location == "global"

    def test_email_sending_to_channel_restricted(self):
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
                "prowler.providers.m365.services.teams.teams_email_sending_to_channel_disabled.teams_email_sending_to_channel_disabled.teams_client",
                new=teams_client,
            ),
        ):
            from prowler.providers.m365.services.teams.teams_email_sending_to_channel_disabled.teams_email_sending_to_channel_disabled import (
                teams_email_sending_to_channel_disabled,
            )
            from prowler.providers.m365.services.teams.teams_service import (
                CloudStorageSettings,
                TeamsSettings,
            )

            teams_client.teams_settings = TeamsSettings(
                cloud_storage_settings=CloudStorageSettings(
                    allow_box=True,
                    allow_drop_box=True,
                    allow_egnyte=True,
                    allow_google_drive=True,
                    allow_share_file=True,
                ),
                allow_email_into_channel=False,
            )

            check = teams_email_sending_to_channel_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Users can not send emails to channel email addresses."
            )
            assert (
                result[0].resource
                == teams_client.teams_settings.cloud_storage_settings.dict()
            )
            assert result[0].resource_name == "Teams Settings"
            assert result[0].resource_id == "teamsSettings"
            assert result[0].location == "global"
