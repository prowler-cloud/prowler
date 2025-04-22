from unittest import mock
from unittest.mock import patch

from prowler.providers.m365.models import M365IdentityInfo
from prowler.providers.m365.services.teams.teams_service import (
    CloudStorageSettings,
    GlobalMeetingPolicy,
    Teams,
    TeamsSettings,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


def mock_get_teams_client_configuration(_):
    return TeamsSettings(
        cloud_storage_settings=CloudStorageSettings(
            allow_box=False,
            allow_drop_box=False,
            allow_egnyte=False,
            allow_google_drive=False,
            allow_share_file=False,
        )
    )


def mock_get_global_meeting_policy(_):
    return GlobalMeetingPolicy(allow_anonymous_users_to_join_meeting=False)


class Test_Teams_Service:
    def test_get_client(self):
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_microsoft_teams"
            ),
        ):
            teams_client = Teams(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )
            assert teams_client.client.__class__.__name__ == "GraphServiceClient"
            assert teams_client.powershell.__class__.__name__ == "M365PowerShell"
            teams_client.powershell.close()

    @patch(
        "prowler.providers.m365.services.teams.teams_service.Teams._get_teams_client_configuration",
        new=mock_get_teams_client_configuration,
    )
    def test_get_settings(self):
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_microsoft_teams"
            ),
        ):
            teams_client = Teams(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )
            assert teams_client.teams_settings == TeamsSettings(
                cloud_storage_settings=CloudStorageSettings(
                    allow_box=False,
                    allow_drop_box=False,
                    allow_egnyte=False,
                    allow_google_drive=False,
                    allow_share_file=False,
                )
            )
            teams_client.powershell.close()

    @patch(
        "prowler.providers.m365.services.teams.teams_service.Teams._get_global_meeting_policy",
        new=mock_get_global_meeting_policy,
    )
    def test_get_global_meeting_policy(self):
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_microsoft_teams"
            ),
        ):
            teams_client = Teams(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )
            assert teams_client.global_meeting_policy == GlobalMeetingPolicy(
                allow_anonymous_users_to_join_meeting=False
            )
            teams_client.powershell.close()
