from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_teams_meeting_recording_disabled:
    def test_no_global_meeting_policy(self):
        teams_client = mock.MagicMock()
        teams_client.global_meeting_policy = None
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
                "prowler.providers.m365.services.teams.teams_meeting_recording_disabled.teams_meeting_recording_disabled.teams_client",
                new=teams_client,
            ),
        ):
            from prowler.providers.m365.services.teams.teams_meeting_recording_disabled.teams_meeting_recording_disabled import (
                teams_meeting_recording_disabled,
            )

            check = teams_meeting_recording_disabled()
            result = check.execute()
            assert len(result) == 0

    def test_meeting_recording_enabled(self):
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
                "prowler.providers.m365.services.teams.teams_meeting_recording_disabled.teams_meeting_recording_disabled.teams_client",
                new=teams_client,
            ),
        ):
            from prowler.providers.m365.services.teams.teams_meeting_recording_disabled.teams_meeting_recording_disabled import (
                teams_meeting_recording_disabled,
            )
            from prowler.providers.m365.services.teams.teams_service import (
                GlobalMeetingPolicy,
            )

            teams_client.global_meeting_policy = GlobalMeetingPolicy(
                allow_cloud_recording=True
            )

            check = teams_meeting_recording_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended == "Meeting recording is enabled by default."
            )
            assert result[0].resource == teams_client.global_meeting_policy.dict()
            assert (
                result[0].resource_name
                == "Teams Meetings Global (Org-wide default) Policy"
            )
            assert result[0].resource_id == "teamsMeetingsGlobalPolicy"

    def test_meeting_recording_disabled(self):
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
                "prowler.providers.m365.services.teams.teams_meeting_recording_disabled.teams_meeting_recording_disabled.teams_client",
                new=teams_client,
            ),
        ):
            from prowler.providers.m365.services.teams.teams_meeting_recording_disabled.teams_meeting_recording_disabled import (
                teams_meeting_recording_disabled,
            )
            from prowler.providers.m365.services.teams.teams_service import (
                GlobalMeetingPolicy,
            )

            teams_client.global_meeting_policy = GlobalMeetingPolicy(
                allow_cloud_recording=False
            )

            check = teams_meeting_recording_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended == "Meeting recording is disabled by default."
            )
            assert result[0].resource == teams_client.global_meeting_policy.dict()
            assert (
                result[0].resource_name
                == "Teams Meetings Global (Org-wide default) Policy"
            )
            assert result[0].resource_id == "teamsMeetingsGlobalPolicy"
