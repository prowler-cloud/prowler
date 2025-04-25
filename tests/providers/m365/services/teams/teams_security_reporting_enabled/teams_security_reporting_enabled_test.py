from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_teams_security_reporting_enabled:
    def test_no_policies(self):
        teams_client = mock.MagicMock()
        teams_client.global_messaging_policy = None
        defender_client = mock.MagicMock()
        defender_client.report_submission_policy = None

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_microsoft_teams"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.teams.teams_security_reporting_enabled.teams_security_reporting_enabled.teams_client",
                new=teams_client,
            ),
            mock.patch(
                "prowler.providers.m365.services.teams.teams_security_reporting_enabled.teams_security_reporting_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.teams.teams_security_reporting_enabled.teams_security_reporting_enabled import (
                teams_security_reporting_enabled,
            )

            check = teams_security_reporting_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_security_reporting_properly_configured(self):
        teams_client = mock.MagicMock()
        teams_client.audited_tenant = "audited_tenant"
        teams_client.audited_domain = DOMAIN
        defender_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_microsoft_teams"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.teams.teams_security_reporting_enabled.teams_security_reporting_enabled.teams_client",
                new=teams_client,
            ),
            mock.patch(
                "prowler.providers.m365.services.teams.teams_security_reporting_enabled.teams_security_reporting_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_service import (
                ReportSubmissionPolicy,
            )
            from prowler.providers.m365.services.teams.teams_security_reporting_enabled.teams_security_reporting_enabled import (
                teams_security_reporting_enabled,
            )
            from prowler.providers.m365.services.teams.teams_service import (
                GlobalMessagingPolicy,
            )

            teams_client.global_messaging_policy = GlobalMessagingPolicy(
                allow_security_end_user_reporting=True
            )
            defender_client.report_submission_policy = ReportSubmissionPolicy(
                report_junk_to_customized_address=True,
                report_not_junk_to_customized_address=True,
                report_phish_to_customized_address=True,
                report_junk_addresses=["security@example.com"],
                report_not_junk_addresses=["security@example.com"],
                report_phish_addresses=["security@example.com"],
                report_chat_message_enabled=False,
                report_chat_message_to_customized_address_enabled=True,
            )

            check = teams_security_reporting_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Security reporting is properly configured in Teams and Defender settings."
            )
            assert result[0].resource_name == "Teams Security Reporting Settings"
            assert result[0].resource_id == "teamsSecurityReporting"

    def test_security_reporting_not_properly_configured(self):
        teams_client = mock.MagicMock()
        teams_client.audited_tenant = "audited_tenant"
        teams_client.audited_domain = DOMAIN
        defender_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_microsoft_teams"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.teams.teams_security_reporting_enabled.teams_security_reporting_enabled.teams_client",
                new=teams_client,
            ),
            mock.patch(
                "prowler.providers.m365.services.teams.teams_security_reporting_enabled.teams_security_reporting_enabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_service import (
                ReportSubmissionPolicy,
            )
            from prowler.providers.m365.services.teams.teams_security_reporting_enabled.teams_security_reporting_enabled import (
                teams_security_reporting_enabled,
            )
            from prowler.providers.m365.services.teams.teams_service import (
                GlobalMessagingPolicy,
            )

            teams_client.global_messaging_policy = GlobalMessagingPolicy(
                allow_security_end_user_reporting=True
            )
            defender_client.report_submission_policy = ReportSubmissionPolicy(
                report_junk_to_customized_address=False,
                report_not_junk_to_customized_address=False,
                report_phish_to_customized_address=False,
                report_junk_addresses=["security@example.com"],
                report_not_junk_addresses=[],
                report_phish_addresses=[],
                report_chat_message_enabled=False,
                report_chat_message_to_customized_address_enabled=True,
            )

            check = teams_security_reporting_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Security reporting is not properly configured in Teams and Defender settings."
            )
