from unittest import mock

from prowler.providers.m365.services.defender.defender_service import (
    ReportSubmissionPolicy,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_defender_chat_report_policy_configured:
    def test_report_policy_configured_pass(self):
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN
        defender_client.report_submission_policy = ReportSubmissionPolicy(
            report_junk_to_customized_address=True,
            report_not_junk_to_customized_address=True,
            report_phish_to_customized_address=True,
            report_junk_addresses=["address1"],
            report_not_junk_addresses=["address2"],
            report_phish_addresses=["address3"],
            report_chat_message_enabled=False,
            report_chat_message_to_customized_address_enabled=True,
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_chat_report_policy_configured.defender_chat_report_policy_configured.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_chat_report_policy_configured.defender_chat_report_policy_configured import (
                defender_chat_report_policy_configured,
            )

            check = defender_chat_report_policy_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Defender report submission policy is properly configured for Teams security reporting."
            )
            assert result[0].resource == defender_client.report_submission_policy.dict()
            assert result[0].resource_name == "Defender Security Reporting Policy"
            assert result[0].resource_id == "defenderSecurityReportingPolicy"
            assert result[0].location == "global"

    def test_report_policy_configured_fail(self):
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN
        defender_client.report_submission_policy = ReportSubmissionPolicy(
            report_junk_to_customized_address=False,
            report_not_junk_to_customized_address=True,
            report_phish_to_customized_address=True,
            report_junk_addresses=[],
            report_not_junk_addresses=[],
            report_phish_addresses=[],
            report_chat_message_enabled=True,
            report_chat_message_to_customized_address_enabled=False,
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_chat_report_policy_configured.defender_chat_report_policy_configured.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_chat_report_policy_configured.defender_chat_report_policy_configured import (
                defender_chat_report_policy_configured,
            )

            check = defender_chat_report_policy_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Defender report submission policy is not properly configured for Teams security reporting."
            )
            assert result[0].resource == defender_client.report_submission_policy.dict()
            assert result[0].resource_name == "Defender Security Reporting Policy"
            assert result[0].resource_id == "defenderSecurityReportingPolicy"
            assert result[0].location == "global"

    def test_report_policy_configured_none(self):
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN
        defender_client.report_submission_policy = None

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_chat_report_policy_configured.defender_chat_report_policy_configured.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_chat_report_policy_configured.defender_chat_report_policy_configured import (
                defender_chat_report_policy_configured,
            )

            check = defender_chat_report_policy_configured()
            result = check.execute()
            assert len(result) == 0
