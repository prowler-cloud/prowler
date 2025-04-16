from unittest import mock
from unittest.mock import patch

from prowler.providers.m365.models import M365IdentityInfo
from prowler.providers.m365.services.defender.defender_service import (
    AntiphishingPolicy,
    AntiphishingRule,
    Defender,
    DefenderMalwarePolicy,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


def mock_defender_get_malware_filter_policy(_):
    return [
        DefenderMalwarePolicy(enable_file_filter=False, identity="Policy1"),
        DefenderMalwarePolicy(enable_file_filter=True, identity="Policy2"),
    ]


def mock_defender_get_antiphising_policy(_):
    return {
        "Policy1": AntiphishingPolicy(
            spoof_intelligence=True,
            spoof_intelligence_action="Quarantine",
            dmarc_reject_action="Reject",
            dmarc_quarantine_action="Quarantine",
            safety_tips=True,
            unauthenticated_sender_action=True,
            show_tag=True,
            honor_dmarc_policy=True,
            default=False,
        ),
        "Policy2": AntiphishingPolicy(
            spoof_intelligence=False,
            spoof_intelligence_action="None",
            dmarc_reject_action="None",
            dmarc_quarantine_action="None",
            safety_tips=False,
            unauthenticated_sender_action=False,
            show_tag=False,
            honor_dmarc_policy=False,
            default=True,
        ),
    }


def mock_defender_get_antiphising_rules(_):
    return {
        "Policy1": AntiphishingRule(
            state="Enabled",
        ),
        "Policy2": AntiphishingRule(
            state="Disabled",
        ),
    }


class Test_Defender_Service:
    def test_get_client(self):
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
        ):
            defender_client = Defender(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )
            assert defender_client.client.__class__.__name__ == "GraphServiceClient"
            assert defender_client.powershell.__class__.__name__ == "M365PowerShell"
            defender_client.powershell.close()

    @patch(
        "prowler.providers.m365.services.defender.defender_service.Defender._get_malware_filter_policy",
        new=mock_defender_get_malware_filter_policy,
    )
    def test_get_malware_filter_policy(self):
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
        ):
            defender_client = Defender(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )
            malware_policies = defender_client.malware_policies
            assert malware_policies[0].enable_file_filter is False
            assert malware_policies[0].identity == "Policy1"
            assert malware_policies[1].enable_file_filter is True
            assert malware_policies[1].identity == "Policy2"
            defender_client.powershell.close()

    @patch(
        "prowler.providers.m365.services.defender.defender_service.Defender._get_antiphising_policy",
        new=mock_defender_get_antiphising_policy,
    )
    def test_get_antiphising_policy(self):
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
        ):
            defender_client = Defender(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )
            antiphishing_policies = defender_client.antiphishing_policies
            assert antiphishing_policies["Policy1"].spoof_intelligence is True
            assert (
                antiphishing_policies["Policy1"].spoof_intelligence_action
                == "Quarantine"
            )
            assert antiphishing_policies["Policy1"].dmarc_reject_action == "Reject"
            assert (
                antiphishing_policies["Policy1"].dmarc_quarantine_action == "Quarantine"
            )
            assert antiphishing_policies["Policy1"].safety_tips is True
            assert (
                antiphishing_policies["Policy1"].unauthenticated_sender_action is True
            )
            assert antiphishing_policies["Policy1"].show_tag is True
            assert antiphishing_policies["Policy1"].honor_dmarc_policy is True
            assert antiphishing_policies["Policy1"].default is False
            assert antiphishing_policies["Policy2"].spoof_intelligence is False
            assert antiphishing_policies["Policy2"].spoof_intelligence_action == "None"
            assert antiphishing_policies["Policy2"].dmarc_reject_action == "None"
            assert antiphishing_policies["Policy2"].dmarc_quarantine_action == "None"
            assert antiphishing_policies["Policy2"].safety_tips is False
            assert (
                antiphishing_policies["Policy2"].unauthenticated_sender_action is False
            )
            assert antiphishing_policies["Policy2"].show_tag is False
            assert antiphishing_policies["Policy2"].honor_dmarc_policy is False
            assert antiphishing_policies["Policy2"].default is True
            defender_client.powershell.close()

    @patch(
        "prowler.providers.m365.services.defender.defender_service.Defender._get_antiphising_rules",
        new=mock_defender_get_antiphising_rules,
    )
    def test_get_antiphising_rules(self):
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
        ):
            defender_client = Defender(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )
            antiphishing_rules = defender_client.antiphising_rules
            assert antiphishing_rules["Policy1"].state == "Enabled"
            assert antiphishing_rules["Policy2"].state == "Disabled"
            defender_client.powershell.close()
