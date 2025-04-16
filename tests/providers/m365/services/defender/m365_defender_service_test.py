from unittest import mock
from unittest.mock import patch

from prowler.providers.m365.models import M365IdentityInfo
from prowler.providers.m365.services.defender.defender_service import (
    Defender,
    DefenderMalwarePolicy,
    DefenderOutboundSpamPolicy,
    DefenderOutboundSpamRule,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


def mock_defender_get_malware_filter_policy(_):
    return [
        DefenderMalwarePolicy(enable_file_filter=False, identity="Policy1"),
        DefenderMalwarePolicy(enable_file_filter=True, identity="Policy2"),
    ]


def mock_defender_get_outbound_spam_filter_policy(_):
    return {
        "Policy1": DefenderOutboundSpamPolicy(
            notify_sender_blocked=True,
            notify_limit_exceeded=True,
            notify_limit_exceeded_adresses=["test@correo.com"],
            notify_sender_blocked_adresses=["test@correo.com"],
            default=False,
        ),
        "Policy2": DefenderOutboundSpamPolicy(
            notify_sender_blocked=False,
            notify_limit_exceeded=False,
            notify_limit_exceeded_adresses=[],
            notify_sender_blocked_adresses=[],
            default=True,
        ),
    }


def mock_defender_get_outbound_spam_filter_rule(_):
    return {
        "Policy1": DefenderOutboundSpamRule(
            state="Enabled",
        ),
        "Policy2": DefenderOutboundSpamRule(
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
    def test__get_malware_filter_policy(self):
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

    @patch(
        "prowler.providers.m365.services.defender.defender_service.Defender._get_outbound_spam_filter_policy",
        new=mock_defender_get_outbound_spam_filter_policy,
    )
    def test_get_outbound_spam_filter_policy(self):
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
            outbound_spam_policies = defender_client.outbound_spam_policies
            assert outbound_spam_policies["Policy1"].notify_sender_blocked is True
            assert outbound_spam_policies["Policy1"].notify_limit_exceeded is True
            assert outbound_spam_policies["Policy1"].notify_limit_exceeded_adresses == [
                "test@correo.com"
            ]
            assert outbound_spam_policies["Policy1"].notify_sender_blocked_adresses == [
                "test@correo.com"
            ]
            assert outbound_spam_policies["Policy1"].default is False
            assert outbound_spam_policies["Policy2"].notify_sender_blocked is False
            assert outbound_spam_policies["Policy2"].notify_limit_exceeded is False
            assert (
                outbound_spam_policies["Policy2"].notify_limit_exceeded_adresses == []
            )
            assert (
                outbound_spam_policies["Policy2"].notify_sender_blocked_adresses == []
            )
            assert outbound_spam_policies["Policy2"].default is True

    @patch(
        "prowler.providers.m365.services.defender.defender_service.Defender._get_outbound_spam_filter_rule",
        new=mock_defender_get_outbound_spam_filter_rule,
    )
    def test_get_outbound_spam_filter_rule(self):
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
            outbound_spam_rules = defender_client.outbound_spam_rules
            assert outbound_spam_rules["Policy1"].state == "Enabled"
            assert outbound_spam_rules["Policy2"].state == "Disabled"
