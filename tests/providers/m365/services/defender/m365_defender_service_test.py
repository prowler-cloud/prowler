from unittest import mock
from unittest.mock import patch

from prowler.providers.m365.models import M365IdentityInfo
from prowler.providers.m365.services.defender.defender_service import (
    AntiphishingPolicy,
    AntiphishingRule,
    ConnectionFilterPolicy,
    Defender,
    DefenderInboundSpamPolicy,
    DkimConfig,
    MalwarePolicy,
    MalwareRule,
    OutboundSpamPolicy,
    OutboundSpamRule,
    ReportSubmissionPolicy,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


def mock_defender_get_malware_filter_policy(_):
    return [
        MalwarePolicy(
            enable_file_filter=False,
            identity="Policy1",
            enable_internal_sender_admin_notifications=False,
            internal_sender_admin_address="",
            file_types=[],
            is_default=True,
        ),
        MalwarePolicy(
            enable_file_filter=True,
            identity="Policy2",
            enable_internal_sender_admin_notifications=True,
            internal_sender_admin_address="security@example.com",
            file_types=["exe", "zip"],
            is_default=False,
        ),
    ]


def mock_defender_get_malware_filter_rule(_):
    return {
        "Policy1": MalwareRule(state="Enabled"),
        "Policy2": MalwareRule(state="Disabled"),
    }


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


def mock_defender_get_inbound_spam_policy(_):
    return [
        DefenderInboundSpamPolicy(
            identity="Policy1",
            allowed_sender_domains=[],
        ),
        DefenderInboundSpamPolicy(
            identity="Policy2",
            allowed_sender_domains=["example.com"],
        ),
    ]


def mock_defender_get_connection_filter_policy(_):
    return ConnectionFilterPolicy(
        ip_allow_list=[],
        identity="Default",
        enable_safe_list=False,
    )


def mock_defender_get_dkim_config(_):
    return [
        DkimConfig(dkim_signing_enabled=True, id="domain1"),
        DkimConfig(dkim_signing_enabled=False, id="domain2"),
    ]


def mock_defender_get_report_submission_policy(_):
    return ReportSubmissionPolicy(
        id="DefaultReportSubmissionPolicy",
        identity="DefaultReportSubmissionPolicy",
        name="DefaultReportSubmissionPolicy",
        report_junk_to_customized_address=True,
        report_not_junk_to_customized_address=True,
        report_phish_to_customized_address=True,
        report_junk_addresses=[],
        report_not_junk_addresses=[],
        report_phish_addresses=[],
        report_chat_message_enabled=True,
        report_chat_message_to_customized_address_enabled=True,
    )


def mock_defender_get_outbound_spam_filter_policy(_):
    return {
        "Policy1": OutboundSpamPolicy(
            notify_sender_blocked=True,
            notify_limit_exceeded=True,
            notify_limit_exceeded_addresses=["security@example.com"],
            notify_sender_blocked_addresses=["security@example.com"],
            auto_forwarding_mode=False,
            default=False,
        ),
        "Policy2": OutboundSpamPolicy(
            notify_sender_blocked=False,
            notify_limit_exceeded=False,
            notify_limit_exceeded_addresses=[],
            notify_sender_blocked_addresses=[],
            auto_forwarding_mode=True,
            default=True,
        ),
    }


def mock_defender_get_outbound_spam_filter_rule(_):
    return {
        "Policy1": OutboundSpamRule(
            state="Enabled",
        ),
        "Policy2": OutboundSpamRule(
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
            assert (
                malware_policies[0].enable_internal_sender_admin_notifications is False
            )
            assert malware_policies[0].internal_sender_admin_address == ""
            assert malware_policies[0].enable_file_filter is False
            assert malware_policies[0].identity == "Policy1"
            assert malware_policies[0].file_types == []
            assert malware_policies[0].is_default is True
            assert malware_policies[1].enable_file_filter is True
            assert malware_policies[1].identity == "Policy2"
            assert (
                malware_policies[1].enable_internal_sender_admin_notifications is True
            )
            assert (
                malware_policies[1].internal_sender_admin_address
                == "security@example.com"
            )
            assert malware_policies[1].file_types == ["exe", "zip"]
            assert malware_policies[1].is_default is False
            defender_client.powershell.close()

    @patch(
        "prowler.providers.m365.services.defender.defender_service.Defender._get_malware_filter_rule",
        new=mock_defender_get_malware_filter_rule,
    )
    def test__get_malware_filter_rule(self):
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
            malware_rules = defender_client.malware_rules
            assert malware_rules["Policy1"].state == "Enabled"
            assert malware_rules["Policy2"].state == "Disabled"
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

    @patch(
        "prowler.providers.m365.services.defender.defender_service.Defender._get_connection_filter_policy",
        new=mock_defender_get_connection_filter_policy,
    )
    def test__get_connection_filter_policy(self):
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
            connection_filter_policy = defender_client.connection_filter_policy
            assert connection_filter_policy.ip_allow_list == []
            assert connection_filter_policy.identity == "Default"
            assert connection_filter_policy.enable_safe_list is False
            defender_client.powershell.close()

    @patch(
        "prowler.providers.m365.services.defender.defender_service.Defender._get_dkim_config",
        new=mock_defender_get_dkim_config,
    )
    def test_get_dkim_config(self):
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
            dkim_configs = defender_client.dkim_configurations
            assert dkim_configs[0].dkim_signing_enabled is True
            assert dkim_configs[0].id == "domain1"
            assert dkim_configs[1].dkim_signing_enabled is False
            assert dkim_configs[1].id == "domain2"
            defender_client.powershell.close()

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
            assert outbound_spam_policies[
                "Policy1"
            ].notify_limit_exceeded_addresses == ["security@example.com"]
            assert outbound_spam_policies[
                "Policy1"
            ].notify_sender_blocked_addresses == ["security@example.com"]
            assert outbound_spam_policies["Policy1"].auto_forwarding_mode is False
            assert outbound_spam_policies["Policy1"].default is False
            assert outbound_spam_policies["Policy2"].notify_sender_blocked is False
            assert outbound_spam_policies["Policy2"].notify_limit_exceeded is False
            assert (
                outbound_spam_policies["Policy2"].notify_limit_exceeded_addresses == []
            )
            assert (
                outbound_spam_policies["Policy2"].notify_sender_blocked_addresses == []
            )
            assert outbound_spam_policies["Policy2"].auto_forwarding_mode is True
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

    @patch(
        "prowler.providers.m365.services.defender.defender_service.Defender._get_inbound_spam_filter_policy",
        new=mock_defender_get_inbound_spam_policy,
    )
    def test__get_inbound_spam_filter_policy(self):
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
            inbound_spam_policies = defender_client.inbound_spam_policies
            assert inbound_spam_policies[0].allowed_sender_domains == []
            assert inbound_spam_policies[1].allowed_sender_domains == ["example.com"]
            defender_client.powershell.close()

    @patch(
        "prowler.providers.m365.services.defender.defender_service.Defender._get_report_submission_policy",
        new=mock_defender_get_report_submission_policy,
    )
    def test_get_report_submission_policy(self):
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
            report_submission_policy = defender_client.report_submission_policy
            assert report_submission_policy.report_junk_to_customized_address is True
            assert (
                report_submission_policy.report_not_junk_to_customized_address is True
            )
            assert report_submission_policy.report_phish_to_customized_address is True
            assert report_submission_policy.report_junk_addresses == []
            assert report_submission_policy.report_not_junk_addresses == []
            assert report_submission_policy.report_phish_addresses == []
            assert report_submission_policy.report_chat_message_enabled is True
