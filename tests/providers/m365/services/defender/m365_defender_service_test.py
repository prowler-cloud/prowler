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
    InboundSpamRule,
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
        "Policy1": MalwareRule(
            state="Enabled",
            priority=1,
            users=["test@example.com"],
            groups=["example_group"],
            domains=["example.com"],
        ),
        "Policy2": MalwareRule(
            state="Disabled",
            priority=2,
            users=["test@example.com"],
            groups=["example_group"],
            domains=["example.com"],
        ),
    }


def mock_defender_get_antiphishing_policy(_):
    return {
        "Policy1": AntiphishingPolicy(
            name="Policy1",
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
            name="Policy2",
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


def mock_defender_get_antiphishing_rules(_):
    return {
        "Policy1": AntiphishingRule(
            state="Enabled",
            priority=1,
            users=["test@example.com"],
            groups=["example_group"],
            domains=["example.com"],
        ),
        "Policy2": AntiphishingRule(
            state="Disabled",
            priority=2,
            users=["test@example.com"],
            groups=["example_group"],
            domains=["example.com"],
        ),
    }


def mock_defender_get_inbound_spam_policy(_):
    return [
        DefenderInboundSpamPolicy(
            identity="Policy1",
            allowed_sender_domains=[],
            default=False,
        ),
        DefenderInboundSpamPolicy(
            identity="Policy2",
            allowed_sender_domains=["example.com"],
            default=True,
        ),
    ]


def mock_defender_get_inbound_spam_rule(_):
    return {
        "Policy1": InboundSpamRule(
            state="Enabled",
            priority=1,
            users=["test@example.com"],
            groups=["example_group"],
            domains=["example.com"],
        ),
        "Policy2": InboundSpamRule(
            state="Disabled",
            priority=2,
            users=["test@example.com"],
            groups=["example_group"],
            domains=["example.com"],
        ),
    }


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
            name="Policy1",
            notify_sender_blocked=True,
            notify_limit_exceeded=True,
            notify_limit_exceeded_addresses=["security@example.com"],
            notify_sender_blocked_addresses=["security@example.com"],
            auto_forwarding_mode="Off",
            default=False,
        ),
        "Policy2": OutboundSpamPolicy(
            name="Policy2",
            notify_sender_blocked=False,
            notify_limit_exceeded=False,
            notify_limit_exceeded_addresses=[],
            notify_sender_blocked_addresses=[],
            auto_forwarding_mode="On",
            default=True,
        ),
    }


def mock_defender_get_outbound_spam_filter_rule(_):
    return {
        "Policy1": OutboundSpamRule(
            state="Enabled",
            priority=1,
            users=["test@example.com"],
            groups=["example_group"],
            domains=["example.com"],
        ),
        "Policy2": OutboundSpamRule(
            state="Disabled",
            priority=2,
            users=["test@example.com"],
            groups=["example_group"],
            domains=["example.com"],
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
            assert malware_rules["Policy1"].priority == 1
            assert malware_rules["Policy1"].users == ["test@example.com"]
            assert malware_rules["Policy1"].groups == ["example_group"]
            assert malware_rules["Policy1"].domains == ["example.com"]
            assert malware_rules["Policy2"].state == "Disabled"
            assert malware_rules["Policy2"].priority == 2
            assert malware_rules["Policy2"].users == ["test@example.com"]
            assert malware_rules["Policy2"].groups == ["example_group"]
            assert malware_rules["Policy2"].domains == ["example.com"]
            defender_client.powershell.close()

    @patch(
        "prowler.providers.m365.services.defender.defender_service.Defender._get_antiphishing_policy",
        new=mock_defender_get_antiphishing_policy,
    )
    def test_get_antiphishing_policy(self):
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
            assert antiphishing_policies["Policy1"].name == "Policy1"
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
            assert antiphishing_policies["Policy2"].name == "Policy2"
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
        "prowler.providers.m365.services.defender.defender_service.Defender._get_antiphishing_rules",
        new=mock_defender_get_antiphishing_rules,
    )
    def test_get_antiphishing_rules(self):
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
            antiphishing_rules = defender_client.antiphishing_rules
            assert antiphishing_rules["Policy1"].state == "Enabled"
            assert antiphishing_rules["Policy1"].priority == 1
            assert antiphishing_rules["Policy1"].users == ["test@example.com"]
            assert antiphishing_rules["Policy1"].groups == ["example_group"]
            assert antiphishing_rules["Policy1"].domains == ["example.com"]
            assert antiphishing_rules["Policy2"].state == "Disabled"
            assert antiphishing_rules["Policy2"].priority == 2
            assert antiphishing_rules["Policy2"].users == ["test@example.com"]
            assert antiphishing_rules["Policy2"].groups == ["example_group"]
            assert antiphishing_rules["Policy2"].domains == ["example.com"]
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
            assert outbound_spam_policies["Policy1"].name == "Policy1"
            assert outbound_spam_policies["Policy1"].notify_sender_blocked is True
            assert outbound_spam_policies["Policy1"].notify_limit_exceeded is True
            assert outbound_spam_policies[
                "Policy1"
            ].notify_limit_exceeded_addresses == ["security@example.com"]
            assert outbound_spam_policies[
                "Policy1"
            ].notify_sender_blocked_addresses == ["security@example.com"]
            assert outbound_spam_policies["Policy1"].auto_forwarding_mode == "Off"
            assert outbound_spam_policies["Policy1"].default is False
            assert outbound_spam_policies["Policy2"].name == "Policy2"
            assert outbound_spam_policies["Policy2"].notify_sender_blocked is False
            assert outbound_spam_policies["Policy2"].notify_limit_exceeded is False
            assert (
                outbound_spam_policies["Policy2"].notify_limit_exceeded_addresses == []
            )
            assert (
                outbound_spam_policies["Policy2"].notify_sender_blocked_addresses == []
            )
            assert outbound_spam_policies["Policy2"].auto_forwarding_mode == "On"
            assert outbound_spam_policies["Policy2"].default is True
            defender_client.powershell.close()

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
            assert outbound_spam_rules["Policy1"].priority == 1
            assert outbound_spam_rules["Policy1"].users == ["test@example.com"]
            assert outbound_spam_rules["Policy1"].groups == ["example_group"]
            assert outbound_spam_rules["Policy1"].domains == ["example.com"]
            assert outbound_spam_rules["Policy2"].state == "Disabled"
            assert outbound_spam_rules["Policy2"].priority == 2
            assert outbound_spam_rules["Policy2"].users == ["test@example.com"]
            assert outbound_spam_rules["Policy2"].groups == ["example_group"]
            assert outbound_spam_rules["Policy2"].domains == ["example.com"]
            defender_client.powershell.close()

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
        "prowler.providers.m365.services.defender.defender_service.Defender._get_inbound_spam_filter_rule",
        new=mock_defender_get_inbound_spam_rule,
    )
    def test__get_inbound_spam_filter_rule(self):
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
            inbound_spam_rules = defender_client.inbound_spam_rules
            assert inbound_spam_rules["Policy1"].state == "Enabled"
            assert inbound_spam_rules["Policy1"].priority == 1
            assert inbound_spam_rules["Policy1"].users == ["test@example.com"]
            assert inbound_spam_rules["Policy1"].groups == ["example_group"]
            assert inbound_spam_rules["Policy1"].domains == ["example.com"]
            assert inbound_spam_rules["Policy2"].state == "Disabled"
            assert inbound_spam_rules["Policy2"].priority == 2
            assert inbound_spam_rules["Policy2"].users == ["test@example.com"]
            assert inbound_spam_rules["Policy2"].groups == ["example_group"]
            assert inbound_spam_rules["Policy2"].domains == ["example.com"]
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
            assert (
                report_submission_policy.report_chat_message_to_customized_address_enabled
                is True
            )
            defender_client.powershell.close()

    def test_get_antiphishing_policy_with_string_data(self):
        """Test that _get_antiphishing_policy handles string data gracefully and logs warning"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_antiphishing_policy",
                return_value=[
                    "Policy1",
                    "Policy2",
                ],  # Return list of strings instead of dicts
            ),
            mock.patch("prowler.lib.logger.logger.warning") as mock_warning,
        ):
            defender_client = Defender(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return empty dict since no valid policies were processed
            antiphishing_policies = defender_client.antiphishing_policies
            assert antiphishing_policies == {}

            # Should log warning for each string item
            assert mock_warning.call_count == 2
            mock_warning.assert_any_call(
                "Skipping invalid antiphishing policy data type: <class 'str'> - Policy1"
            )
            mock_warning.assert_any_call(
                "Skipping invalid antiphishing policy data type: <class 'str'> - Policy2"
            )

            defender_client.powershell.close()

    def test_get_antiphishing_policy_with_mixed_data(self):
        """Test that _get_antiphishing_policy handles mixed dict and string data"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_antiphishing_policy",
                return_value=[
                    {
                        "Name": "ValidPolicy",
                        "EnableSpoofIntelligence": True,
                        "IsDefault": False,
                    },
                    "InvalidStringPolicy",
                ],
            ),
            mock.patch("prowler.lib.logger.logger.warning") as mock_warning,
        ):
            defender_client = Defender(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should process valid dict and skip string
            antiphishing_policies = defender_client.antiphishing_policies
            assert len(antiphishing_policies) == 1
            assert "ValidPolicy" in antiphishing_policies

            # Should log warning only for the string item
            mock_warning.assert_called_once_with(
                "Skipping invalid antiphishing policy data type: <class 'str'> - InvalidStringPolicy"
            )

            defender_client.powershell.close()

    def test_get_antiphishing_rules_with_string_data(self):
        """Test that _get_antiphishing_rules handles string data gracefully and logs warning"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_antiphishing_rules",
                return_value=[
                    "Rule1",
                    "Rule2",
                ],  # Return list of strings instead of dicts
            ),
            mock.patch("prowler.lib.logger.logger.warning") as mock_warning,
        ):
            defender_client = Defender(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return empty dict since no valid rules were processed
            antiphishing_rules = defender_client.antiphishing_rules
            assert antiphishing_rules == {}

            # Should log warning for each string item
            assert mock_warning.call_count == 2
            mock_warning.assert_any_call(
                "Skipping invalid antiphishing rule data type: <class 'str'> - Rule1"
            )
            mock_warning.assert_any_call(
                "Skipping invalid antiphishing rule data type: <class 'str'> - Rule2"
            )

            defender_client.powershell.close()

    def test_get_malware_filter_rule_with_string_data(self):
        """Test that _get_malware_filter_rule handles string data gracefully and logs warning"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_malware_filter_rule",
                return_value=[
                    "MalwareRule1",
                    "MalwareRule2",
                ],  # Return list of strings instead of dicts
            ),
            mock.patch("prowler.lib.logger.logger.warning") as mock_warning,
        ):
            defender_client = Defender(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return empty dict since no valid rules were processed
            malware_rules = defender_client.malware_rules
            assert malware_rules == {}

            # Should log warning for each string item
            assert mock_warning.call_count == 2
            mock_warning.assert_any_call(
                "Skipping invalid malware rule data type: <class 'str'> - MalwareRule1"
            )
            mock_warning.assert_any_call(
                "Skipping invalid malware rule data type: <class 'str'> - MalwareRule2"
            )

            defender_client.powershell.close()

    def test_get_outbound_spam_filter_rule_with_string_data(self):
        """Test that _get_outbound_spam_filter_rule handles string data gracefully and logs warning"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_outbound_spam_filter_rule",
                return_value=[
                    "OutboundRule1",
                    "OutboundRule2",
                ],  # Return list of strings instead of dicts
            ),
            mock.patch("prowler.lib.logger.logger.warning") as mock_warning,
        ):
            defender_client = Defender(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return empty dict since no valid rules were processed
            outbound_spam_rules = defender_client.outbound_spam_rules
            assert outbound_spam_rules == {}

            # Should log warning for each string item
            assert mock_warning.call_count == 2
            mock_warning.assert_any_call(
                "Skipping invalid outbound spam rule data type: <class 'str'> - OutboundRule1"
            )
            mock_warning.assert_any_call(
                "Skipping invalid outbound spam rule data type: <class 'str'> - OutboundRule2"
            )

            defender_client.powershell.close()

    def test_get_inbound_spam_filter_rule_with_string_data(self):
        """Test that _get_inbound_spam_filter_rule handles string data gracefully and logs warning"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_inbound_spam_filter_rule",
                return_value=[
                    "InboundRule1",
                    "InboundRule2",
                ],  # Return list of strings instead of dicts
            ),
            mock.patch("prowler.lib.logger.logger.warning") as mock_warning,
        ):
            defender_client = Defender(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return empty dict since no valid rules were processed
            inbound_spam_rules = defender_client.inbound_spam_rules
            assert inbound_spam_rules == {}

            # Should log warning for each string item
            assert mock_warning.call_count == 2
            mock_warning.assert_any_call(
                "Skipping invalid inbound spam rule data type: <class 'str'> - InboundRule1"
            )
            mock_warning.assert_any_call(
                "Skipping invalid inbound spam rule data type: <class 'str'> - InboundRule2"
            )

            defender_client.powershell.close()

    def test_get_connection_filter_policy_with_string_data(self):
        """Test that _get_connection_filter_policy handles string data gracefully and logs warning"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_connection_filter_policy",
                return_value="InvalidStringPolicy",  # Return string instead of dict
            ),
            mock.patch("prowler.lib.logger.logger.warning") as mock_warning,
        ):
            defender_client = Defender(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return None since no valid policy was processed
            connection_filter_policy = defender_client.connection_filter_policy
            assert connection_filter_policy is None

            # Should log warning for the string item
            mock_warning.assert_called_once_with(
                "Skipping invalid connection filter policy data type: <class 'str'> - InvalidStringPolicy"
            )

            defender_client.powershell.close()

    def test_get_dkim_config_with_string_data(self):
        """Test that _get_dkim_config handles string data gracefully and logs warning"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_dkim_config",
                return_value=[
                    "DKIMConfig1",
                    "DKIMConfig2",
                ],  # Return list of strings instead of dicts
            ),
            mock.patch("prowler.lib.logger.logger.warning") as mock_warning,
        ):
            defender_client = Defender(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return empty list since no valid configs were processed
            dkim_configs = defender_client.dkim_configurations
            assert dkim_configs == []

            # Should log warning for each string item
            assert mock_warning.call_count == 2
            mock_warning.assert_any_call(
                "Skipping invalid DKIM config data type: <class 'str'> - DKIMConfig1"
            )
            mock_warning.assert_any_call(
                "Skipping invalid DKIM config data type: <class 'str'> - DKIMConfig2"
            )

            defender_client.powershell.close()

    def test_get_inbound_spam_filter_policy_with_string_data(self):
        """Test that _get_inbound_spam_filter_policy handles string data gracefully and logs warning"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_inbound_spam_filter_policy",
                return_value=[
                    "InboundPolicy1",
                    "InboundPolicy2",
                ],  # Return list of strings instead of dicts
            ),
            mock.patch("prowler.lib.logger.logger.warning") as mock_warning,
        ):
            defender_client = Defender(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return empty list since no valid policies were processed
            inbound_spam_policies = defender_client.inbound_spam_policies
            assert inbound_spam_policies == []

            # Should log warning for each string item
            assert mock_warning.call_count == 2
            mock_warning.assert_any_call(
                "Skipping invalid inbound spam policy data type: <class 'str'> - InboundPolicy1"
            )
            mock_warning.assert_any_call(
                "Skipping invalid inbound spam policy data type: <class 'str'> - InboundPolicy2"
            )

            defender_client.powershell.close()

    def test_get_report_submission_policy_with_string_data(self):
        """Test that _get_report_submission_policy handles string data gracefully and logs warning"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_report_submission_policy",
                return_value="InvalidStringPolicy",  # Return string instead of dict
            ),
            mock.patch("prowler.lib.logger.logger.warning") as mock_warning,
        ):
            defender_client = Defender(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return None since no valid policy was processed
            report_submission_policy = defender_client.report_submission_policy
            assert report_submission_policy is None

            # Should log warning for the string item
            mock_warning.assert_called_once_with(
                "Skipping invalid report submission policy data type: <class 'str'> - InvalidStringPolicy"
            )

            defender_client.powershell.close()
