from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_defender_antispam_outbound_policy_forwarding_disabled:
    def test_no_outbound_spam_policies(self):
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_antispam_outbound_policy_forwarding_disabled.defender_antispam_outbound_policy_forwarding_disabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_antispam_outbound_policy_forwarding_disabled.defender_antispam_outbound_policy_forwarding_disabled import (
                defender_antispam_outbound_policy_forwarding_disabled,
            )

            defender_client.outbound_spam_policies = {}
            defender_client.outbound_spam_rules = {}

            check = defender_antispam_outbound_policy_forwarding_disabled()
            result = check.execute()
            assert len(result) == 0

    def test_forwarding_disabled_custom_policy(self):
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_antispam_outbound_policy_forwarding_disabled.defender_antispam_outbound_policy_forwarding_disabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_antispam_outbound_policy_forwarding_disabled.defender_antispam_outbound_policy_forwarding_disabled import (
                defender_antispam_outbound_policy_forwarding_disabled,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                OutboundSpamPolicy,
                OutboundSpamRule,
            )

            defender_client.outbound_spam_policies = {
                "Policy1": OutboundSpamPolicy(
                    default=False,
                    notify_sender_blocked=True,
                    notify_limit_exceeded=True,
                    notify_limit_exceeded_addresses=["test@correo.com"],
                    notify_sender_blocked_addresses=["test@correo.com"],
                    auto_forwarding_mode=False,
                )
            }
            defender_client.outbound_spam_rules = {
                "Policy1": OutboundSpamRule(state="Enabled")
            }

            check = defender_antispam_outbound_policy_forwarding_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Outbound Spam Policy Policy1 does not allow mail forwarding."
            )
            assert (
                result[0].resource
                == defender_client.outbound_spam_policies["Policy1"].dict()
            )
            assert result[0].resource_name == "Defender Outbound Spam Policy"
            assert result[0].resource_id == "Policy1"
            assert result[0].location == "global"

    def test_forwarding_enabled_policy(self):
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_antispam_outbound_policy_forwarding_disabled.defender_antispam_outbound_policy_forwarding_disabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_antispam_outbound_policy_forwarding_disabled.defender_antispam_outbound_policy_forwarding_disabled import (
                defender_antispam_outbound_policy_forwarding_disabled,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                OutboundSpamPolicy,
                OutboundSpamRule,
            )

            defender_client.outbound_spam_policies = {
                "Policy2": OutboundSpamPolicy(
                    default=False,
                    notify_sender_blocked=True,
                    notify_limit_exceeded=True,
                    notify_limit_exceeded_addresses=["test@correo.com"],
                    notify_sender_blocked_addresses=["test@correo.com"],
                    auto_forwarding_mode=True,
                )
            }
            defender_client.outbound_spam_rules = {
                "Policy2": OutboundSpamRule(state="Enabled")
            }

            check = defender_antispam_outbound_policy_forwarding_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Outbound Spam Policy Policy2 does allow mail forwarding."
            )
            assert (
                result[0].resource
                == defender_client.outbound_spam_policies["Policy2"].dict()
            )
            assert result[0].resource_name == "Defender Outbound Spam Policy"
            assert result[0].resource_id == "Policy2"
            assert result[0].location == "global"

    def test_forwarding_disabled_default_policy(self):
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_antispam_outbound_policy_forwarding_disabled.defender_antispam_outbound_policy_forwarding_disabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_antispam_outbound_policy_forwarding_disabled.defender_antispam_outbound_policy_forwarding_disabled import (
                defender_antispam_outbound_policy_forwarding_disabled,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                OutboundSpamPolicy,
            )

            defender_client.outbound_spam_policies = {
                "Default": OutboundSpamPolicy(
                    default=True,
                    notify_sender_blocked=True,
                    notify_limit_exceeded=True,
                    notify_limit_exceeded_addresses=["test@correo.com"],
                    notify_sender_blocked_addresses=["test@correo.com"],
                    auto_forwarding_mode=False,
                )
            }
            defender_client.outbound_spam_rules = {}

            check = defender_antispam_outbound_policy_forwarding_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Outbound Spam Policy Default does not allow mail forwarding."
            )
            assert (
                result[0].resource
                == defender_client.outbound_spam_policies["Default"].dict()
            )
            assert result[0].resource_name == "Defender Outbound Spam Policy"
            assert result[0].resource_id == "Default"
            assert result[0].location == "global"

    def test_policy_without_rule(self):
        defender_client = mock.MagicMock()
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_antispam_outbound_policy_forwarding_disabled.defender_antispam_outbound_policy_forwarding_disabled.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_antispam_outbound_policy_forwarding_disabled.defender_antispam_outbound_policy_forwarding_disabled import (
                defender_antispam_outbound_policy_forwarding_disabled,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                OutboundSpamPolicy,
            )

            defender_client.outbound_spam_policies = {
                "PolicyX": OutboundSpamPolicy(
                    default=False,
                    notify_sender_blocked=True,
                    notify_limit_exceeded=True,
                    notify_limit_exceeded_addresses=["test@correo.com"],
                    notify_sender_blocked_addresses=["test@correo.com"],
                    auto_forwarding_mode=False,
                )
            }
            defender_client.outbound_spam_rules = {}

            check = defender_antispam_outbound_policy_forwarding_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Outbound Spam Policy PolicyX does allow mail forwarding."
            )
            assert (
                result[0].resource
                == defender_client.outbound_spam_policies["PolicyX"].dict()
            )
            assert result[0].resource_name == "Defender Outbound Spam Policy"
            assert result[0].resource_id == "PolicyX"
            assert result[0].location == "global"
