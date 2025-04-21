from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_defender_antispam_outbound_policy_configured:
    def test_properly_configured_custom_policy(self):
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
                "prowler.providers.m365.services.defender.defender_antispam_outbound_policy_configured.defender_antispam_outbound_policy_configured.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_antispam_outbound_policy_configured.defender_antispam_outbound_policy_configured import (
                defender_antispam_outbound_policy_configured,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                DefenderOutboundSpamPolicy,
                DefenderOutboundSpamRule,
            )

            defender_client.outbound_spam_policies = {
                "Policy1": DefenderOutboundSpamPolicy(
                    notify_sender_blocked=True,
                    notify_limit_exceeded=True,
                    notify_limit_exceeded_adresses=["test@correo.com"],
                    notify_sender_blocked_adresses=["test@correo.com"],
                    default=False,
                )
            }
            defender_client.outbound_spam_rules = {
                "Policy1": DefenderOutboundSpamRule(state="Enabled")
            }

            check = defender_antispam_outbound_policy_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Outbound Spam Policy 'Policy1' is not properly configured and enabled."
            )
            assert (
                result[0].resource
                == defender_client.outbound_spam_policies["Policy1"].dict()
            )
            assert result[0].resource_name == "Defender Outbound Spam Policy"
            assert result[0].resource_id == "Policy1"
            assert result[0].location == "global"

    def test_not_properly_configured_policy(self):
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
                "prowler.providers.m365.services.defender.defender_antispam_outbound_policy_configured.defender_antispam_outbound_policy_configured.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_antispam_outbound_policy_configured.defender_antispam_outbound_policy_configured import (
                defender_antispam_outbound_policy_configured,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                DefenderOutboundSpamPolicy,
                DefenderOutboundSpamRule,
            )

            defender_client.outbound_spam_policies = {
                "Policy2": DefenderOutboundSpamPolicy(
                    notify_sender_blocked=False,
                    notify_limit_exceeded=False,
                    notify_limit_exceeded_adresses=[],
                    notify_sender_blocked_adresses=[],
                    default=False,
                )
            }
            defender_client.outbound_spam_rules = {
                "Policy2": DefenderOutboundSpamRule(state="Enabled")
            }

            check = defender_antispam_outbound_policy_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Outbound Spam Policy 'Policy2' is not properly configured."
            )
            assert (
                result[0].resource
                == defender_client.outbound_spam_policies["Policy2"].dict()
            )
            assert result[0].resource_name == "Defender Outbound Spam Policy"
            assert result[0].resource_id == "Policy2"
            assert result[0].location == "global"

    def test_properly_configured_default_policy(self):
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
                "prowler.providers.m365.services.defender.defender_antispam_outbound_policy_configured.defender_antispam_outbound_policy_configured.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_antispam_outbound_policy_configured.defender_antispam_outbound_policy_configured import (
                defender_antispam_outbound_policy_configured,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                DefenderOutboundSpamPolicy,
            )

            defender_client.outbound_spam_policies = {
                "Default": DefenderOutboundSpamPolicy(
                    notify_sender_blocked=True,
                    notify_limit_exceeded=True,
                    notify_limit_exceeded_adresses=["test@correo.com"],
                    notify_sender_blocked_adresses=["test@correo.com"],
                    default=True,
                )
            }
            defender_client.outbound_spam_rules = {}

            check = defender_antispam_outbound_policy_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Outbound Spam Policy 'Default' is properly configured and enabled."
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
                "prowler.providers.m365.services.defender.defender_antispam_outbound_policy_configured.defender_antispam_outbound_policy_configured.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_antispam_outbound_policy_configured.defender_antispam_outbound_policy_configured import (
                defender_antispam_outbound_policy_configured,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                DefenderOutboundSpamPolicy,
            )

            defender_client.outbound_spam_policies = {
                "PolicyX": DefenderOutboundSpamPolicy(
                    notify_sender_blocked=True,
                    notify_limit_exceeded=True,
                    notify_limit_exceeded_adresses=["admin@org.com"],
                    notify_sender_blocked_adresses=["admin@org.com"],
                    default=False,
                )
            }
            defender_client.outbound_spam_rules = {}

            check = defender_antispam_outbound_policy_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Outbound Spam Policy 'PolicyX' is not properly configured."
            )
            assert (
                result[0].resource
                == defender_client.outbound_spam_policies["PolicyX"].dict()
            )
            assert result[0].resource_name == "Defender Outbound Spam Policy"
            assert result[0].resource_id == "PolicyX"
            assert result[0].location == "global"

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
                "prowler.providers.m365.services.defender.defender_antispam_outbound_policy_configured.defender_antispam_outbound_policy_configured.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_antispam_outbound_policy_configured.defender_antispam_outbound_policy_configured import (
                defender_antispam_outbound_policy_configured,
            )

            defender_client.outbound_spam_policies = {}
            defender_client.outbound_spam_rules = {}

            check = defender_antispam_outbound_policy_configured()
            result = check.execute()
            assert len(result) == 0
