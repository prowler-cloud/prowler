from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_defender_antispam_outbound_policy_forwarding_disabled:
    def test_case_1_default_policy_forwarding_disabled(self):
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
                    name="Default",
                    auto_forwarding_mode=False,
                    notify_limit_exceeded=True,
                    notify_sender_blocked=True,
                    notify_limit_exceeded_addresses=["admin@example.com"],
                    notify_sender_blocked_addresses=["admin@example.com"],
                    default=True,
                )
            }
            defender_client.outbound_spam_rules = {}

            check = defender_antispam_outbound_policy_forwarding_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Default is the only policy and mail forwarding is disabled."
            )
            assert result[0].resource_name == "Default"
            assert result[0].resource_id == "Default"
            assert (
                result[0].resource
                == defender_client.outbound_spam_policies["Default"].dict()
            )

    def test_case_2_all_policies_forwarding_disabled(self):
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
                "Default": OutboundSpamPolicy(
                    name="Default",
                    auto_forwarding_mode=False,
                    notify_limit_exceeded=True,
                    notify_sender_blocked=True,
                    notify_limit_exceeded_addresses=["admin@example.com"],
                    notify_sender_blocked_addresses=["admin@example.com"],
                    default=True,
                ),
                "Policy1": OutboundSpamPolicy(
                    name="Policy1",
                    auto_forwarding_mode=False,
                    notify_limit_exceeded=True,
                    notify_sender_blocked=True,
                    notify_limit_exceeded_addresses=["admin@example.com"],
                    notify_sender_blocked_addresses=["admin@example.com"],
                    default=False,
                ),
            }

            defender_client.outbound_spam_rules = {
                "Policy1": OutboundSpamRule(
                    state="Enabled",
                    priority=1,
                    users=["test@example.com"],
                    groups=["group1"],
                    domains=["example.com"],
                )
            }

            check = defender_antispam_outbound_policy_forwarding_disabled()
            result = check.execute()
            assert len(result) == 2

            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Default is the default policy and mail forwarding is disabled, but it could be overridden by another misconfigured Custom Policy."
            )
            assert result[0].resource_name == "Default"
            assert result[0].resource_id == "Default"
            assert (
                result[0].resource
                == defender_client.outbound_spam_policies["Default"].dict()
            )

            assert result[1].status == "PASS"
            assert (
                result[1].status_extended
                == "Custom Outbound Spam policy Policy1 disables mail forwarding and includes users: test@example.com; groups: group1; domains: example.com, "
                "with priority 1 (0 is the highest). Also, the default policy disables mail forwarding, so entities not included by this custom policy could still be correctly protected."
            )
            assert result[1].resource_name == "Policy1"
            assert result[1].resource_id == "Policy1"
            assert (
                result[1].resource
                == defender_client.outbound_spam_policies["Policy1"].dict()
            )

    def test_case_3_default_ok_custom_not(self):
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
                "Default": OutboundSpamPolicy(
                    name="Default",
                    auto_forwarding_mode=False,
                    notify_limit_exceeded=True,
                    notify_sender_blocked=True,
                    notify_limit_exceeded_addresses=["admin@example.com"],
                    notify_sender_blocked_addresses=["admin@example.com"],
                    default=True,
                ),
                "Policy1": OutboundSpamPolicy(
                    name="Policy1",
                    auto_forwarding_mode=True,
                    notify_limit_exceeded=False,
                    notify_sender_blocked=False,
                    notify_limit_exceeded_addresses=[],
                    notify_sender_blocked_addresses=[],
                    default=False,
                ),
            }

            defender_client.outbound_spam_rules = {
                "Policy1": OutboundSpamRule(
                    state="Enabled",
                    priority=1,
                    users=["test@example.com"],
                    groups=["group1"],
                    domains=["example.com"],
                )
            }

            check = defender_antispam_outbound_policy_forwarding_disabled()
            result = check.execute()
            assert len(result) == 2

            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Default is the default policy and mail forwarding is disabled, but it could be overridden by another misconfigured Custom Policy."
            )
            assert result[0].resource_name == "Default"
            assert result[0].resource_id == "Default"
            assert (
                result[0].resource
                == defender_client.outbound_spam_policies["Default"].dict()
            )

            assert result[1].status == "FAIL"
            assert (
                result[1].status_extended
                == "Custom Outbound Spam policy Policy1 allows mail forwarding and includes users: test@example.com; groups: group1; domains: example.com, "
                "with priority 1 (0 is the highest). However, the default policy disables mail forwarding, so entities not included by this custom policy could be correctly protected."
            )
            assert result[1].resource_name == "Policy1"
            assert result[1].resource_id == "Policy1"
            assert (
                result[1].resource
                == defender_client.outbound_spam_policies["Policy1"].dict()
            )

    def test_case_4_default_not_ok_custom_good(self):
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
                "Default": OutboundSpamPolicy(
                    name="Default",
                    auto_forwarding_mode=True,
                    notify_limit_exceeded=False,
                    notify_sender_blocked=False,
                    notify_limit_exceeded_addresses=[],
                    notify_sender_blocked_addresses=[],
                    default=True,
                ),
                "Policy1": OutboundSpamPolicy(
                    name="Policy1",
                    auto_forwarding_mode=False,
                    notify_limit_exceeded=True,
                    notify_sender_blocked=True,
                    notify_limit_exceeded_addresses=["admin@example.com"],
                    notify_sender_blocked_addresses=["admin@example.com"],
                    default=False,
                ),
            }

            defender_client.outbound_spam_rules = {
                "Policy1": OutboundSpamRule(
                    state="Enabled",
                    priority=0,
                    users=["user1@example.com"],
                    groups=["group1"],
                    domains=["domain.com"],
                )
            }

            check = defender_antispam_outbound_policy_forwarding_disabled()
            result = check.execute()
            assert len(result) == 2

            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Default is the default policy and mail forwarding is allowed, but it could be overridden by another well-configured Custom Policy."
            )
            assert result[0].resource_name == "Default"
            assert result[0].resource_id == "Default"
            assert (
                result[0].resource
                == defender_client.outbound_spam_policies["Default"].dict()
            )

            assert result[1].status == "PASS"
            assert (
                result[1].status_extended
                == "Custom Outbound Spam policy Policy1 disables mail forwarding and includes users: user1@example.com; groups: group1; domains: domain.com, "
                "with priority 0 (0 is the highest). However, the default policy allows mail forwarding, so entities not included by this custom policy could not be correctly protected."
            )
            assert result[1].resource_name == "Policy1"
            assert result[1].resource_id == "Policy1"
            assert (
                result[1].resource
                == defender_client.outbound_spam_policies["Policy1"].dict()
            )

    def test_case_5_only_default_not_ok(self):
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
                    name="Default",
                    auto_forwarding_mode=True,
                    notify_limit_exceeded=False,
                    notify_sender_blocked=False,
                    notify_limit_exceeded_addresses=[],
                    notify_sender_blocked_addresses=[],
                    default=True,
                )
            }
            defender_client.outbound_spam_rules = {}

            check = defender_antispam_outbound_policy_forwarding_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Default is the only policy and mail forwarding is allowed."
            )
            assert result[0].resource_name == "Default"
            assert result[0].resource_id == "Default"
            assert (
                result[0].resource
                == defender_client.outbound_spam_policies["Default"].dict()
            )

    def test_case_6_default_and_custom_not_ok(self):
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
                "Default": OutboundSpamPolicy(
                    name="Default",
                    auto_forwarding_mode=True,
                    notify_limit_exceeded=False,
                    notify_sender_blocked=False,
                    notify_limit_exceeded_addresses=[],
                    notify_sender_blocked_addresses=[],
                    default=True,
                ),
                "Policy1": OutboundSpamPolicy(
                    name="Policy1",
                    auto_forwarding_mode=True,
                    notify_limit_exceeded=False,
                    notify_sender_blocked=False,
                    notify_limit_exceeded_addresses=[],
                    notify_sender_blocked_addresses=[],
                    default=False,
                ),
            }

            defender_client.outbound_spam_rules = {
                "Policy1": OutboundSpamRule(
                    state="Enabled",
                    priority=1,
                    users=["user@example.com"],
                    groups=["group1"],
                    domains=["domain.com"],
                )
            }

            check = defender_antispam_outbound_policy_forwarding_disabled()
            result = check.execute()
            assert len(result) == 2

            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Default is the default policy and mail forwarding is allowed, but it could be overridden by another well-configured Custom Policy."
            )
            assert result[0].resource_name == "Default"
            assert result[0].resource_id == "Default"
            assert (
                result[0].resource
                == defender_client.outbound_spam_policies["Default"].dict()
            )

            assert result[1].status == "FAIL"
            assert (
                result[1].status_extended
                == "Custom Outbound Spam policy Policy1 allows mail forwarding and includes users: user@example.com; groups: group1; domains: domain.com, "
                "with priority 1 (0 is the highest). Also, the default policy allows mail forwarding, so entities not included by this custom policy could not be correctly protected."
            )
            assert result[1].resource_name == "Policy1"
            assert result[1].resource_id == "Policy1"
            assert (
                result[1].resource
                == defender_client.outbound_spam_policies["Policy1"].dict()
            )

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
