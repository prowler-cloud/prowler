from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_defender_antispam_policy_inbound_no_allowed_domains:
    def test_case_1_default_policy_no_allowed_domains(self):
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
                "prowler.providers.m365.services.defender.defender_antispam_policy_inbound_no_allowed_domains.defender_antispam_policy_inbound_no_allowed_domains.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_antispam_policy_inbound_no_allowed_domains.defender_antispam_policy_inbound_no_allowed_domains import (
                defender_antispam_policy_inbound_no_allowed_domains,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                DefenderInboundSpamPolicy,
            )

            defender_client.inbound_spam_policies = [
                DefenderInboundSpamPolicy(
                    identity="Default",
                    default=True,
                    allowed_sender_domains=[],
                )
            ]
            defender_client.inbound_spam_rules = {}

            check = defender_antispam_policy_inbound_no_allowed_domains()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Default is the only policy and it does not contain allowed domains."
            )
            assert result[0].resource_name == "Default"
            assert result[0].resource_id == "Default"
            assert result[0].resource == defender_client.inbound_spam_policies[0].dict()

    def test_case_2_all_policies_no_allowed_domains(self):
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
                "prowler.providers.m365.services.defender.defender_antispam_policy_inbound_no_allowed_domains.defender_antispam_policy_inbound_no_allowed_domains.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_antispam_policy_inbound_no_allowed_domains.defender_antispam_policy_inbound_no_allowed_domains import (
                defender_antispam_policy_inbound_no_allowed_domains,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                DefenderInboundSpamPolicy,
                InboundSpamRule,
            )

            defender_client.inbound_spam_policies = [
                DefenderInboundSpamPolicy(
                    identity="Default",
                    default=True,
                    allowed_sender_domains=[],
                ),
                DefenderInboundSpamPolicy(
                    identity="Policy1",
                    default=False,
                    allowed_sender_domains=[],
                ),
            ]
            defender_client.inbound_spam_rules = {
                "Policy1": InboundSpamRule(
                    state="Enabled",
                    priority=1,
                    users=["user1@example.com"],
                    groups=["group1"],
                    domains=["example.com"],
                )
            }

            check = defender_antispam_policy_inbound_no_allowed_domains()
            result = check.execute()
            assert len(result) == 2

            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Default is the default policy and it does not contain allowed domains, but it could be overridden by another misconfigured Custom Policy."
            )
            assert result[0].resource_name == "Default"
            assert result[0].resource_id == "Default"
            assert result[0].resource == defender_client.inbound_spam_policies[0].dict()

            assert result[1].status == "PASS"
            assert (
                result[1].status_extended
                == "Custom Inbound Spam policy Policy1 does not contain allowed domains and includes users: user1@example.com; groups: group1; domains: example.com, "
                "with priority 1 (0 is the highest). Also, the default policy does not contain allowed domains, so entities not included by this custom policy could still be correctly protected."
            )
            assert result[1].resource_name == "Policy1"
            assert result[1].resource_id == "Policy1"
            assert result[1].resource == defender_client.inbound_spam_policies[1].dict()

    def test_case_3_default_ok_custom_with_allowed_domains(self):
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
                "prowler.providers.m365.services.defender.defender_antispam_policy_inbound_no_allowed_domains.defender_antispam_policy_inbound_no_allowed_domains.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_antispam_policy_inbound_no_allowed_domains.defender_antispam_policy_inbound_no_allowed_domains import (
                defender_antispam_policy_inbound_no_allowed_domains,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                DefenderInboundSpamPolicy,
                InboundSpamRule,
            )

            defender_client.inbound_spam_policies = [
                DefenderInboundSpamPolicy(
                    identity="Default",
                    default=True,
                    allowed_sender_domains=[],
                ),
                DefenderInboundSpamPolicy(
                    identity="Policy1",
                    default=False,
                    allowed_sender_domains=["spam.com"],
                ),
            ]
            defender_client.inbound_spam_rules = {
                "Policy1": InboundSpamRule(
                    state="Enabled",
                    priority=2,
                    users=["user@example.com"],
                    groups=["group1"],
                    domains=["domain.com"],
                )
            }

            check = defender_antispam_policy_inbound_no_allowed_domains()
            result = check.execute()
            assert len(result) == 2

            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Default is the default policy and it does not contain allowed domains, but it could be overridden by another misconfigured Custom Policy."
            )
            assert result[0].resource_name == "Default"
            assert result[0].resource_id == "Default"
            assert result[0].resource == defender_client.inbound_spam_policies[0].dict()

            assert result[1].status == "FAIL"
            assert (
                result[1].status_extended
                == "Custom Inbound Spam policy Policy1 contains allowed domains and includes users: user@example.com; groups: group1; domains: domain.com, "
                "with priority 2 (0 is the highest). However, the default policy does not contain allowed domains, so entities not included by this custom policy could be correctly protected."
            )
            assert result[1].resource_name == "Policy1"
            assert result[1].resource_id == "Policy1"
            assert result[1].resource == defender_client.inbound_spam_policies[1].dict()

    def test_case_4_default_with_allowed_domains_custom_ok(self):
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
                "prowler.providers.m365.services.defender.defender_antispam_policy_inbound_no_allowed_domains.defender_antispam_policy_inbound_no_allowed_domains.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_antispam_policy_inbound_no_allowed_domains.defender_antispam_policy_inbound_no_allowed_domains import (
                defender_antispam_policy_inbound_no_allowed_domains,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                DefenderInboundSpamPolicy,
                InboundSpamRule,
            )

            defender_client.inbound_spam_policies = [
                DefenderInboundSpamPolicy(
                    identity="Default",
                    default=True,
                    allowed_sender_domains=["example.org"],
                ),
                DefenderInboundSpamPolicy(
                    identity="Policy1",
                    default=False,
                    allowed_sender_domains=[],
                ),
            ]

            defender_client.inbound_spam_rules = {
                "Policy1": InboundSpamRule(
                    state="Enabled",
                    priority=0,
                    users=["user@example.com"],
                    groups=["group1"],
                    domains=["domain.com"],
                )
            }

            check = defender_antispam_policy_inbound_no_allowed_domains()
            result = check.execute()
            assert len(result) == 2

            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Default is the default policy and it contains allowed domains: example.org, but it could be overridden by another well-configured Custom Policy."
            )
            assert result[0].resource_name == "Default"
            assert result[0].resource_id == "Default"
            assert result[0].resource == defender_client.inbound_spam_policies[0].dict()

            assert result[1].status == "PASS"
            assert (
                result[1].status_extended
                == "Custom Inbound Spam policy Policy1 does not contain allowed domains and includes users: user@example.com; groups: group1; domains: domain.com, "
                "with priority 0 (0 is the highest). However, the default policy contains allowed domains, so entities not included by this custom policy could not be correctly protected."
            )
            assert result[1].resource_name == "Policy1"
            assert result[1].resource_id == "Policy1"
            assert result[1].resource == defender_client.inbound_spam_policies[1].dict()

    def test_case_5_default_with_allowed_domains(self):
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
                "prowler.providers.m365.services.defender.defender_antispam_policy_inbound_no_allowed_domains.defender_antispam_policy_inbound_no_allowed_domains.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_antispam_policy_inbound_no_allowed_domains.defender_antispam_policy_inbound_no_allowed_domains import (
                defender_antispam_policy_inbound_no_allowed_domains,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                DefenderInboundSpamPolicy,
            )

            defender_client.inbound_spam_policies = [
                DefenderInboundSpamPolicy(
                    identity="Default",
                    default=True,
                    allowed_sender_domains=["example.com"],
                )
            ]
            defender_client.inbound_spam_rules = {}

            check = defender_antispam_policy_inbound_no_allowed_domains()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Default is the only policy and it contains allowed domains: example.com."
            )
            assert result[0].resource_name == "Default"
            assert result[0].resource_id == "Default"
            assert result[0].resource == defender_client.inbound_spam_policies[0].dict()

    def test_case_6_both_default_and_custom_with_allowed_domains(self):
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
                "prowler.providers.m365.services.defender.defender_antispam_policy_inbound_no_allowed_domains.defender_antispam_policy_inbound_no_allowed_domains.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_antispam_policy_inbound_no_allowed_domains.defender_antispam_policy_inbound_no_allowed_domains import (
                defender_antispam_policy_inbound_no_allowed_domains,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                DefenderInboundSpamPolicy,
                InboundSpamRule,
            )

            defender_client.inbound_spam_policies = [
                DefenderInboundSpamPolicy(
                    identity="Default",
                    default=True,
                    allowed_sender_domains=["example.com"],
                ),
                DefenderInboundSpamPolicy(
                    identity="Policy1",
                    default=False,
                    allowed_sender_domains=["spam.com"],
                ),
            ]

            defender_client.inbound_spam_rules = {
                "Policy1": InboundSpamRule(
                    state="Enabled",
                    priority=5,
                    users=["user@example.com"],
                    groups=["group1"],
                    domains=["domain.com"],
                )
            }

            check = defender_antispam_policy_inbound_no_allowed_domains()
            result = check.execute()
            assert len(result) == 2

            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Default is the default policy and it contains allowed domains: example.com, but it could be overridden by another well-configured Custom Policy."
            )
            assert result[0].resource_name == "Default"
            assert result[0].resource_id == "Default"
            assert result[0].resource == defender_client.inbound_spam_policies[0].dict()

            assert result[1].status == "FAIL"
            assert (
                result[1].status_extended
                == "Custom Inbound Spam policy Policy1 contains allowed domains and includes users: user@example.com; groups: group1; domains: domain.com, "
                "with priority 5 (0 is the highest). Also, the default policy contains allowed domains, so entities not included by this custom policy could not be correctly protected."
            )
            assert result[1].resource_name == "Policy1"
            assert result[1].resource_id == "Policy1"
            assert result[1].resource == defender_client.inbound_spam_policies[1].dict()

    def test_no_inbound_spam_policies(self):
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
                "prowler.providers.m365.services.defender.defender_antispam_policy_inbound_no_allowed_domains.defender_antispam_policy_inbound_no_allowed_domains.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_antispam_policy_inbound_no_allowed_domains.defender_antispam_policy_inbound_no_allowed_domains import (
                defender_antispam_policy_inbound_no_allowed_domains,
            )

            defender_client.inbound_spam_policies = []
            defender_client.inbound_spam_rules = {}

            check = defender_antispam_policy_inbound_no_allowed_domains()
            result = check.execute()
            assert len(result) == 0
