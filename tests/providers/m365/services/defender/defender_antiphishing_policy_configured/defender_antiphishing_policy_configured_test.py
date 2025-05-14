from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_defender_antiphishing_policy_configured:
    def test_case_1_default_policy_properly_configured(self):
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
                "prowler.providers.m365.services.defender.defender_antiphishing_policy_configured.defender_antiphishing_policy_configured.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_antiphishing_policy_configured.defender_antiphishing_policy_configured import (
                defender_antiphishing_policy_configured,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                AntiphishingPolicy,
            )

            defender_client.antiphishing_policies = {
                "Default": AntiphishingPolicy(
                    name="Default",
                    spoof_intelligence=True,
                    spoof_intelligence_action="Quarantine",
                    dmarc_reject_action="Quarantine",
                    dmarc_quarantine_action="Quarantine",
                    safety_tips=True,
                    unauthenticated_sender_action=True,
                    show_tag=True,
                    honor_dmarc_policy=True,
                    default=True,
                )
            }
            defender_client.antiphishing_rules = {}

            check = defender_antiphishing_policy_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Default is the only policy and it's properly configured in the default Defender Anti-Phishing Policy."
            )
            assert (
                result[0].resource_name
                == defender_client.antiphishing_policies["Default"].name
            )
            assert (
                result[0].resource_id
                == defender_client.antiphishing_policies["Default"].name
            )
            assert (
                result[0].resource
                == defender_client.antiphishing_policies["Default"].dict()
            )

    def test_case_2_all_policies_properly_configured(self):
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
                "prowler.providers.m365.services.defender.defender_antiphishing_policy_configured.defender_antiphishing_policy_configured.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_antiphishing_policy_configured.defender_antiphishing_policy_configured import (
                defender_antiphishing_policy_configured,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                AntiphishingPolicy,
                AntiphishingRule,
            )

            defender_client.antiphishing_policies = {
                "Default": AntiphishingPolicy(
                    name="Default",
                    spoof_intelligence=True,
                    spoof_intelligence_action="Quarantine",
                    dmarc_reject_action="Quarantine",
                    dmarc_quarantine_action="Quarantine",
                    safety_tips=True,
                    unauthenticated_sender_action=True,
                    show_tag=True,
                    honor_dmarc_policy=True,
                    default=True,
                ),
                "Policy1": AntiphishingPolicy(
                    name="Policy1",
                    spoof_intelligence=True,
                    spoof_intelligence_action="Quarantine",
                    dmarc_reject_action="Quarantine",
                    dmarc_quarantine_action="Quarantine",
                    safety_tips=True,
                    unauthenticated_sender_action=True,
                    show_tag=True,
                    honor_dmarc_policy=True,
                    default=False,
                ),
            }
            defender_client.antiphishing_rules = {
                "Policy1": AntiphishingRule(
                    state="Enabled",
                    priority=1,
                    users=["test@example.com"],
                    groups=["example_group"],
                    domains=["example.com"],
                )
            }

            check = defender_antiphishing_policy_configured()
            result = check.execute()
            assert len(result) == 2
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Default is properly configured in the default Defender Anti-Phishing Policy, but could be overridden by another bad-configured Custom Policy."
            )
            assert (
                result[0].resource_name
                == defender_client.antiphishing_policies["Default"].name
            )
            assert (
                result[0].resource_id
                == defender_client.antiphishing_policies["Default"].name
            )
            assert (
                result[0].resource
                == defender_client.antiphishing_policies["Default"].dict()
            )
            assert result[1].status == "PASS"
            assert (
                result[1].status_extended
                == f"Custom Anti-phishing policy {defender_client.antiphishing_policies['Policy1'].name} is properly configured and includes users: {', '.join(defender_client.antiphishing_rules['Policy1'].users)}; groups: {', '.join(defender_client.antiphishing_rules['Policy1'].groups)}; domains: {', '.join(defender_client.antiphishing_rules['Policy1'].domains)}, "
                f"with priority {defender_client.antiphishing_rules['Policy1'].priority} (0 is the highest). "
                "Also, the default policy is properly configured, so entities not included by this custom policy could still be correctly protected."
            )
            assert (
                result[1].resource_name
                == defender_client.antiphishing_policies["Policy1"].name
            )
            assert (
                result[1].resource_id
                == defender_client.antiphishing_policies["Policy1"].name
            )
            assert (
                result[1].resource
                == defender_client.antiphishing_policies["Policy1"].dict()
            )

    def test_case_3_default_ok_others_not(self):
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
                "prowler.providers.m365.services.defender.defender_antiphishing_policy_configured.defender_antiphishing_policy_configured.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_antiphishing_policy_configured.defender_antiphishing_policy_configured import (
                defender_antiphishing_policy_configured,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                AntiphishingPolicy,
                AntiphishingRule,
            )

            defender_client.antiphishing_policies = {
                "Default": AntiphishingPolicy(
                    name="Default",
                    spoof_intelligence=True,
                    spoof_intelligence_action="Quarantine",
                    dmarc_reject_action="Quarantine",
                    dmarc_quarantine_action="Quarantine",
                    safety_tips=True,
                    unauthenticated_sender_action=True,
                    show_tag=True,
                    honor_dmarc_policy=True,
                    default=True,
                ),
                "Policy1": AntiphishingPolicy(
                    name="Policy1",
                    spoof_intelligence=False,
                    spoof_intelligence_action="None",
                    dmarc_reject_action="None",
                    dmarc_quarantine_action="None",
                    safety_tips=False,
                    unauthenticated_sender_action=False,
                    show_tag=False,
                    honor_dmarc_policy=False,
                    default=False,
                ),
            }
            defender_client.antiphishing_rules = {
                "Policy1": AntiphishingRule(
                    state="Enabled",
                    priority=1,
                    users=["test@example.com"],
                    groups=["example_group"],
                    domains=["example.com"],
                )
            }

            check = defender_antiphishing_policy_configured()
            result = check.execute()
            assert len(result) == 2
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Default is properly configured in the default Defender Anti-Phishing Policy, but could be overridden by another bad-configured Custom Policy."
            )
            assert result[0].resource_name == "Default"
            assert result[0].resource_id == "Default"
            assert (
                result[0].resource
                == defender_client.antiphishing_policies["Default"].dict()
            )

            assert result[1].status == "FAIL"
            assert (
                result[1].status_extended
                == "Custom Anti-phishing policy Policy1 is not properly configured and includes users: test@example.com; groups: example_group; domains: example.com, "
                "with priority 1 (0 is the highest). However, the default policy is properly configured, so entities not included by this custom policy could be correctly protected."
            )
            assert result[1].resource_name == "Policy1"
            assert result[1].resource_id == "Policy1"
            assert (
                result[1].resource
                == defender_client.antiphishing_policies["Policy1"].dict()
            )

    def test_case_4_default_not_ok_potential_false_positive(self):
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
                "prowler.providers.m365.services.defender.defender_antiphishing_policy_configured.defender_antiphishing_policy_configured.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_antiphishing_policy_configured.defender_antiphishing_policy_configured import (
                defender_antiphishing_policy_configured,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                AntiphishingPolicy,
                AntiphishingRule,
            )

            defender_client.antiphishing_policies = {
                "Default": AntiphishingPolicy(
                    name="Default",
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
                "Policy1": AntiphishingPolicy(
                    name="Policy1",
                    spoof_intelligence=True,
                    spoof_intelligence_action="Quarantine",
                    dmarc_reject_action="Quarantine",
                    dmarc_quarantine_action="Quarantine",
                    safety_tips=True,
                    unauthenticated_sender_action=True,
                    show_tag=True,
                    honor_dmarc_policy=True,
                    default=False,
                ),
            }
            defender_client.antiphishing_rules = {
                "Policy1": AntiphishingRule(
                    state="Enabled",
                    priority=1,
                    users=["test@example.com"],
                    groups=["example_group"],
                    domains=["example.com"],
                )
            }

            check = defender_antiphishing_policy_configured()
            result = check.execute()
            assert len(result) == 2
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Default is not properly configured in the default Defender Anti-Phishing Policy, but could be overridden by another well-configured Custom Policy."
            )
            assert result[0].resource_name == "Default"
            assert result[0].resource_id == "Default"
            assert (
                result[0].resource
                == defender_client.antiphishing_policies["Default"].dict()
            )
            assert result[1].status == "PASS"
            assert (
                result[1].status_extended
                == "Custom Anti-phishing policy Policy1 is properly configured and includes users: test@example.com; groups: example_group; domains: example.com, "
                f"with priority {defender_client.antiphishing_rules['Policy1'].priority} (0 is the highest). "
                "However, the default policy is not properly configured, so entities not included by this custom policy could not be correctly protected."
            )
            assert result[1].resource_name == "Policy1"
            assert result[1].resource_id == "Policy1"
            assert (
                result[1].resource
                == defender_client.antiphishing_policies["Policy1"].dict()
            )

    def test_case_5_default_policy_not_properly_configured(self):
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
                "prowler.providers.m365.services.defender.defender_antiphishing_policy_configured.defender_antiphishing_policy_configured.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_antiphishing_policy_configured.defender_antiphishing_policy_configured import (
                defender_antiphishing_policy_configured,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                AntiphishingPolicy,
            )

            defender_client.antiphishing_policies = {
                "Default": AntiphishingPolicy(
                    name="Default",
                    spoof_intelligence=False,
                    spoof_intelligence_action="None",
                    dmarc_reject_action="None",
                    dmarc_quarantine_action="None",
                    safety_tips=False,
                    unauthenticated_sender_action=False,
                    show_tag=False,
                    honor_dmarc_policy=False,
                    default=True,
                )
            }
            defender_client.antiphishing_rules = {}

            check = defender_antiphishing_policy_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Default is the only policy and it's not properly configured in the default Defender Anti-Phishing Policy."
            )
            assert result[0].resource_name == "Default"
            assert result[0].resource_id == "Default"
            assert (
                result[0].resource
                == defender_client.antiphishing_policies["Default"].dict()
            )

    def test_case_6_both_policies_not_properly_configured(self):
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
                "prowler.providers.m365.services.defender.defender_antiphishing_policy_configured.defender_antiphishing_policy_configured.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_antiphishing_policy_configured.defender_antiphishing_policy_configured import (
                defender_antiphishing_policy_configured,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                AntiphishingPolicy,
                AntiphishingRule,
            )

            defender_client.antiphishing_policies = {
                "Default": AntiphishingPolicy(
                    name="Default",
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
                "Policy1": AntiphishingPolicy(
                    name="Policy1",
                    spoof_intelligence=False,
                    spoof_intelligence_action="None",
                    dmarc_reject_action="None",
                    dmarc_quarantine_action="None",
                    safety_tips=False,
                    unauthenticated_sender_action=False,
                    show_tag=False,
                    honor_dmarc_policy=False,
                    default=False,
                ),
            }
            defender_client.antiphishing_rules = {
                "Policy1": AntiphishingRule(
                    state="Enabled",
                    priority=1,
                    users=[],
                    groups=[],
                    domains=["example.com"],
                )
            }

            check = defender_antiphishing_policy_configured()
            result = check.execute()
            assert len(result) == 2
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Default is not properly configured in the default Defender Anti-Phishing Policy, but could be overridden by another well-configured Custom Policy."
            )
            assert result[0].resource_name == "Default"
            assert result[0].resource_id == "Default"
            assert (
                result[0].resource
                == defender_client.antiphishing_policies["Default"].dict()
            )
            assert result[1].status == "FAIL"
            assert (
                result[1].status_extended
                == "Custom Anti-phishing policy Policy1 is not properly configured and includes domains: example.com, "
                "with priority 1 (0 is the highest). Also, the default policy is not properly configured, so entities not included by this custom policy could not be correctly protected."
            )
            assert result[1].resource_name == "Policy1"
            assert result[1].resource_id == "Policy1"
            assert (
                result[1].resource
                == defender_client.antiphishing_policies["Policy1"].dict()
            )

    def test_no_antiphishing_policies(self):
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
                "prowler.providers.m365.services.defender.defender_antiphishing_policy_configured.defender_antiphishing_policy_configured.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_antiphishing_policy_configured.defender_antiphishing_policy_configured import (
                defender_antiphishing_policy_configured,
            )

            defender_client.antiphishing_policies = {}
            defender_client.antiphishing_rules = {}

            check = defender_antiphishing_policy_configured()
            result = check.execute()
            assert len(result) == 0
