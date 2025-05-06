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
            defender_client.antiphising_rules = {}

            check = defender_antiphishing_policy_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Anti-phishing policy is properly configured in the default Defender Anti-Phishing Policy."
            )
            assert (
                result[0].resource_name
                == defender_client.antiphishing_policies["Default"].name
            )
            assert result[0].resource_id == "defaultDefenderAntiPhishingPolicy"

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
            defender_client.antiphising_rules = {
                "Policy1": AntiphishingRule(state="Enabled")
            }

            check = defender_antiphishing_policy_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Anti-phishing policy is properly configured in all Defender Anti-Phishing Policies."
            )
            assert result[0].resource_name == "Defender Anti-Phishing Policies"
            assert result[0].resource_id == "defenderAntiPhishingPolicies"

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
            defender_client.antiphising_rules = {
                "Policy1": AntiphishingRule(state="Enabled")
            }

            check = defender_antiphishing_policy_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Anti-phishing policy is properly configured in default Defender Anti-Phishing Policy but not in the following Defender Anti-Phishing Policies that may override it: Policy1."
            )
            assert result[0].resource_name == "Defender Anti-Phishing Policies"
            assert result[0].resource_id == "defenderAntiPhishingPolicies"

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
            defender_client.antiphising_rules = {
                "Policy1": AntiphishingRule(state="Enabled")
            }

            check = defender_antiphishing_policy_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Anti-phishing policy is not properly configured in the default Defender Anti-Phishing Policy, but could be overridden by another policy which is out of Prowler's scope."
            )
            assert (
                result[0].resource
                == defender_client.antiphishing_policies["Default"].dict()
            )
            assert (
                result[0].resource_name
                == defender_client.antiphishing_policies["Default"].name
            )
            assert result[0].resource_id == "defaultDefenderAntiPhishingPolicy"

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
            defender_client.antiphising_rules = {}

            check = defender_antiphishing_policy_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Anti-phishing policy is not properly configured in the default Defender Anti-Phishing Policy."
            )
            assert (
                result[0].resource_name
                == defender_client.antiphishing_policies["Default"].name
            )
            assert result[0].resource_id == "defaultDefenderAntiPhishingPolicy"

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
            defender_client.antiphising_rules = {}

            check = defender_antiphishing_policy_configured()
            result = check.execute()
            assert len(result) == 0
