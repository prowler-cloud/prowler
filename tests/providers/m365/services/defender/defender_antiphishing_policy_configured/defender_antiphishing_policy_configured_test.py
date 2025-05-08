from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_defender_antiphishing_policy_configured:
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
                "Policy1": AntiphishingPolicy(
                    spoof_intelligence=True,
                    spoof_intelligence_action="Quarantine",
                    dmarc_reject_action="Quarantine",
                    dmarc_quarantine_action="Quarantine",
                    safety_tips=True,
                    unauthenticated_sender_action=True,
                    show_tag=True,
                    honor_dmarc_policy=True,
                    default=False,
                )
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
                == "Anti-phishing policy Policy1 is properly configured and enabled."
            )
            assert (
                result[0].resource
                == defender_client.antiphishing_policies["Policy1"].dict()
            )
            assert result[0].resource_name == "Defender Anti-Phishing Policy"
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
                "Policy2": AntiphishingPolicy(
                    spoof_intelligence=False,
                    spoof_intelligence_action="None",
                    dmarc_reject_action="None",
                    dmarc_quarantine_action="None",
                    safety_tips=False,
                    unauthenticated_sender_action=False,
                    show_tag=False,
                    honor_dmarc_policy=False,
                    default=False,
                )
            }
            defender_client.antiphising_rules = {
                "Policy2": AntiphishingRule(state="Enabled")
            }

            check = defender_antiphishing_policy_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Anti-phishing policy Policy2 is not properly configured."
            )
            assert (
                result[0].resource
                == defender_client.antiphishing_policies["Policy2"].dict()
            )
            assert result[0].resource_name == "Defender Anti-Phishing Policy"
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
                == "Anti-phishing policy Default is properly configured and enabled."
            )
            assert (
                result[0].resource
                == defender_client.antiphishing_policies["Default"].dict()
            )
            assert result[0].resource_name == "Defender Anti-Phishing Policy"
            assert result[0].resource_id == "Default"
            assert result[0].location == "global"

    def test_default_policy_not_properly_configured(self):
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
                == "Anti-phishing policy Default is not properly configured."
            )
            assert (
                result[0].resource
                == defender_client.antiphishing_policies["Default"].dict()
            )
            assert result[0].resource_name == "Defender Anti-Phishing Policy"
            assert result[0].resource_id == "Default"
            assert result[0].location == "global"

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
            assert result == []

    def test_custom_policy_without_rule(self):
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
                "PolicyX": AntiphishingPolicy(
                    spoof_intelligence=True,
                    spoof_intelligence_action="Quarantine",
                    dmarc_reject_action="Quarantine",
                    dmarc_quarantine_action="Quarantine",
                    safety_tips=True,
                    unauthenticated_sender_action=True,
                    show_tag=True,
                    honor_dmarc_policy=True,
                    default=False,
                )
            }
            defender_client.antiphising_rules = {}

            check = defender_antiphishing_policy_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Anti-phishing policy PolicyX is not properly configured."
            )
            assert (
                result[0].resource
                == defender_client.antiphishing_policies["PolicyX"].dict()
            )
            assert result[0].resource_name == "Defender Anti-Phishing Policy"
            assert result[0].resource_id == "PolicyX"
            assert result[0].location == "global"
