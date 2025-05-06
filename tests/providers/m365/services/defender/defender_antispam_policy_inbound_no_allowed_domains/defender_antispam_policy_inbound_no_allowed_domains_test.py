from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_defender_antispam_policy_inbound_no_allowed_domains:
    def test_policy_without_allowed_domains(self):
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
                    identity="Policy1",
                    allowed_sender_domains=[],
                    default=True,
                )
            ]

            check = defender_antispam_policy_inbound_no_allowed_domains()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Inbound anti-spam policy does not contain allowed domains in all Defender Inbound Spam Policies."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Defender Inbound Spam Policies"
            assert result[0].resource_id == "defenderInboundSpamPolicies"
            assert result[0].location == "global"

    def test_policy_with_allowed_domains(self):
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
                    identity="Policy2",
                    allowed_sender_domains=["bad-domain.com"],
                    default=False,
                )
            ]

            check = defender_antispam_policy_inbound_no_allowed_domains()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Inbound anti-spam policy does not contain allowed domains in default Defender Inbound Spam Policy but does in the following Defender Inbound Spam Policies that may override it: Policy2."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Defender Inbound Spam Policies"
            assert result[0].resource_id == "defenderInboundSpamPolicies"
            assert result[0].location == "global"

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

            check = defender_antispam_policy_inbound_no_allowed_domains()
            result = check.execute()

            assert len(result) == 0
