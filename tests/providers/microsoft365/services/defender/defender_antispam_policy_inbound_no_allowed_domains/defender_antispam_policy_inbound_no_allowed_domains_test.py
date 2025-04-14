from unittest import mock

from tests.providers.microsoft365.microsoft365_fixtures import (
    DOMAIN,
    set_mocked_microsoft365_provider,
)


class Test_defender_antispam_policy_inbound_no_allowed_domains:
    def test_policy_without_allowed_domains(self):
        defender_client = mock.MagicMock
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.defender.defender_antispam_policy_inbound_no_allowed_domains.defender_antispam_policy_inbound_no_allowed_domains.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.microsoft365.services.defender.defender_antispam_policy_inbound_no_allowed_domains.defender_antispam_policy_inbound_no_allowed_domains import (
                defender_antispam_policy_inbound_no_allowed_domains,
            )
            from prowler.providers.microsoft365.services.defender.defender_service import (
                DefenderInboundSpamPolicy,
            )

            defender_client = mock.MagicMock
            defender_client.inbound_spam_policies = [
                DefenderInboundSpamPolicy(
                    identity="Policy1",
                    allowed_sender_domains=[],
                )
            ]

            check = defender_antispam_policy_inbound_no_allowed_domains()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Inbound anti-spam policy Policy1 does not contain allowed domains."
            )
            assert result[0].resource == defender_client.inbound_spam_policies[0].dict()
            assert result[0].resource_name == "Defender Inbound Spam Policy"
            assert result[0].resource_id == "Policy1"
            assert result[0].location == "global"

    def test_policy_with_allowed_domains(self):
        defender_client = mock.MagicMock
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.defender.defender_antispam_policy_inbound_no_allowed_domains.defender_antispam_policy_inbound_no_allowed_domains.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.microsoft365.services.defender.defender_antispam_policy_inbound_no_allowed_domains.defender_antispam_policy_inbound_no_allowed_domains import (
                defender_antispam_policy_inbound_no_allowed_domains,
            )
            from prowler.providers.microsoft365.services.defender.defender_service import (
                DefenderInboundSpamPolicy,
            )

            defender_client = mock.MagicMock
            defender_client.inbound_spam_policies = [
                DefenderInboundSpamPolicy(
                    identity="Policy2",
                    allowed_sender_domains=["bad-domain.com"],
                )
            ]

            check = defender_antispam_policy_inbound_no_allowed_domains()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Inbound anti-spam policy Policy2 contains allowed domains: ['bad-domain.com']."
            )
            assert result[0].resource == defender_client.inbound_spam_policies[0].dict()
            assert result[0].resource_name == "Defender Inbound Spam Policy"
            assert result[0].resource_id == "Policy2"
            assert result[0].location == "global"

    def test_no_inbound_spam_policies(self):
        defender_client = mock.MagicMock
        defender_client.audited_tenant = "audited_tenant"
        defender_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.defender.defender_antispam_policy_inbound_no_allowed_domains.defender_antispam_policy_inbound_no_allowed_domains.defender_client",
                new=defender_client,
            ),
        ):
            from prowler.providers.microsoft365.services.defender.defender_antispam_policy_inbound_no_allowed_domains.defender_antispam_policy_inbound_no_allowed_domains import (
                defender_antispam_policy_inbound_no_allowed_domains,
            )

            defender_client = mock.MagicMock
            defender_client.inbound_spam_policies = []

            check = defender_antispam_policy_inbound_no_allowed_domains()
            result = check.execute()
            assert len(result) == 0
