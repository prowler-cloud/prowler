from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_exchange_transport_rules_mail_forwarding_disabled:
    def test_empty_rule_list(self):
        exchange_client = mock.MagicMock()
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_transport_rules_mail_forwarding_disabled.exchange_transport_rules_mail_forwarding_disabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_transport_rules_mail_forwarding_disabled.exchange_transport_rules_mail_forwarding_disabled import (
                exchange_transport_rules_mail_forwarding_disabled,
            )

            exchange_client.transport_rules = []

            check = exchange_transport_rules_mail_forwarding_disabled()
            result = check.execute()

            assert len(result) == 0

    def test_forwarding_disabled(self):
        exchange_client = mock.MagicMock()
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_transport_rules_mail_forwarding_disabled.exchange_transport_rules_mail_forwarding_disabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_service import (
                TransportRule,
            )
            from prowler.providers.m365.services.exchange.exchange_transport_rules_mail_forwarding_disabled.exchange_transport_rules_mail_forwarding_disabled import (
                exchange_transport_rules_mail_forwarding_disabled,
            )

            exchange_client.transport_rules = [
                TransportRule(
                    name="Rule1", redirect_message_to=[], sender_domain_is=[]
                ),
                TransportRule(
                    name="Rule2", redirect_message_to=[], sender_domain_is=[]
                ),
            ]

            check = exchange_transport_rules_mail_forwarding_disabled()
            result = check.execute()

            assert len(result) == 2
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Transport rule Rule1 does not allow forwarding mail to external domains."
            )
            assert result[0].resource_name == "Rule1"
            assert result[0].resource_id == "ExchangeTransportRule"
            assert result[1].status == "PASS"
            assert (
                result[1].status_extended
                == "Transport rule Rule2 does not allow forwarding mail to external domains."
            )
            assert result[1].resource_name == "Rule2"

    def test_forwarding_enabled(self):
        exchange_client = mock.MagicMock()
        exchange_client.audited_tenant = "audited_tenant"
        exchange_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.exchange.exchange_transport_rules_mail_forwarding_disabled.exchange_transport_rules_mail_forwarding_disabled.exchange_client",
                new=exchange_client,
            ),
        ):
            from prowler.providers.m365.services.exchange.exchange_service import (
                TransportRule,
            )
            from prowler.providers.m365.services.exchange.exchange_transport_rules_mail_forwarding_disabled.exchange_transport_rules_mail_forwarding_disabled import (
                exchange_transport_rules_mail_forwarding_disabled,
            )

            exchange_client.transport_rules = [
                TransportRule(
                    name="ForwardingRule",
                    redirect_message_to=["external@example.com"],
                    sender_domain_is=[],
                ),
                TransportRule(
                    name="NoForwardingRule",
                    redirect_message_to=[],
                    sender_domain_is=[],
                ),
            ]

            check = exchange_transport_rules_mail_forwarding_disabled()
            result = check.execute()

            assert len(result) == 2
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Transport rule ForwardingRule allows forwarding mail to external domains: external@example.com."
            )
            assert result[0].resource_name == "ForwardingRule"
            assert result[0].resource_id == "ExchangeTransportRule"
            assert result[0].location == "global"
            assert result[1].status == "PASS"
            assert (
                result[1].status_extended
                == "Transport rule NoForwardingRule does not allow forwarding mail to external domains."
            )
            assert result[1].resource_name == "NoForwardingRule"
            assert result[1].resource_id == "ExchangeTransportRule"
            assert result[1].location == "global"
