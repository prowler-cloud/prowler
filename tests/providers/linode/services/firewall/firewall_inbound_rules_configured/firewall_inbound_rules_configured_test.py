from unittest import mock

from prowler.providers.linode.services.firewall.firewall_service import (
    Firewall,
    FirewallRule,
)
from tests.providers.linode.linode_fixtures import set_mocked_linode_provider


class Test_firewall_inbound_rules_configured:
    def test_no_firewalls(self):
        firewall_client = mock.MagicMock
        firewall_client.firewalls = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.firewall.firewall_inbound_rules_configured.firewall_inbound_rules_configured.firewall_client",
                new=firewall_client,
            ),
        ):
            from prowler.providers.linode.services.firewall.firewall_inbound_rules_configured.firewall_inbound_rules_configured import (
                firewall_inbound_rules_configured,
            )

            check = firewall_inbound_rules_configured()
            result = check.execute()

            assert len(result) == 0

    def test_inbound_rules_empty(self):
        firewall_client = mock.MagicMock
        firewall_client.firewalls = [
            Firewall(
                id=100,
                label="empty-inbound-fw",
                status="enabled",
                inbound_rules=[],
                outbound_rules=[],
                inbound_policy="DROP",
                outbound_policy="DROP",
                attached_devices_count=1,
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.firewall.firewall_inbound_rules_configured.firewall_inbound_rules_configured.firewall_client",
                new=firewall_client,
            ),
        ):
            from prowler.providers.linode.services.firewall.firewall_inbound_rules_configured.firewall_inbound_rules_configured import (
                firewall_inbound_rules_configured,
            )

            check = firewall_inbound_rules_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "100"
            assert result[0].resource_name == "empty-inbound-fw"

    def test_inbound_rules_not_empty(self):
        firewall_client = mock.MagicMock
        firewall_client.firewalls = [
            Firewall(
                id=101,
                label="non-empty-inbound-fw",
                status="enabled",
                inbound_rules=[
                    FirewallRule(
                        protocol="TCP",
                        ports="443",
                        addresses_ipv4=["0.0.0.0/0"],
                        addresses_ipv6=[],
                        action="ACCEPT",
                        label="allow-https",
                    )
                ],
                outbound_rules=[],
                inbound_policy="DROP",
                outbound_policy="DROP",
                attached_devices_count=1,
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.firewall.firewall_inbound_rules_configured.firewall_inbound_rules_configured.firewall_client",
                new=firewall_client,
            ),
        ):
            from prowler.providers.linode.services.firewall.firewall_inbound_rules_configured.firewall_inbound_rules_configured import (
                firewall_inbound_rules_configured,
            )

            check = firewall_inbound_rules_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "101"
            assert result[0].resource_name == "non-empty-inbound-fw"
