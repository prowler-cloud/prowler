from unittest import mock
from unittest.mock import MagicMock, patch

from prowler.providers.linode.services.firewall.firewall_service import (
    Firewall,
    FirewallRule,
)


def mock_provider():
    provider = MagicMock()
    provider.type = "linode"
    return provider


class TestLinodeFirewallInboundRulesRestricted:
    def test_firewall_not_overly_permissive(self):
        firewall_client = mock.MagicMock
        firewall_client.firewalls = [
            Firewall(
                id=100,
                label="good-firewall",
                status="enabled",
                inbound_rules=[
                    FirewallRule(
                        protocol="TCP",
                        ports="443",
                        addresses_ipv4=["0.0.0.0/0"],
                        action="ACCEPT",
                    )
                ],
                tags=[],
            )
        ]

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider(),
            ),
            patch(
                "prowler.providers.linode.services.firewall.firewall_inbound_rules_restricted.firewall_inbound_rules_restricted.firewall_client",
                new=firewall_client,
            ),
        ):
            from prowler.providers.linode.services.firewall.firewall_inbound_rules_restricted.firewall_inbound_rules_restricted import (
                firewall_inbound_rules_restricted,
            )

            check = firewall_inbound_rules_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_firewall_all_ports_from_internet(self):
        firewall_client = mock.MagicMock
        firewall_client.firewalls = [
            Firewall(
                id=100,
                label="bad-firewall",
                status="enabled",
                inbound_rules=[
                    FirewallRule(
                        protocol="TCP",
                        ports="",
                        addresses_ipv4=["0.0.0.0/0"],
                        action="ACCEPT",
                    )
                ],
                tags=[],
            )
        ]

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider(),
            ),
            patch(
                "prowler.providers.linode.services.firewall.firewall_inbound_rules_restricted.firewall_inbound_rules_restricted.firewall_client",
                new=firewall_client,
            ),
        ):
            from prowler.providers.linode.services.firewall.firewall_inbound_rules_restricted.firewall_inbound_rules_restricted import (
                firewall_inbound_rules_restricted,
            )

            check = firewall_inbound_rules_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_firewall_drop_rule_not_flagged(self):
        firewall_client = mock.MagicMock
        firewall_client.firewalls = [
            Firewall(
                id=100,
                label="drop-firewall",
                status="enabled",
                inbound_rules=[
                    FirewallRule(
                        protocol="TCP",
                        ports="",
                        addresses_ipv4=["0.0.0.0/0"],
                        action="DROP",
                    )
                ],
                tags=[],
            )
        ]

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider(),
            ),
            patch(
                "prowler.providers.linode.services.firewall.firewall_inbound_rules_restricted.firewall_inbound_rules_restricted.firewall_client",
                new=firewall_client,
            ),
        ):
            from prowler.providers.linode.services.firewall.firewall_inbound_rules_restricted.firewall_inbound_rules_restricted import (
                firewall_inbound_rules_restricted,
            )

            check = firewall_inbound_rules_restricted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
