from unittest import mock

from prowler.providers.linode.services.firewall.firewall_service import (
    Firewall,
    FirewallRule,
)
from tests.providers.linode.linode_fixtures import set_mocked_linode_provider


class Test_firewall_blocks_rdp_from_internet:
    def test_no_firewalls(self):
        firewall_client = mock.MagicMock
        firewall_client.firewalls = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.firewall.firewall_blocks_rdp_from_internet.firewall_blocks_rdp_from_internet.firewall_client",
                new=firewall_client,
            ),
        ):
            from prowler.providers.linode.services.firewall.firewall_blocks_rdp_from_internet.firewall_blocks_rdp_from_internet import (
                firewall_blocks_rdp_from_internet,
            )

            check = firewall_blocks_rdp_from_internet()
            result = check.execute()

            assert len(result) == 0

    def test_firewall_allows_rdp_from_internet(self):
        firewall_client = mock.MagicMock
        firewall_client.firewalls = [
            Firewall(
                id=100,
                label="open-rdp-fw",
                status="enabled",
                inbound_rules=[
                    FirewallRule(
                        protocol="TCP",
                        ports="3389",
                        addresses_ipv4=["0.0.0.0/0"],
                        addresses_ipv6=[],
                        action="ACCEPT",
                        label="allow-rdp",
                    )
                ],
                outbound_rules=[],
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.firewall.firewall_blocks_rdp_from_internet.firewall_blocks_rdp_from_internet.firewall_client",
                new=firewall_client,
            ),
        ):
            from prowler.providers.linode.services.firewall.firewall_blocks_rdp_from_internet.firewall_blocks_rdp_from_internet import (
                firewall_blocks_rdp_from_internet,
            )

            check = firewall_blocks_rdp_from_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "100"
            assert result[0].resource_name == "open-rdp-fw"
            assert "allows RDP" in result[0].status_extended

    def test_firewall_rdp_restricted(self):
        firewall_client = mock.MagicMock
        firewall_client.firewalls = [
            Firewall(
                id=101,
                label="secure-fw",
                status="enabled",
                inbound_rules=[
                    FirewallRule(
                        protocol="TCP",
                        ports="3389",
                        addresses_ipv4=["10.0.0.0/8"],
                        addresses_ipv6=[],
                        action="ACCEPT",
                        label="allow-rdp-private",
                    )
                ],
                outbound_rules=[],
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.firewall.firewall_blocks_rdp_from_internet.firewall_blocks_rdp_from_internet.firewall_client",
                new=firewall_client,
            ),
        ):
            from prowler.providers.linode.services.firewall.firewall_blocks_rdp_from_internet.firewall_blocks_rdp_from_internet import (
                firewall_blocks_rdp_from_internet,
            )

            check = firewall_blocks_rdp_from_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "101"
            assert result[0].resource_name == "secure-fw"

    def test_firewall_all_ports_from_internet_includes_rdp(self):
        firewall_client = mock.MagicMock
        firewall_client.firewalls = [
            Firewall(
                id=102,
                label="all-ports-fw",
                status="enabled",
                inbound_rules=[
                    FirewallRule(
                        protocol="TCP",
                        ports="",
                        addresses_ipv4=["0.0.0.0/0"],
                        addresses_ipv6=[],
                        action="ACCEPT",
                        label="allow-all",
                    )
                ],
                outbound_rules=[],
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.firewall.firewall_blocks_rdp_from_internet.firewall_blocks_rdp_from_internet.firewall_client",
                new=firewall_client,
            ),
        ):
            from prowler.providers.linode.services.firewall.firewall_blocks_rdp_from_internet.firewall_blocks_rdp_from_internet import (
                firewall_blocks_rdp_from_internet,
            )

            check = firewall_blocks_rdp_from_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "102"
            assert result[0].resource_name == "all-ports-fw"

    def test_firewall_rdp_in_port_range_from_internet(self):
        firewall_client = mock.MagicMock
        firewall_client.firewalls = [
            Firewall(
                id=103,
                label="range-fw",
                status="enabled",
                inbound_rules=[
                    FirewallRule(
                        protocol="TCP",
                        ports="3000-4000",
                        addresses_ipv4=["::/0"],
                        addresses_ipv6=["::/0"],
                        action="ACCEPT",
                        label="allow-range",
                    )
                ],
                outbound_rules=[],
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.firewall.firewall_blocks_rdp_from_internet.firewall_blocks_rdp_from_internet.firewall_client",
                new=firewall_client,
            ),
        ):
            from prowler.providers.linode.services.firewall.firewall_blocks_rdp_from_internet.firewall_blocks_rdp_from_internet import (
                firewall_blocks_rdp_from_internet,
            )

            check = firewall_blocks_rdp_from_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "103"
            assert result[0].resource_name == "range-fw"

    def test_firewall_drop_rule_does_not_trigger(self):
        firewall_client = mock.MagicMock
        firewall_client.firewalls = [
            Firewall(
                id=104,
                label="drop-fw",
                status="enabled",
                inbound_rules=[
                    FirewallRule(
                        protocol="TCP",
                        ports="3389",
                        addresses_ipv4=["0.0.0.0/0"],
                        addresses_ipv6=[],
                        action="DROP",
                        label="drop-rdp",
                    )
                ],
                outbound_rules=[],
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.firewall.firewall_blocks_rdp_from_internet.firewall_blocks_rdp_from_internet.firewall_client",
                new=firewall_client,
            ),
        ):
            from prowler.providers.linode.services.firewall.firewall_blocks_rdp_from_internet.firewall_blocks_rdp_from_internet import (
                firewall_blocks_rdp_from_internet,
            )

            check = firewall_blocks_rdp_from_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "104"
            assert result[0].resource_name == "drop-fw"
