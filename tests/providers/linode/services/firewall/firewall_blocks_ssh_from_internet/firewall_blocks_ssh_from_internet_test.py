from unittest import mock

from prowler.providers.linode.services.firewall.firewall_service import (
    Firewall,
    FirewallRule,
)
from tests.providers.linode.linode_fixtures import set_mocked_linode_provider


class Test_firewall_blocks_ssh_from_internet:
    def test_no_firewalls(self):
        firewall_client = mock.MagicMock
        firewall_client.firewalls = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.firewall.firewall_blocks_ssh_from_internet.firewall_blocks_ssh_from_internet.firewall_client",
                new=firewall_client,
            ),
        ):
            from prowler.providers.linode.services.firewall.firewall_blocks_ssh_from_internet.firewall_blocks_ssh_from_internet import (
                firewall_blocks_ssh_from_internet,
            )

            check = firewall_blocks_ssh_from_internet()
            result = check.execute()

            assert len(result) == 0

    def test_firewall_allows_ssh_from_internet(self):
        firewall_client = mock.MagicMock
        firewall_client.firewalls = [
            Firewall(
                id=100,
                label="open-firewall",
                status="enabled",
                inbound_rules=[
                    FirewallRule(
                        protocol="TCP",
                        ports="22",
                        addresses_ipv4=["0.0.0.0/0"],
                        action="ACCEPT",
                    )
                ],
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.firewall.firewall_blocks_ssh_from_internet.firewall_blocks_ssh_from_internet.firewall_client",
                new=firewall_client,
            ),
        ):
            from prowler.providers.linode.services.firewall.firewall_blocks_ssh_from_internet.firewall_blocks_ssh_from_internet import (
                firewall_blocks_ssh_from_internet,
            )

            check = firewall_blocks_ssh_from_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "100"
            assert result[0].resource_name == "open-firewall"
            assert "allows SSH" in result[0].status_extended

    def test_firewall_ssh_in_port_range(self):
        firewall_client = mock.MagicMock
        firewall_client.firewalls = [
            Firewall(
                id=100,
                label="range-firewall",
                status="enabled",
                inbound_rules=[
                    FirewallRule(
                        protocol="TCP",
                        ports="1-1024",
                        addresses_ipv4=["0.0.0.0/0"],
                        action="ACCEPT",
                    )
                ],
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.firewall.firewall_blocks_ssh_from_internet.firewall_blocks_ssh_from_internet.firewall_client",
                new=firewall_client,
            ),
        ):
            from prowler.providers.linode.services.firewall.firewall_blocks_ssh_from_internet.firewall_blocks_ssh_from_internet import (
                firewall_blocks_ssh_from_internet,
            )

            check = firewall_blocks_ssh_from_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "100"
            assert result[0].resource_name == "range-firewall"

    def test_firewall_ssh_from_private_ip(self):
        firewall_client = mock.MagicMock
        firewall_client.firewalls = [
            Firewall(
                id=100,
                label="private-firewall",
                status="enabled",
                inbound_rules=[
                    FirewallRule(
                        protocol="TCP",
                        ports="22",
                        addresses_ipv4=["10.0.0.0/8"],
                        action="ACCEPT",
                    )
                ],
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.firewall.firewall_blocks_ssh_from_internet.firewall_blocks_ssh_from_internet.firewall_client",
                new=firewall_client,
            ),
        ):
            from prowler.providers.linode.services.firewall.firewall_blocks_ssh_from_internet.firewall_blocks_ssh_from_internet import (
                firewall_blocks_ssh_from_internet,
            )

            check = firewall_blocks_ssh_from_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "100"
            assert result[0].resource_name == "private-firewall"
