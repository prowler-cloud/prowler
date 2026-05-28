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


class TestLinodeFirewallBlocksSshFromInternet:
    def test_firewall_no_ssh_from_internet(self):
        firewall_client = mock.MagicMock
        firewall_client.firewalls = [
            Firewall(
                id=100,
                label="my-firewall",
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

    def test_firewall_ssh_from_internet(self):
        firewall_client = mock.MagicMock
        firewall_client.firewalls = [
            Firewall(
                id=100,
                label="bad-firewall",
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
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider(),
            ),
            patch(
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
            assert "SSH" in result[0].status_extended

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
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider(),
            ),
            patch(
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
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider(),
            ),
            patch(
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
