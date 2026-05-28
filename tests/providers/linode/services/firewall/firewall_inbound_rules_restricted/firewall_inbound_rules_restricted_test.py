from unittest import mock

from prowler.providers.linode.services.firewall.firewall_service import (
    Firewall,
    FirewallRule,
)
from tests.providers.linode.linode_fixtures import set_mocked_linode_provider


class Test_firewall_inbound_rules_restricted:
    def test_no_firewalls(self):
        firewall_client = mock.MagicMock
        firewall_client.firewalls = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.firewall.firewall_inbound_rules_restricted.firewall_inbound_rules_restricted.firewall_client",
                new=firewall_client,
            ),
        ):
            from prowler.providers.linode.services.firewall.firewall_inbound_rules_restricted.firewall_inbound_rules_restricted import (
                firewall_inbound_rules_restricted,
            )

            check = firewall_inbound_rules_restricted()
            result = check.execute()

            assert len(result) == 0

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
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
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
            assert result[0].resource_id == "100"
            assert result[0].resource_name == "good-firewall"

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
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
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
            assert result[0].resource_id == "100"
            assert result[0].resource_name == "bad-firewall"

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
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
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
            assert result[0].resource_id == "100"
            assert result[0].resource_name == "drop-firewall"
