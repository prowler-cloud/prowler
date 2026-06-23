from unittest import mock

from prowler.providers.linode.services.networking.networking_service import Firewall
from tests.providers.linode.linode_fixtures import set_mocked_linode_provider


class Test_networking_firewall_default_outbound_policy_drop:
    def test_no_firewalls(self):
        networking_client = mock.MagicMock()
        networking_client.firewalls = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.networking.networking_firewall_default_outbound_policy_drop.networking_firewall_default_outbound_policy_drop.networking_client",
                new=networking_client,
            ),
        ):
            from prowler.providers.linode.services.networking.networking_firewall_default_outbound_policy_drop.networking_firewall_default_outbound_policy_drop import (
                networking_firewall_default_outbound_policy_drop,
            )

            check = networking_firewall_default_outbound_policy_drop()
            result = check.execute()

            assert len(result) == 0

    def test_outbound_policy_drop(self):
        networking_client = mock.MagicMock()
        networking_client.firewalls = [
            Firewall(
                id=100,
                label="drop-fw",
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
                "prowler.providers.linode.services.networking.networking_firewall_default_outbound_policy_drop.networking_firewall_default_outbound_policy_drop.networking_client",
                new=networking_client,
            ),
        ):
            from prowler.providers.linode.services.networking.networking_firewall_default_outbound_policy_drop.networking_firewall_default_outbound_policy_drop import (
                networking_firewall_default_outbound_policy_drop,
            )

            check = networking_firewall_default_outbound_policy_drop()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "100"
            assert result[0].resource_name == "drop-fw"

    def test_outbound_policy_accept(self):
        networking_client = mock.MagicMock()
        networking_client.firewalls = [
            Firewall(
                id=101,
                label="accept-fw",
                status="enabled",
                inbound_rules=[],
                outbound_rules=[],
                inbound_policy="DROP",
                outbound_policy="ACCEPT",
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
                "prowler.providers.linode.services.networking.networking_firewall_default_outbound_policy_drop.networking_firewall_default_outbound_policy_drop.networking_client",
                new=networking_client,
            ),
        ):
            from prowler.providers.linode.services.networking.networking_firewall_default_outbound_policy_drop.networking_firewall_default_outbound_policy_drop import (
                networking_firewall_default_outbound_policy_drop,
            )

            check = networking_firewall_default_outbound_policy_drop()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "101"
            assert result[0].resource_name == "accept-fw"
