from unittest import mock

from prowler.providers.linode.services.firewall.firewall_service import Firewall
from tests.providers.linode.linode_fixtures import set_mocked_linode_provider


class Test_firewall_assigned_to_devices:
    def test_no_firewalls(self):
        firewall_client = mock.MagicMock
        firewall_client.firewalls = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.firewall.firewall_assigned_to_devices.firewall_assigned_to_devices.firewall_client",
                new=firewall_client,
            ),
        ):
            from prowler.providers.linode.services.firewall.firewall_assigned_to_devices.firewall_assigned_to_devices import (
                firewall_assigned_to_devices,
            )

            check = firewall_assigned_to_devices()
            result = check.execute()

            assert len(result) == 0

    def test_firewall_assigned(self):
        firewall_client = mock.MagicMock
        firewall_client.firewalls = [
            Firewall(
                id=100,
                label="assigned-fw",
                status="enabled",
                inbound_rules=[],
                outbound_rules=[],
                inbound_policy="DROP",
                outbound_policy="DROP",
                attached_devices_count=2,
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.firewall.firewall_assigned_to_devices.firewall_assigned_to_devices.firewall_client",
                new=firewall_client,
            ),
        ):
            from prowler.providers.linode.services.firewall.firewall_assigned_to_devices.firewall_assigned_to_devices import (
                firewall_assigned_to_devices,
            )

            check = firewall_assigned_to_devices()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "100"
            assert result[0].resource_name == "assigned-fw"

    def test_firewall_not_assigned(self):
        firewall_client = mock.MagicMock
        firewall_client.firewalls = [
            Firewall(
                id=101,
                label="unassigned-fw",
                status="enabled",
                inbound_rules=[],
                outbound_rules=[],
                inbound_policy="DROP",
                outbound_policy="DROP",
                attached_devices_count=0,
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.firewall.firewall_assigned_to_devices.firewall_assigned_to_devices.firewall_client",
                new=firewall_client,
            ),
        ):
            from prowler.providers.linode.services.firewall.firewall_assigned_to_devices.firewall_assigned_to_devices import (
                firewall_assigned_to_devices,
            )

            check = firewall_assigned_to_devices()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "101"
            assert result[0].resource_name == "unassigned-fw"
