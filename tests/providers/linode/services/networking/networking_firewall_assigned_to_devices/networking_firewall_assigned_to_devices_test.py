from unittest import mock

from prowler.providers.linode.services.networking.networking_service import Firewall
from tests.providers.linode.linode_fixtures import set_mocked_linode_provider


class Test_networking_firewall_assigned_to_devices:
    def test_no_firewalls(self):
        networking_client = mock.MagicMock()
        networking_client.firewalls = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.networking.networking_firewall_assigned_to_devices.networking_firewall_assigned_to_devices.networking_client",
                new=networking_client,
            ),
        ):
            from prowler.providers.linode.services.networking.networking_firewall_assigned_to_devices.networking_firewall_assigned_to_devices import (
                networking_firewall_assigned_to_devices,
            )

            check = networking_firewall_assigned_to_devices()
            result = check.execute()

            assert len(result) == 0

    def test_firewall_assigned(self):
        networking_client = mock.MagicMock()
        networking_client.firewalls = [
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
                "prowler.providers.linode.services.networking.networking_firewall_assigned_to_devices.networking_firewall_assigned_to_devices.networking_client",
                new=networking_client,
            ),
        ):
            from prowler.providers.linode.services.networking.networking_firewall_assigned_to_devices.networking_firewall_assigned_to_devices import (
                networking_firewall_assigned_to_devices,
            )

            check = networking_firewall_assigned_to_devices()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "100"
            assert result[0].resource_name == "assigned-fw"

    def test_firewall_not_assigned(self):
        networking_client = mock.MagicMock()
        networking_client.firewalls = [
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
                "prowler.providers.linode.services.networking.networking_firewall_assigned_to_devices.networking_firewall_assigned_to_devices.networking_client",
                new=networking_client,
            ),
        ):
            from prowler.providers.linode.services.networking.networking_firewall_assigned_to_devices.networking_firewall_assigned_to_devices import (
                networking_firewall_assigned_to_devices,
            )

            check = networking_firewall_assigned_to_devices()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "101"
            assert result[0].resource_name == "unassigned-fw"

    def test_firewall_device_count_undetermined_is_skipped(self):
        # attached_devices_count is None when the devices fetch failed; the
        # firewall must be skipped rather than reported as a false FAIL.
        networking_client = mock.MagicMock()
        networking_client.firewalls = [
            Firewall(
                id=102,
                label="undetermined-fw",
                status="enabled",
                inbound_rules=[],
                outbound_rules=[],
                inbound_policy="DROP",
                outbound_policy="DROP",
                attached_devices_count=None,
                tags=[],
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_linode_provider(),
            ),
            mock.patch(
                "prowler.providers.linode.services.networking.networking_firewall_assigned_to_devices.networking_firewall_assigned_to_devices.networking_client",
                new=networking_client,
            ),
        ):
            from prowler.providers.linode.services.networking.networking_firewall_assigned_to_devices.networking_firewall_assigned_to_devices import (
                networking_firewall_assigned_to_devices,
            )

            check = networking_firewall_assigned_to_devices()
            result = check.execute()

            assert len(result) == 0
