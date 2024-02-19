from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.network.network_service import (
    NetworkWatcher,
    SecurityGroup,
)

AZURE_SUBSCRIPTION = str(uuid4())


class Test_network_watcher_enabled:
    def test_no_security_groups_network_watchers(self):
        network_client = mock.MagicMock
        network_client.security_groups = {}
        network_client.network_watchers = {}

        with mock.patch(
            "prowler.providers.azure.services.network.network_service.Network",
            new=network_client,
        ) as service_client, mock.patch(
            "prowler.providers.azure.services.network.network_client.network_client",
            new=service_client,
        ):
            from prowler.providers.azure.services.network.network_watcher_enabled.network_watcher_enabled import (
                network_watcher_enabled,
            )

            check = network_watcher_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_network_security_groups_invalid_network_watchers(self):
        network_client = mock.MagicMock
        security_group_name = "Security Group Name"
        security_group_id = str(uuid4())
        network_watcher_name = "Network Watcher Name"
        network_watcher_id = str(uuid4)
        locations = ["location"]

        network_client.security_groups = {
            AZURE_SUBSCRIPTION: [
                SecurityGroup(
                    id=security_group_id,
                    name=security_group_name,
                    location="location",
                    security_rules=[],
                    subscription_locations=locations,
                )
            ]
        }

        network_client.network_watchers = {
            AZURE_SUBSCRIPTION: [
                NetworkWatcher(
                    id=network_watcher_id,
                    name=network_watcher_name,
                    location=None,
                    flow_logs=[],
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.network.network_service.Network",
            new=network_client,
        ) as service_client, mock.patch(
            "prowler.providers.azure.services.network.network_client.network_client",
            new=service_client,
        ):
            from prowler.providers.azure.services.network.network_watcher_enabled.network_watcher_enabled import (
                network_watcher_enabled,
            )

            check = network_watcher_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Security Group {security_group_name} from subscription {AZURE_SUBSCRIPTION} has Network Watcher disabled for the location {locations[0]}."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == security_group_name
            assert result[0].resource_id == security_group_id

    def test_network_security_groups_valid_network_watchers(self):
        network_client = mock.MagicMock
        security_group_name = "Security Group Name"
        security_group_id = str(uuid4())
        network_watcher_name = "Network Watcher Name"
        network_watcher_id = str(uuid4)

        network_client.security_groups = {
            AZURE_SUBSCRIPTION: [
                SecurityGroup(
                    id=security_group_id,
                    name=security_group_name,
                    location="location",
                    security_rules=[],
                    subscription_locations=["location"],
                )
            ]
        }

        network_client.network_watchers = {
            AZURE_SUBSCRIPTION: [
                NetworkWatcher(
                    id=network_watcher_id,
                    name=network_watcher_name,
                    location="location",
                    flow_logs=[],
                )
            ]
        }

        with mock.patch(
            "prowler.providers.azure.services.network.network_service.Network",
            new=network_client,
        ) as service_client, mock.patch(
            "prowler.providers.azure.services.network.network_client.network_client",
            new=service_client,
        ):
            from prowler.providers.azure.services.network.network_watcher_enabled.network_watcher_enabled import (
                network_watcher_enabled,
            )

            check = network_watcher_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Security Group {security_group_name} from subscription {AZURE_SUBSCRIPTION} has Network Watcher enabled for the location location."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == security_group_name
            assert result[0].resource_id == security_group_id
